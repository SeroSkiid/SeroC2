using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;

namespace SeroServer.Data;

public class DataStore
{
    private static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SeroServer");
    private static readonly string LogPath = Path.Combine(DataDir, "server.log");
    private static readonly string ClientsPath = Path.Combine(DataDir, "clients.json");

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = true };
    private readonly object _lock = new();
    private volatile bool _clientsDirty;
    private readonly System.Timers.Timer _saveTimer;

    public ObservableCollection<string> Logs { get; } = [];

    /// <summary>Persistent client records indexed by HWID.</summary>
    public ConcurrentDictionary<string, ClientRecord> AllClients { get; } = new();

    public DataStore()
    {
        LoadClients();
        // Save clients.json at most every 10 seconds instead of on every event
        _saveTimer = new System.Timers.Timer(10_000) { AutoReset = true };
        _saveTimer.Elapsed += (_, _) => { if (_clientsDirty) { _clientsDirty = false; SaveClientsNow(); } };
        _saveTimer.Start();
    }

    // ── Logging ─────────────────────────────────────

    public void Log(string message)
    {
        var entry = $"[{DateTime.Now:HH:mm:ss}] {message}";
        Logs.Add(entry);
        if (Logs.Count > 1000)
        {
            // Batch remove instead of one-by-one
            for (int i = 0; i < 500; i++) Logs.RemoveAt(0);
        }

        try
        {
            Directory.CreateDirectory(DataDir);
            File.AppendAllText(LogPath, entry + Environment.NewLine);
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

        lock (_lock)
        {
            record.LastUsername = client.Username;
            record.LastIP = client.IP;
            record.LastCountry = client.Country;
            record.LastMachineName = client.MachineName;
            record.LastOS = client.OS;
            record.LastIsAdmin = client.IsAdmin;
            record.LastSeen = DateTime.UtcNow;
            record.ActivityLog.Add(new ActivityEntry { Action = $"Connected from {client.IP} ({client.Username})" });

            if (record.ActivityLog.Count > 200)
                record.ActivityLog.RemoveRange(0, record.ActivityLog.Count - 200);
        }

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
            lock (_lock) { record.Tag = tag; }
            SaveClients();
        }
    }

    // ── Persistence ─────────────────────────────────

    private void SaveClients() => _clientsDirty = true;

    private void SaveClientsNow()
    {
        try
        {
            Directory.CreateDirectory(DataDir);
            var json = JsonSerializer.Serialize(AllClients, JsonOpts);
            File.WriteAllText(ClientsPath, json);
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
            foreach (var kv in data) AllClients[kv.Key] = kv.Value;
            Log($"[*] Loaded {AllClients.Count} persistent client records.");
        }
        catch (Exception ex) { Log($"[!] Failed to load clients: {ex.Message}"); }
    }
}
