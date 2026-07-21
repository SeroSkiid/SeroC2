using System.IO;
using System.Runtime.CompilerServices;
using System.Text;

namespace SeroServer;

/// <summary>
/// File-based diagnostic logger.  Writes to %LOCALAPPDATA%\SeroServer\logs\.
/// Rotates across 5 files × 5 MB.  Enabled by default; can be toggled at runtime.
/// Never logs sensitive data (passwords, screenshots, webcam frames, etc.).
/// </summary>
public static class DiagnosticLogger
{
    private const int MaxFileSizeBytes  = 5 * 1024 * 1024; // 5 MB per file
    private const int MaxFileCount      = 5;
    private const string LogDir         = "logs";
    private const string LogFilePrefix  = "sero_diag_";

    private static string? _dir;
    private static int _fileIndex;
    private static long _currentSize;
    private static StreamWriter? _writer;
    private static readonly object _lock = new();
    private static bool _enabled = true;

    public static bool Enabled
    {
        get => _enabled;
        set
        {
            lock (_lock)
            {
                _enabled = value;
                if (!value) CloseWriter();
            }
        }
    }

    public static string LogDirectory => _dir ?? "(not initialised)";

    public static void Init()
    {
        lock (_lock)
        {
            try
            {
                _dir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "SeroServer", LogDir);
                Directory.CreateDirectory(_dir);
                _fileIndex = FindLatestFileIndex();
                OpenWriter(_fileIndex);
                WriteHeader();
            }
            catch { _enabled = false; }
        }
    }

    // ── Public write API ───────────────────────────────────────────────────────

    public static void Info(string msg,  [CallerMemberName] string? caller = null) => Write("INFO ", msg, caller);
    public static void Warn(string msg,  [CallerMemberName] string? caller = null) => Write("WARN ", msg, caller);
    public static void Error(string msg, [CallerMemberName] string? caller = null) => Write("ERROR", msg, caller);

    public static void Exception(Exception ex, string context = "",
        [CallerMemberName] string? caller = null)
    {
        Write("EXCPT", $"{context} — {ex.GetType().Name}: {ex.Message}", caller);
        // Log the first frame of the stack trace (no sensitive data, just code location)
        var frame = ex.StackTrace?.Split('\n').FirstOrDefault()?.Trim();
        if (frame != null) Write("STACK", frame, caller);
    }

    public static void ClientConnect(string clientId, string ip, string username, string os) =>
        Write("CONN+", $"client={clientId} ip={ip} user={username} os={os}");

    public static void ClientDisconnect(string clientId, string reason) =>
        Write("CONN-", $"client={clientId} reason={reason}");

    public static void StreamState(string clientId, string streamType, string state) =>
        Write("STRM ", $"client={clientId} stream={streamType} state={state}");

    // ── Internal ──────────────────────────────────────────────────────────────

    private static void Write(string level, string msg, string? caller = null)
    {
        if (!_enabled) return;
        lock (_lock)
        {
            if (_writer == null) return;
            try
            {
                var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}] [{level}] {(caller != null ? $"[{caller}] " : "")}{msg}";
                _writer.WriteLine(line);
                _writer.Flush();
                _currentSize += Encoding.UTF8.GetByteCount(line) + 2;
                if (_currentSize >= MaxFileSizeBytes) Rotate();
            }
            catch { }
        }
    }

    private static void WriteHeader()
    {
        if (_writer == null) return;
        _writer.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [----] SeroServer diagnostic log started");
        _writer.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [INFO] OS: {Environment.OSVersion}");
        _writer.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [INFO] Machine: {Environment.MachineName} · Proc: {Environment.ProcessorCount}");
        _writer.Flush();
    }

    private static void Rotate()
    {
        CloseWriter();
        _fileIndex = (_fileIndex + 1) % MaxFileCount;
        OpenWriter(_fileIndex);
        WriteHeader();
    }

    private static void OpenWriter(int index)
    {
        if (_dir == null) return;
        var path = Path.Combine(_dir, $"{LogFilePrefix}{index}.log");
        try
        {
            // Overwrite the slot (oldest file gets recycled)
            _writer = new StreamWriter(path, append: false, Encoding.UTF8) { AutoFlush = false };
            _currentSize = 0;
        }
        catch { _writer = null; }
    }

    private static void CloseWriter()
    {
        try { _writer?.Flush(); _writer?.Dispose(); } catch { }
        _writer = null;
    }

    private static int FindLatestFileIndex()
    {
        if (_dir == null) return 0;
        int best = 0;
        DateTime bestTime = DateTime.MinValue;
        for (int i = 0; i < MaxFileCount; i++)
        {
            var path = Path.Combine(_dir, $"{LogFilePrefix}{i}.log");
            if (!File.Exists(path)) return i; // empty slot — use it
            var t = File.GetLastWriteTime(path);
            if (t > bestTime) { bestTime = t; best = i; }
        }
        return best;
    }
}
