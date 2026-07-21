using System.Runtime.InteropServices;
using System.Text.Json;

namespace SeroStub;

internal static class ScreenshotFeature
{
    [DllImport("user32.dll")]  static extern nint GetDC(nint hwnd);
    [DllImport("user32.dll")]  static extern int  ReleaseDC(nint hwnd, nint hdc);
    [DllImport("user32.dll")]  static extern int  GetSystemMetrics(int nIndex);
    [DllImport("gdi32.dll")]   static extern nint CreateCompatibleDC(nint hdc);
    [DllImport("gdi32.dll")]   static extern nint SelectObject(nint hdc, nint h);
    [DllImport("gdi32.dll")]   static extern bool BitBlt(nint hdc, int x, int y, int cx, int cy, nint src, int xs, int ys, uint rop);
    [DllImport("gdi32.dll")]   static extern bool DeleteDC(nint hdc);
    [DllImport("gdi32.dll")]   static extern bool DeleteObject(nint ho);
    [DllImport("gdi32.dll")]   static extern nint CreateDIBSection(nint hdc, ref BmpInfo bmi, uint usage, out nint bits, nint sec, uint off);
    [DllImport("shlwapi.dll")] static extern nint SHCreateMemStream(nint p, uint cb);
    [DllImport("gdiplus.dll")] static extern int  GdiplusStartup(out nint tok, ref GdipIn inp, nint outp);
    [DllImport("gdiplus.dll")] static extern void GdiplusShutdown(nint tok);
    [DllImport("gdiplus.dll")] static extern int  GdipCreateBitmapFromScan0(int w, int h, int stride, int fmt, nint scan0, out nint bmp);
    [DllImport("gdiplus.dll")] static extern int  GdipDisposeImage(nint img);
    [DllImport("gdiplus.dll")] static extern int  GdipSaveImageToStream(nint img, nint stream, ref Guid clsid, nint ep);

    [StructLayout(LayoutKind.Sequential)]
    struct BmpInfoHdr { public uint size; public int w, h; public ushort planes, bpp; public uint compress, imgSize, xppm, yppm, clrUsed, clrImp; }
    [StructLayout(LayoutKind.Sequential)]
    struct BmpInfo { public BmpInfoHdr hdr; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public uint[] colors; }
    [StructLayout(LayoutKind.Sequential)]
    struct GdipIn { public uint Version; public nint Callback; public int SuppBg, SuppExt; }
    [StructLayout(LayoutKind.Sequential)]
    struct EncParam { public Guid Guid; public uint Count, Type; public nint Value; }
    [StructLayout(LayoutKind.Sequential)]
    struct EncParams { public uint Count; public EncParam Param; }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint VtRelease(nint p);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int  VtSeek(nint p, long move, uint origin, ref long pos);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int  VtRead(nint p, nint pv, uint cb, out uint cbRead);

    static readonly Guid JpegClsid  = new("557CF401-1A04-11D3-9A73-0000F81EF32E");
    static readonly Guid EncQuality = new("1D5BE4B5-FA4A-452D-9CDD-5DB35105E7EB");

    private static readonly nint _gdipToken;

    static ScreenshotFeature()
    {
        var gdipInp = new GdipIn { Version = 1 };
        GdiplusStartup(out var tok, ref gdipInp, 0);
        _gdipToken = tok;
    }

    internal static unsafe string Capture(int quality = 55)
    {
        int sw = GetSystemMetrics(0);
        int sh = GetSystemMetrics(1);
        if (sw <= 0 || sh <= 0) return "";

        nint hdcScreen = GetDC(0);
        if (hdcScreen == 0) return "";
        try
        {
            nint hdcMem = CreateCompatibleDC(hdcScreen);
            if (hdcMem == 0) return "";

            var bmi = new BmpInfo
            {
                hdr = new BmpInfoHdr
                {
                    size = (uint)Marshal.SizeOf<BmpInfoHdr>(),
                    w = sw, h = -sh, planes = 1, bpp = 32, compress = 0
                },
                colors = new uint[4]
            };

            nint hbm = CreateDIBSection(hdcScreen, ref bmi, 0, out nint bits, 0, 0);
            if (hbm == 0 || bits == 0) { DeleteDC(hdcMem); return ""; }

            SelectObject(hdcMem, hbm);
            BitBlt(hdcMem, 0, 0, sw, sh, hdcScreen, 0, 0, 0x00CC0020u); // SRCCOPY

            if (GdipCreateBitmapFromScan0(sw, sh, sw * 4, 0x26200A, bits, out nint bmp) != 0 || bmp == 0)
                { DeleteObject(hbm); DeleteDC(hdcMem); return ""; }
            try
            {
                nint stream = SHCreateMemStream(0, 0);
                if (stream == 0) { GdipDisposeImage(bmp); DeleteObject(hbm); DeleteDC(hdcMem); return ""; }

                int q = quality;
                var ep = new EncParams
                {
                    Count = 1,
                    Param = new EncParam { Guid = EncQuality, Count = 1, Type = 4, Value = (nint)(&q) }
                };
                var cls = JpegClsid;
                GdipSaveImageToStream(bmp, stream, ref cls, (nint)(&ep));

                long pos = 0;
                var seek = Marshal.GetDelegateForFunctionPointer<VtSeek>((*(nint**)stream)[5]);
                seek(stream, 0, 0, ref pos);

                var chunks = new List<byte[]>(); int total = 0;
                var buf = new byte[65536];
                fixed (byte* pb = buf)
                {
                    var read = Marshal.GetDelegateForFunctionPointer<VtRead>((*(nint**)stream)[3]);
                    while (true)
                    {
                        uint n = 0; read(stream, (nint)pb, (uint)buf.Length, out n);
                        if (n == 0) break;
                        var c = new byte[n]; Buffer.BlockCopy(buf, 0, c, 0, (int)n);
                        chunks.Add(c); total += (int)n;
                    }
                }
                Marshal.GetDelegateForFunctionPointer<VtRelease>((*(nint**)stream)[2])(stream);
                if (total == 0) return "";
                var result = new byte[total]; int off = 0;
                foreach (var ch in chunks) { Buffer.BlockCopy(ch, 0, result, off, ch.Length); off += ch.Length; }
                return Convert.ToBase64String(result);
            }
            finally { GdipDisposeImage(bmp); DeleteObject(hbm); DeleteDC(hdcMem); }
        }
        finally { ReleaseDC(0, hdcScreen); }
    }
}

internal class ScreenshotResultStub { public string Data { get; set; } = ""; }
