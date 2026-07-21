using System.Runtime.InteropServices;

namespace SeroStub;

// Extracts a 16x16 app icon from an exe/dll path and encodes it as base64 PNG (alpha-preserving)
internal static class StubIconHelper
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFO
    {
        public nint hIcon; public int iIcon; public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]  public string szTypeName;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern nint SHGetFileInfo(string path, uint attr, ref SHFILEINFO shfi, uint cb, uint flags);
    [DllImport("user32.dll")]  private static extern bool DrawIconEx(nint hdc, int x, int y, nint hIcon, int cx, int cy, uint step, nint brush, uint flags);
    [DllImport("user32.dll")]  private static extern bool DestroyIcon(nint hIcon);
    [DllImport("gdi32.dll")]   private static extern nint CreateCompatibleDC(nint hdc);
    [DllImport("gdi32.dll")]   private static extern nint SelectObject(nint hdc, nint h);
    [DllImport("gdi32.dll")]   private static extern bool DeleteDC(nint hdc);
    [DllImport("gdi32.dll")]   private static extern bool DeleteObject(nint ho);
    [DllImport("gdi32.dll")]   private static extern nint CreateDIBSection(nint hdc, ref BmpInfo bmi, uint usage, out nint bits, nint sec, uint off);
    [DllImport("user32.dll")]  private static extern nint GetDC(nint hwnd);
    [DllImport("user32.dll")]  private static extern int  ReleaseDC(nint hwnd, nint hdc);
    [DllImport("shlwapi.dll")] private static extern nint SHCreateMemStream(nint p, uint cb);
    [DllImport("gdiplus.dll")] private static extern int  GdiplusStartup(out nint tok, ref GdipIn inp, nint outp);
    [DllImport("gdiplus.dll")] private static extern void GdiplusShutdown(nint tok);
    [DllImport("gdiplus.dll")] private static extern int  GdipCreateBitmapFromScan0(int w, int h, int stride, int fmt, nint scan0, out nint bmp);
    [DllImport("gdiplus.dll")] private static extern int  GdipDisposeImage(nint img);
    [DllImport("gdiplus.dll")] private static extern int  GdipSaveImageToStream(nint img, nint stream, ref Guid clsid, nint ep);

    [StructLayout(LayoutKind.Sequential)]
    private struct BmpInfoHdr { public uint size; public int w, h; public ushort planes, bpp; public uint compress, imgSize, xppm, yppm, used, imp; }
    [StructLayout(LayoutKind.Sequential)]
    private struct BmpInfo    { public BmpInfoHdr hdr; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public uint[] colors; }
    [StructLayout(LayoutKind.Sequential)]
    private struct GdipIn     { public uint Version; public nint Callback; public int SuppBg, SuppExt; }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate uint VtRelease(nint p);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int  VtSeek(nint p, long move, uint origin, ref long pos);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)] delegate int  VtRead(nint p, nint pv, uint cb, out uint n);

    // PNG encoder — preserves alpha channel unlike JPEG
    static readonly Guid PngClsid = new("557CF406-1A04-11D3-9A73-0000F81EF32E");

    private static string? _genericExeIcon;

    // Returns the default Windows .exe shell icon (16x16 PNG base64), cached.
    internal static string GetGenericExeIcon()
    {
        if (_genericExeIcon != null) return _genericExeIcon;
        try
        {
            const uint FILE_ATTRIBUTE_NORMAL  = 0x80;
            const uint SHGFI_USEFILEATTRIBUTES = 0x10;
            var shfi = new SHFILEINFO();
            if (SHGetFileInfo("dummy.exe", FILE_ATTRIBUTE_NORMAL, ref shfi,
                    (uint)Marshal.SizeOf<SHFILEINFO>(),
                    SHGFI_USEFILEATTRIBUTES | 0x100 | 0x001) == 0 || shfi.hIcon == 0)
                return _genericExeIcon = "";
            try   { return _genericExeIcon = HIconToPngBase64(shfi.hIcon, 16); }
            finally { DestroyIcon(shfi.hIcon); }
        }
        catch { return _genericExeIcon = ""; }
    }

    internal static unsafe string ExtractExeIcon(string path)
    {
        if (string.IsNullOrEmpty(path)) return "";
        // Strip leading @ (e.g. @C:\Windows\system32\shell32.dll,-1)
        path = path.TrimStart('@').Trim();
        // Expand environment variables (e.g. %ProgramFiles%\...)
        path = Environment.ExpandEnvironmentVariables(path);
        if (!System.IO.File.Exists(path)) return "";
        try
        {
            var shfi = new SHFILEINFO();
            if (SHGetFileInfo(path, 0, ref shfi, (uint)Marshal.SizeOf<SHFILEINFO>(), 0x100 | 0x001) == 0 || shfi.hIcon == 0)
                return "";
            try { return HIconToPngBase64(shfi.hIcon, 16); }
            finally { DestroyIcon(shfi.hIcon); }
        }
        catch { return ""; }
    }

    internal static unsafe string HIconToPngBase64(nint hIcon, int size)
    {
        nint hdcScreen = GetDC(0);
        if (hdcScreen == 0) return "";
        try
        {
            nint hdcMem = CreateCompatibleDC(hdcScreen);
            if (hdcMem == 0) return "";
            var bmi = new BmpInfo
            {
                hdr = new BmpInfoHdr { size = (uint)Marshal.SizeOf<BmpInfoHdr>(), w = size, h = -size, planes = 1, bpp = 32 },
                colors = new uint[4]
            };
            nint hbm = CreateDIBSection(hdcScreen, ref bmi, 0, out nint bits, 0, 0);
            if (hbm == 0 || bits == 0) { DeleteDC(hdcMem); return ""; }
            SelectObject(hdcMem, hbm);
            DrawIconEx(hdcMem, 0, 0, hIcon, size, size, 0, 0, 0x0003); // DI_NORMAL

            // GDI DrawIconEx leaves alpha=0 on opaque pixels for old-format icons.
            // Fix: any pixel with color data but alpha=0 is treated as fully opaque.
            var px = (uint*)bits;
            for (int i = 0; i < size * size; i++)
            {
                if ((px[i] >> 24) == 0 && (px[i] & 0x00FFFFFFu) != 0)
                    px[i] |= 0xFF000000u;
            }

            var gdipInp = new GdipIn { Version = 1 };
            GdiplusStartup(out nint tok, ref gdipInp, 0);
            try
            {
                if (GdipCreateBitmapFromScan0(size, size, size * 4, 0x26200A, bits, out nint bmp) != 0 || bmp == 0)
                { DeleteObject(hbm); DeleteDC(hdcMem); return ""; }
                try
                {
                    nint stream = SHCreateMemStream(0, 0);
                    if (stream == 0) { GdipDisposeImage(bmp); DeleteObject(hbm); DeleteDC(hdcMem); return ""; }
                    var cls = PngClsid;
                    GdipSaveImageToStream(bmp, stream, ref cls, 0); // PNG needs no encoder params
                    long pos = 0;
                    var seek = Marshal.GetDelegateForFunctionPointer<VtSeek>((*(nint**)stream)[5]);
                    seek(stream, 0, 0, ref pos);
                    var chunks = new List<byte[]>(); int total = 0;
                    var buf = new byte[4096];
                    fixed (byte* pb = buf)
                    {
                        var read = Marshal.GetDelegateForFunctionPointer<VtRead>((*(nint**)stream)[3]);
                        while (true) { uint n = 0; read(stream, (nint)pb, (uint)buf.Length, out n); if (n == 0) break; var c = new byte[n]; Buffer.BlockCopy(buf, 0, c, 0, (int)n); chunks.Add(c); total += (int)n; }
                    }
                    Marshal.GetDelegateForFunctionPointer<VtRelease>((*(nint**)stream)[2])(stream);
                    if (total == 0) return "";
                    var res = new byte[total]; int off = 0;
                    foreach (var ch in chunks) { Buffer.BlockCopy(ch, 0, res, off, ch.Length); off += ch.Length; }
                    return Convert.ToBase64String(res);
                }
                finally { GdipDisposeImage(bmp); }
            }
            finally { GdiplusShutdown(tok); DeleteObject(hbm); DeleteDC(hdcMem); }
        }
        finally { ReleaseDC(0, hdcScreen); }
    }
}
