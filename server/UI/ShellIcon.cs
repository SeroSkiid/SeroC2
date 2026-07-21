using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace SeroServer.UI;

// Shared shell icon extractor — used by FileManager, ServiceManager, WindowManager, InstalledApps
internal static class ShellIcon
{
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct SHFILEINFO
    {
        public nint hIcon; public int iIcon; public uint dwAttributes;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 80)]  public string szTypeName;
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern nint SHGetFileInfo(string path, uint attr, ref SHFILEINFO shfi, uint shfiSize, uint flags);
    [DllImport("user32.dll")] private static extern bool DestroyIcon(nint hIcon);

    private const uint SHGFI_ICON              = 0x100;
    private const uint SHGFI_SMALLICON         = 0x001;
    private const uint SHGFI_USEFILEATTRIBUTES = 0x010;
    private const uint FILE_ATTRIBUTE_NORMAL    = 0x080;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x010;

    private static readonly Dictionary<string, ImageSource?> _cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object _lock = new();

    // Icon by file extension (uses fake path — fast, no file I/O)
    public static ImageSource? Get(string extension, bool isDir)
    {
        string key = isDir ? "<DIR>" : (string.IsNullOrEmpty(extension) ? "<FILE>" : extension);
        lock (_lock) { if (_cache.TryGetValue(key, out var c)) return c; }
        var r = Extract("_" + extension, isDir ? FILE_ATTRIBUTE_DIRECTORY : FILE_ATTRIBUTE_NORMAL, SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
        lock (_lock) { _cache.TryAdd(key, r); }
        return r;
    }

    // Icon from actual file path on the local machine (e.g. services.exe, notepad.exe)
    public static ImageSource? GetFromPath(string fullPath)
    {
        if (string.IsNullOrEmpty(fullPath) || !System.IO.File.Exists(fullPath)) return null;
        lock (_lock) { if (_cache.TryGetValue(fullPath, out var c)) return c; }
        var r = Extract(fullPath, FILE_ATTRIBUTE_NORMAL, SHGFI_ICON | SHGFI_SMALLICON);
        lock (_lock) { _cache.TryAdd(fullPath, r); }
        return r;
    }

    // Drive icon by root path (e.g. "C:\", "D:\").
    // Falls back to SHGFI_USEFILEATTRIBUTES when the drive doesn't exist locally
    // (client drives that aren't present on the server machine).
    public static ImageSource? GetDrive(string drivePath)
    {
        var key = $"<DRV:{drivePath.ToUpperInvariant()}>";
        lock (_lock) { if (_cache.TryGetValue(key, out var c)) return c; }
        var r = Extract(drivePath, FILE_ATTRIBUTE_NORMAL, SHGFI_ICON | SHGFI_SMALLICON);
        if (r == null)
            r = Extract(drivePath, FILE_ATTRIBUTE_NORMAL, SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES);
        lock (_lock) { _cache.TryAdd(key, r); }
        return r;
    }

    private static ImageSource? Extract(string path, uint attr, uint flags)
    {
        try
        {
            var shfi = new SHFILEINFO();
            if (SHGetFileInfo(path, attr, ref shfi, (uint)Marshal.SizeOf<SHFILEINFO>(), flags) == 0 || shfi.hIcon == 0)
                return null;
            try
            {
                var src = Imaging.CreateBitmapSourceFromHIcon(shfi.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                src.Freeze();
                return src;
            }
            finally { DestroyIcon(shfi.hIcon); }
        }
        catch { return null; }
    }
}
