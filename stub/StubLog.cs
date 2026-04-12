namespace SeroStub;

/// <summary>
/// Minimal file logger — completely silent in Release builds.
/// No file is created, no disk writes occur.
/// </summary>
internal static class StubLog
{
#if DEBUG
    private static readonly string LogPath;
    private static readonly object Lock = new();

    static StubLog()
    {
        var dir = Path.Combine(Path.GetTempPath(), "rt");
        try { Directory.CreateDirectory(dir); } catch { }
        LogPath = Path.Combine(dir, "debug.log");
    }

    private static void Write(string level, string message)
    {
        try
        {
            lock (Lock)
            {
                File.AppendAllText(LogPath, $"[{DateTime.Now:HH:mm:ss}] [{level}] {message}{Environment.NewLine}");
            }
        }
        catch { }
    }

    public static void Debug(string message) => Write("DBG", message);
    public static void Info(string message) => Write("INF", message);
    public static void Error(string message) => Write("ERR", message);
#else
    public static void Debug(string message) { }
    public static void Info(string message) { }
    public static void Error(string message) { }
#endif
}
