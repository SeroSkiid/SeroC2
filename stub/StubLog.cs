namespace SeroStub;

internal static class StubLog
{
    private static readonly string _path = System.IO.Path.Combine(
        System.IO.Path.GetTempPath(), "serodebug.log");

    public static void Info(string msg)  => Write("INFO",  msg);
    public static void Error(string msg) => Write("ERROR", msg);
    public static void Debug(string msg) => Write("DEBUG", msg);

    private static void Write(string level, string msg)
    {
        try { System.IO.File.AppendAllText(_path, $"[{DateTime.Now:HH:mm:ss.fff}][{level}] {msg}\r\n"); }
        catch { }
    }
}
