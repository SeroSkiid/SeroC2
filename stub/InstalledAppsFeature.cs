using Microsoft.Win32;
using System.Text.Json;

namespace SeroStub;

internal static class InstalledAppsFeature
{
    private static readonly string[] _regPaths =
    [
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    internal static string GetList()
    {
        var apps = new List<InstalledAppStub>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var path in _regPaths)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                try
                {
                    using var key = hive.OpenSubKey(path);
                    if (key == null) continue;
                    foreach (var subName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var sub = key.OpenSubKey(subName);
                            if (sub == null) continue;
                            var name = sub.GetValue("DisplayName")?.ToString() ?? "";
                            if (string.IsNullOrWhiteSpace(name)) continue;
                            if (!seen.Add(name)) continue;
                            var publisher = sub.GetValue("Publisher")?.ToString() ?? "";
                            apps.Add(new InstalledAppStub
                            {
                                Name            = name,
                                Version         = sub.GetValue("DisplayVersion")?.ToString() ?? "",
                                Publisher       = publisher,
                                InstallDate     = sub.GetValue("InstallDate")?.ToString() ?? "",
                                UninstallString = sub.GetValue("UninstallString")?.ToString() ?? "",
                                IconB64         = "",
                                Verified        = !string.IsNullOrWhiteSpace(publisher)
                            });
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }

        apps.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return JsonSerializer.Serialize(new InstalledListResultStub { Apps = apps }, SeroJson.Default.InstalledListResultStub);
    }

    internal static string GetIcon(string appName)
    {
        if (string.IsNullOrWhiteSpace(appName)) return "";
        foreach (var path in _regPaths)
        {
            foreach (var hive in new[] { Registry.LocalMachine, Registry.CurrentUser })
            {
                try
                {
                    using var key = hive.OpenSubKey(path);
                    if (key == null) continue;
                    foreach (var subName in key.GetSubKeyNames())
                    {
                        try
                        {
                            using var sub = key.OpenSubKey(subName);
                            if (sub == null) continue;
                            var name = sub.GetValue("DisplayName")?.ToString() ?? "";
                            if (!string.Equals(name, appName, StringComparison.OrdinalIgnoreCase)) continue;
                            var dispIcon = sub.GetValue("DisplayIcon")?.ToString() ?? "";
                            var iconPath = dispIcon.Contains(',') ? dispIcon[..dispIcon.LastIndexOf(',')] : dispIcon;
                            iconPath = iconPath.Trim('"');
                            var ico = string.IsNullOrEmpty(iconPath) ? "" : StubIconHelper.ExtractExeIcon(iconPath);
                            return ico.Length > 0 ? ico : StubIconHelper.GetGenericExeIcon();
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        return StubIconHelper.GetGenericExeIcon();
    }

    internal static void Uninstall(string uninstallString)
    {
        if (string.IsNullOrWhiteSpace(uninstallString)) return;
        try
        {
            System.Diagnostics.ProcessStartInfo psi;
            if (uninstallString.StartsWith("msiexec", StringComparison.OrdinalIgnoreCase))
            {
                int msiEnd = uninstallString.IndexOf("msiexec.exe", StringComparison.OrdinalIgnoreCase);
                string msiArgs = msiEnd >= 0 ? uninstallString[(msiEnd + "msiexec.exe".Length)..].Trim() : uninstallString.Trim();
                psi = new System.Diagnostics.ProcessStartInfo("msiexec.exe", msiArgs)
                    { UseShellExecute = true };
            }
            else
            {
                psi = new System.Diagnostics.ProcessStartInfo(uninstallString)
                    { UseShellExecute = true };
            }
            System.Diagnostics.Process.Start(psi);
        }
        catch { }
    }
}
