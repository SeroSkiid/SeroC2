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

    // Populated during GetList() — maps DisplayName → DisplayIcon path so GetIcon() skips the full rescan
    private static readonly Dictionary<string, string> _iconPathCache = new(StringComparer.OrdinalIgnoreCase);

    internal static string GetList()
    {
        var apps = new List<InstalledAppStub>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        lock (_iconPathCache) _iconPathCache.Clear();

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
                            var publisher = sub.GetValue("Publisher")?.ToString() ?? "";
                            var dispIcon  = sub.GetValue("DisplayIcon")?.ToString() ?? "";
                            if (!seen.Add(name)) continue;
                            lock (_iconPathCache)
                                _iconPathCache.TryAdd(name, dispIcon);
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

        // Fast path: cache populated by GetList()
        string? cachedDispIcon;
        lock (_iconPathCache) _iconPathCache.TryGetValue(appName, out cachedDispIcon);
        if (cachedDispIcon != null)
            return ResolveIcon(cachedDispIcon);

        // Slow path: cache cold (GetIcon called without prior GetList)
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
                            return ResolveIcon(sub.GetValue("DisplayIcon")?.ToString() ?? "");
                        }
                        catch { }
                    }
                }
                catch { }
            }
        }
        return StubIconHelper.GetGenericExeIcon();
    }

    private static string ResolveIcon(string dispIcon)
    {
        var iconPath = dispIcon.Contains(',') ? dispIcon[..dispIcon.LastIndexOf(',')] : dispIcon;
        iconPath = iconPath.Trim('"');
        var ico = string.IsNullOrEmpty(iconPath) ? "" : StubIconHelper.ExtractExeIcon(iconPath);
        return ico.Length > 0 ? ico : StubIconHelper.GetGenericExeIcon();
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
                // Parse exe path from strings like: "C:\App\uninstall.exe" /quiet
                string fileName, args;
                if (uninstallString.StartsWith('"'))
                {
                    int end = uninstallString.IndexOf('"', 1);
                    fileName = end > 0 ? uninstallString[1..end] : uninstallString;
                    args     = end > 0 ? uninstallString[(end + 1)..].Trim() : "";
                }
                else
                {
                    int sp = uninstallString.IndexOf(' ');
                    fileName = sp > 0 ? uninstallString[..sp] : uninstallString;
                    args     = sp > 0 ? uninstallString[(sp + 1)..].Trim() : "";
                }
                psi = new System.Diagnostics.ProcessStartInfo(fileName, args)
                    { UseShellExecute = true };
            }
            System.Diagnostics.Process.Start(psi);
        }
        catch { }
    }
}
