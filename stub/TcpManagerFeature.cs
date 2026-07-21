using System.Runtime.InteropServices;
using System.Text.Json;

namespace SeroStub;

internal static class TcpManagerFeature
{
    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [DllImport("iphlpapi.dll")]
    private static extern int GetExtendedTcpTable(nint pTcpTable, ref int pdwSize, bool bOrder, int ulAf, int TableClass, int Reserved);

    [DllImport("iphlpapi.dll")]
    private static extern int SetTcpEntry(ref MIB_TCPROW tcpRow);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
    }

    private static readonly string[] TcpStates =
    [
        "UNKNOWN", "CLOSED", "LISTEN", "SYN_SENT", "SYN_RCVD",
        "ESTABLISHED", "FIN_WAIT1", "FIN_WAIT2", "CLOSE_WAIT",
        "CLOSING", "LAST_ACK", "TIME_WAIT", "DELETE_TCB"
    ];

    private static uint PortFromDword(uint dw)
        => (uint)(((dw & 0xFF) << 8) | ((dw >> 8) & 0xFF));

    internal static string GetList()
    {
        var entries = new List<TcpEntryStub>();
        try
        {
            int size = 0;
            GetExtendedTcpTable(nint.Zero, ref size, false, 2, 5, 0);
            var buf = Marshal.AllocHGlobal(size + 1024);
            try
            {
                if (GetExtendedTcpTable(buf, ref size, true, 2, 5, 0) == 0)
                {
                    int count = Marshal.ReadInt32(buf);
                    int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

                    // Collect unique PIDs first, then resolve names in one batch
                    var pidSet = new HashSet<int>();
                    for (int i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buf + 4 + i * rowSize);
                        pidSet.Add((int)row.dwOwningPid);
                    }
                    var procNames = new Dictionary<int, string>();
                    try
                    {
                        foreach (var p in System.Diagnostics.Process.GetProcesses())
                            if (pidSet.Contains(p.Id))
                                procNames[p.Id] = p.ProcessName;
                    }
                    catch { }

                    for (int i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buf + 4 + i * rowSize);
                        var localIp = new System.Net.IPAddress(row.dwLocalAddr).ToString();
                        var remoteIp = new System.Net.IPAddress(row.dwRemoteAddr).ToString();
                        var localPort = PortFromDword(row.dwLocalPort);
                        var remotePort = PortFromDword(row.dwRemotePort);
                        var state = row.dwState < (uint)TcpStates.Length ? TcpStates[row.dwState] : $"{row.dwState}";

                        procNames.TryGetValue((int)row.dwOwningPid, out var procName);

                        entries.Add(new TcpEntryStub
                        {
                            Pid = (int)row.dwOwningPid,
                            ProcessName = procName ?? "",
                            LocalAddr = $"{localIp}:{localPort}",
                            RemoteAddr = row.dwState == 2 /*LISTEN*/ ? "*:*" : $"{remoteIp}:{remotePort}",
                            State = state
                        });
                    }
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { }
        return JsonSerializer.Serialize(new TcpListResultStub { Entries = entries }, SeroJson.Default.TcpListResultStub);
    }

    internal static void Close(string localAddr, string remoteAddr)
    {
        try
        {
            if (!TryParseEndpoint(localAddr, out var localIp, out var localPort)) return;
            if (!TryParseEndpoint(remoteAddr, out var remoteIp, out var remotePort)) return;

            var row = new MIB_TCPROW
            {
                dwState      = 12,  // DELETE_TCB
                dwLocalAddr  = (uint)localIp.Address,
                dwLocalPort  = (uint)((localPort & 0xFF) << 8 | (localPort >> 8)),
                dwRemoteAddr = (uint)remoteIp.Address,
                dwRemotePort = (uint)((remotePort & 0xFF) << 8 | (remotePort >> 8)),
            };
            SetTcpEntry(ref row);
        }
        catch { }
    }

    private static bool TryParseEndpoint(string ep, out System.Net.IPAddress ip, out int port)
    {
        ip = System.Net.IPAddress.Any; port = 0;
        var idx = ep.LastIndexOf(':');
        if (idx < 0) return false;
        if (!System.Net.IPAddress.TryParse(ep[..idx], out ip!)) return false;
        if (!int.TryParse(ep[(idx + 1)..], out port)) return false;
        return true;
    }

    // ── Firewall blocking via COM API (HNetCfg.FwPolicy2) with netsh fallback ──

#pragma warning disable IL2072, IL2075 // COM late-binding via ProgID — trimming annotations unavailable for HNetCfg types
    // direction: 1 = inbound, 2 = outbound
    private static bool TryAddRuleCom(string name, int direction, string? remoteIp, string? program, int port)
    {
        try
        {
            var sf  = System.Reflection.BindingFlags.SetProperty;
            var gf  = System.Reflection.BindingFlags.GetProperty;
            var im  = System.Reflection.BindingFlags.InvokeMethod;

            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
            if (policyType == null) return false;
            var policy = Activator.CreateInstance(policyType);
            if (policy == null) return false;

            var ruleType = Type.GetTypeFromProgID("HNetCfg.FWRule", throwOnError: false);
            if (ruleType == null) return false;
            var rule = Activator.CreateInstance(ruleType);
            if (rule == null) return false;

            var rt = rule.GetType();
            rt.InvokeMember("Name",      sf, null, rule, [name]);
            rt.InvokeMember("Action",    sf, null, rule, [0]);         // NET_FW_ACTION_BLOCK
            rt.InvokeMember("Enabled",   sf, null, rule, [true]);
            rt.InvokeMember("Direction", sf, null, rule, [direction]); // 1=IN, 2=OUT

            if (!string.IsNullOrEmpty(remoteIp))
                rt.InvokeMember("RemoteAddresses", sf, null, rule, [remoteIp]);
            if (!string.IsNullOrEmpty(program))
                rt.InvokeMember("ApplicationName", sf, null, rule, [program]);
            if (port > 0)
            {
                rt.InvokeMember("Protocol", sf, null, rule, [6]); // TCP
                if (direction == 1) rt.InvokeMember("LocalPorts",  sf, null, rule, [port.ToString()]);
                else                rt.InvokeMember("RemotePorts", sf, null, rule, [port.ToString()]);
            }

            var rulesCol = policy.GetType().InvokeMember("Rules", gf, null, policy, null)!;
            rulesCol.GetType().InvokeMember("Add", im, null, rulesCol, [rule]);
            return true;
        }
        catch { return false; }
    }

    private static bool AddFirewallRule(string name, int direction, string? remoteIp, string? program, int port)
    {
        if (TryAddRuleCom(name, direction, remoteIp, program, port)) return true;

        // Fallback: netsh advfirewall
        try
        {
            string dirStr = direction == 1 ? "in" : "out";
            string args;
            if (!string.IsNullOrEmpty(remoteIp))
                args = $"advfirewall firewall add rule name=\"{name}\" dir={dirStr} action=block remoteip={remoteIp} enable=yes";
            else if (!string.IsNullOrEmpty(program))
                args = $"advfirewall firewall add rule name=\"{name}\" dir={dirStr} action=block program=\"{program}\" enable=yes";
            else
            {
                string portParam = direction == 1 ? $"localport={port}" : $"remoteport={port}";
                args = $"advfirewall firewall add rule name=\"{name}\" dir={dirStr} action=block protocol=TCP {portParam} enable=yes";
            }
            using var p = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo("netsh", args)
                { CreateNoWindow = true, UseShellExecute = false });
            p?.WaitForExit(5000);
            return true;
        }
        catch { return false; }
    }

    internal static string BlockIp(string remoteIp, string direction)
    {
        try
        {
            var rn = $"SeroBlock_IP_{remoteIp.Replace('.', '_').Replace(':', '_')}";
            var added = new List<TcpFirewallRuleStub>();
            if (direction is "" or "both" or "in"  && AddFirewallRule(rn + "_IN",  1, remoteIp, null, 0))
                added.Add(new TcpFirewallRuleStub { RuleName = rn + "_IN",  Direction = "in" });
            if (direction is "" or "both" or "out" && AddFirewallRule(rn + "_OUT", 2, remoteIp, null, 0))
                added.Add(new TcpFirewallRuleStub { RuleName = rn + "_OUT", Direction = "out" });
            return JsonSerializer.Serialize(new TcpFirewallRulesResultStub { Rules = added }, SeroJson.Default.TcpFirewallRulesResultStub);
        }
        catch { return JsonSerializer.Serialize(new TcpFirewallRulesResultStub(), SeroJson.Default.TcpFirewallRulesResultStub); }
    }

    internal static string BlockProcess(string processName, int port, string direction)
    {
        try
        {
            var added = new List<TcpFirewallRuleStub>();

            if (!string.IsNullOrEmpty(processName) && processName != "*")
            {
                var rn = $"SeroBlock_{System.IO.Path.GetFileNameWithoutExtension(processName)}";
                if (direction is "" or "both" or "in"  && AddFirewallRule(rn + "_IN",  1, null, processName, 0))
                    added.Add(new TcpFirewallRuleStub { RuleName = rn + "_IN",  ProcessName = processName, Direction = "in" });
                if (direction is "" or "both" or "out" && AddFirewallRule(rn + "_OUT", 2, null, processName, 0))
                    added.Add(new TcpFirewallRuleStub { RuleName = rn + "_OUT", ProcessName = processName, Direction = "out" });
            }

            if (port > 0)
            {
                var rn = $"SeroBlock_Port{port}";
                if (direction is "" or "both" or "in"  && AddFirewallRule(rn + "_IN",  1, null, null, port))
                    added.Add(new TcpFirewallRuleStub { RuleName = rn + "_IN",  Port = port, Direction = "in" });
                if (direction is "" or "both" or "out" && AddFirewallRule(rn + "_OUT", 2, null, null, port))
                    added.Add(new TcpFirewallRuleStub { RuleName = rn + "_OUT", Port = port, Direction = "out" });
            }

            return JsonSerializer.Serialize(new TcpFirewallRulesResultStub { Rules = added }, SeroJson.Default.TcpFirewallRulesResultStub);
        }
        catch { return JsonSerializer.Serialize(new TcpFirewallRulesResultStub(), SeroJson.Default.TcpFirewallRulesResultStub); }
    }

    internal static void UnblockRule(string ruleName)
    {
        try
        {
            // Try COM API first
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
            if (policyType != null)
            {
                var policy = Activator.CreateInstance(policyType);
                if (policy != null)
                {
                    var rulesCol = policy.GetType().InvokeMember("Rules",
                        System.Reflection.BindingFlags.GetProperty, null, policy, null)!;
                    rulesCol.GetType().InvokeMember("Remove",
                        System.Reflection.BindingFlags.InvokeMethod, null, rulesCol, [ruleName]);
                    return;
                }
            }
        }
        catch { }
        // Fallback: netsh
        try
        {
            using var p = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo("netsh",
                    $"advfirewall firewall delete rule name=\"{ruleName}\"")
                { CreateNoWindow = true, UseShellExecute = false });
            p?.WaitForExit(5000);
        }
        catch { }
    }

    internal static string ListFirewallRules()
    {
        var rules = new List<TcpFirewallRuleStub>();
        try
        {
            // Try COM API first
            var policyType = Type.GetTypeFromProgID("HNetCfg.FwPolicy2", throwOnError: false);
            if (policyType != null)
            {
                var gf = System.Reflection.BindingFlags.GetProperty;
                var policy = Activator.CreateInstance(policyType);
                if (policy != null)
                {
                    var rulesCol = policy.GetType().InvokeMember("Rules", gf, null, policy, null)!;
                    // INetFwRules is enumerable via GetEnumerator
                    var enumerator = rulesCol.GetType().InvokeMember("GetEnumerator",
                        System.Reflection.BindingFlags.InvokeMethod, null, rulesCol, null);
                    if (enumerator is System.Collections.IEnumerator en)
                    {
                        while (en.MoveNext())
                        {
                            var r = en.Current;
                            if (r == null) continue;
                            var rt = r.GetType();
                            string? name = rt.InvokeMember("Name", gf, null, r, null) as string;
                            if (name == null || !name.StartsWith("SeroBlock_")) continue;
                            int dir = (int)(rt.InvokeMember("Direction", gf, null, r, null) ?? 0);
                            rules.Add(new TcpFirewallRuleStub { RuleName = name, Direction = dir == 1 ? "in" : "out" });
                        }
                    }
                    return JsonSerializer.Serialize(new TcpFirewallRulesResultStub { Rules = rules }, SeroJson.Default.TcpFirewallRulesResultStub);
                }
            }
        }
        catch { }

        // Fallback: parse netsh output
        try
        {
            using var p = System.Diagnostics.Process.Start(
                new System.Diagnostics.ProcessStartInfo("netsh", "advfirewall firewall show rule name=all")
                { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true });
            var output = p?.StandardOutput.ReadToEnd() ?? "";
            string? rName = null;
            foreach (var line in output.Split('\n'))
            {
                var l = line.Trim();
                if (l.StartsWith("Rule Name:", StringComparison.OrdinalIgnoreCase))
                {
                    rName = l[(l.IndexOf(':') + 1)..].Trim();
                    if (!rName.StartsWith("SeroBlock_")) rName = null;
                }
                else if (rName != null && l.StartsWith("Direction:", StringComparison.OrdinalIgnoreCase))
                {
                    var dir = l[(l.IndexOf(':') + 1)..].Trim().ToLower();
                    rules.Add(new TcpFirewallRuleStub { RuleName = rName, Direction = dir });
                    rName = null;
                }
            }
        }
        catch { }
        return JsonSerializer.Serialize(new TcpFirewallRulesResultStub { Rules = rules }, SeroJson.Default.TcpFirewallRulesResultStub);
    }
#pragma warning restore IL2072, IL2075
}

internal class TcpEntryStub
{
    public int    Pid         { get; set; }
    public string ProcessName { get; set; } = "";
    public string LocalAddr   { get; set; } = "";
    public string RemoteAddr  { get; set; } = "";
    public string State       { get; set; } = "";
}

internal class TcpListResultStub  { public List<TcpEntryStub> Entries { get; set; } = []; }
internal class TcpCloseDataStub   { public string LocalAddr { get; set; } = ""; public string RemoteAddr { get; set; } = ""; }
