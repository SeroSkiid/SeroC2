using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SeroStub;

internal static class ProcessManagerFeature
{
    [DllImport("ntdll.dll")] private static extern int NtSuspendProcess(IntPtr hProcess);
    [DllImport("ntdll.dll")] private static extern int NtResumeProcess(IntPtr hProcess);
    [DllImport("kernel32.dll")] private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr h);

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [DllImport("kernel32.dll")] private static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS c);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION { public nint ExitStatus, PebBase, Affinity, Priority, Pid, ParentPid; }
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr h, int cls, out PROCESS_BASIC_INFORMATION info, int sz, out int ret);

    private static int GetParentPid(int pid)
    {
        var h = OpenProcess(0x0400, false, pid); // PROCESS_QUERY_INFORMATION
        if (h == IntPtr.Zero) return 0;
        try
        {
            return NtQueryInformationProcess(h, 0, out var pbi,
                Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _) == 0
                ? (int)pbi.ParentPid : 0;
        }
        catch { return 0; }
        finally { CloseHandle(h); }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX { public uint dwLength, dwMemoryLoad; public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtVirtual; }
    [DllImport("kernel32.dll")] private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);

    private static long GetTotalRamMb()
    {
        var ms = new MEMORYSTATUSEX { dwLength = (uint)Marshal.SizeOf<MEMORYSTATUSEX>() };
        return GlobalMemoryStatusEx(ref ms) ? (long)(ms.ullTotalPhys / 1024 / 1024) : 0;
    }

    private const uint PROCESS_SUSPEND_RESUME = 0x0800;

    // ── TCP connection count per PID (via GetExtendedTcpTable) ───────────────
    [DllImport("iphlpapi.dll")] private static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref uint dwSize, bool sort, int ipVersion, int tableClass, uint reserved);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID { public uint dwState, dwLocalAddr, dwLocalPort, dwRemoteAddr, dwRemotePort, dwOwningPid; }

    // Returns per-PID list of distinct remote IPs (ESTABLISHED connections only)
    private static Dictionary<int, List<string>> GetTcpByPid()
    {
        var result = new Dictionary<int, List<string>>();
        try
        {
            uint size = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref size, false, 2, 5, 0);
            if (size == 0) return result;
            var buf = Marshal.AllocHGlobal((int)size);
            try
            {
                if (GetExtendedTcpTable(buf, ref size, false, 2, 5, 0) != 0) return result;
                int count = Marshal.ReadInt32(buf);
                int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
                for (int i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(buf + 4 + i * rowSize);
                    if (row.dwState != 5) continue; // 5 = ESTABLISHED only
                    int pid = (int)row.dwOwningPid;
                    var remIp = new System.Net.IPAddress(row.dwRemoteAddr).ToString();
                    if (!result.TryGetValue(pid, out var list)) result[pid] = list = [];
                    if (!list.Contains(remIp)) list.Add(remIp);
                }
            }
            finally { Marshal.FreeHGlobal(buf); }
        }
        catch { }
        return result;
    }

    // Per-process CPU sampling: (lastTotalCpuTime, lastSampleTime)
    private static readonly Dictionary<int, (TimeSpan cpu, DateTime ts)> _cpuSamples = [];
    private static readonly int _cpuCount = Environment.ProcessorCount;

    // Per-process network I/O sampling (OtherBytes ≈ network traffic)
    private static readonly Dictionary<int, (ulong bytes, DateTime ts)> _netSamples = [];
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    private static float GetNetKbps(int pid, DateTime now)
    {
        var h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        if (h == IntPtr.Zero) return 0f;
        try
        {
            if (!GetProcessIoCounters(h, out var io)) return 0f;
            if (_netSamples.TryGetValue(pid, out var prev))
            {
                var delta = io.OtherBytes >= prev.bytes ? io.OtherBytes - prev.bytes : 0UL;
                var ms    = (now - prev.ts).TotalMilliseconds;
                _netSamples[pid] = (io.OtherBytes, now);
                return ms > 100 ? (float)(delta / 1024.0 / (ms / 1000.0)) : 0f;
            }
            _netSamples[pid] = (io.OtherBytes, now);
            return 0f;
        }
        finally { CloseHandle(h); }
    }

    internal static string GetProcessList()
    {
        var now = DateTime.UtcNow;
        var totalRamMb = GetTotalRamMb();
        var tcpCounts = GetTcpByPid();
        var list = new List<ProcEntryStub>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                float cpuPct = 0f;
                try
                {
                    var totalCpu = p.TotalProcessorTime;
                    if (_cpuSamples.TryGetValue(p.Id, out var prev))
                    {
                        var deltaCpu = (totalCpu - prev.cpu).TotalMilliseconds;
                        var deltaMs  = (now - prev.ts).TotalMilliseconds;
                        if (deltaMs > 0)
                            cpuPct = (float)(deltaCpu / (deltaMs * _cpuCount) * 100.0);
                        cpuPct = Math.Max(0f, Math.Min(100f, cpuPct));
                    }
                    _cpuSamples[p.Id] = (totalCpu, now);
                }
                catch { }

                tcpCounts.TryGetValue(p.Id, out var remIps);
                list.Add(new ProcEntryStub
                {
                    Pid       = p.Id,
                    ParentPid = GetParentPid(p.Id),
                    Name      = p.ProcessName,
                    Memory    = p.WorkingSet64 / 1024,
                    CpuUsage  = cpuPct,
                    TcpConns  = remIps?.Count ?? 0,
                    RemoteIps = remIps,
                    NetKbps   = GetNetKbps(p.Id, now),
                    Title     = p.MainWindowTitle,
                    ExePath   = GetExePath(p)
                });
            }
            catch { list.Add(new ProcEntryStub { Pid = p.Id, Name = p.ProcessName }); }
            finally { try { p.Dispose(); } catch { } }
        }

        // Remove stale samples for dead processes
        var livePids = new HashSet<int>(list.Select(x => x.Pid));
        foreach (var k in _cpuSamples.Keys.Where(k => !livePids.Contains(k)).ToList())
            _cpuSamples.Remove(k);
        foreach (var k in _netSamples.Keys.Where(k => !livePids.Contains(k)).ToList())
            _netSamples.Remove(k);

        list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return JsonSerializer.Serialize(
            new ProcListResultStub { Processes = list, TotalRamMb = totalRamMb, StubPid = Environment.ProcessId },
            SeroJson.Default.ProcListResultStub);
    }

    internal static bool Kill(int pid)
    {
        try { Process.GetProcessById(pid).Kill(); return true; }
        catch { return false; }
    }

    internal static bool Suspend(int pid)
    {
        var h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return NtSuspendProcess(h) >= 0; }
        finally { CloseHandle(h); }
    }

    internal static bool Resume(int pid)
    {
        var h = OpenProcess(PROCESS_SUSPEND_RESUME, false, pid);
        if (h == IntPtr.Zero) return false;
        try { return NtResumeProcess(h) >= 0; }
        finally { CloseHandle(h); }
    }

    private static string GetExePath(Process p)
    {
        try { return p.MainModule?.FileName ?? ""; }
        catch { return ""; }
    }
}

internal class ProcEntryStub
{
    public int           Pid       { get; set; }
    public int           ParentPid { get; set; }
    public string        Name      { get; set; } = "";
    public long          Memory    { get; set; }
    public float         CpuUsage  { get; set; }
    public int           TcpConns  { get; set; }
    public List<string>? RemoteIps { get; set; }
    public float         NetKbps   { get; set; }
    public string        Title     { get; set; } = "";
    public string        ExePath   { get; set; } = "";
}
internal class ProcListResultStub { public List<ProcEntryStub> Processes { get; set; } = []; public long TotalRamMb { get; set; } public int StubPid { get; set; } }
internal class ProcKillDataStub   { public int Pid { get; set; } }
