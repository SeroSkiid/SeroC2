using System.Collections.Concurrent;
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
    [DllImport("kernel32.dll")] private static extern bool GetProcessTimes(IntPtr h, out long created, out long exited, out long kernel, out long user);

    private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);
    [DllImport("user32.dll")] private static extern bool EnumWindows(EnumWindowsProc cb, IntPtr lp);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int  GetWindowTextLength(IntPtr hwnd);
    [DllImport("user32.dll", CharSet = CharSet.Unicode)] private static extern int GetWindowText(IntPtr hwnd, System.Text.StringBuilder sb, int n);

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
    [DllImport("kernel32.dll")] private static extern bool GetProcessIoCounters(IntPtr hProcess, out IO_COUNTERS c);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_BASIC_INFORMATION { public nint ExitStatus, PebBase, Affinity, Priority, Pid, ParentPid; }
    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(IntPtr h, int cls, out PROCESS_BASIC_INFORMATION info, int sz, out int ret);

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

    // Per-process I/O sampling (ReadBytes + WriteBytes = disk + network activity)
    private static readonly Dictionary<int, (ulong bytes, DateTime ts)> _netSamples = [];
    private static readonly object _samplesLock = new();
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;

    private static readonly ConcurrentDictionary<string, string> _iconCache = new();
    private static readonly HashSet<string> _sentIconPaths = [];
    private static readonly object _sentLock = new();

    internal static void ResetSentIcons() { lock (_sentLock) _sentIconPaths.Clear(); }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageName(IntPtr h, uint flags, System.Text.StringBuilder buf, ref uint sz);

    // Single handle per process: NtQueryInfo + IoCounters + QueryFullProcessImageName + GetProcessTimes.
    // Previously GetProcessInfoNative + GetExePath opened two separate handles per process.
    private static (int parentPid, float netKbps, string exePath, TimeSpan cpuTime) GetProcessInfoNative(int pid, DateTime now)
    {
        // Try full query first; fall back to limited for protected processes.
        var h = OpenProcess(PROCESS_QUERY_INFORMATION, false, pid);
        bool limited = h == IntPtr.Zero;
        if (limited) h = OpenProcess(0x1000, false, pid); // PROCESS_QUERY_LIMITED_INFORMATION
        if (h == IntPtr.Zero) return (0, 0f, "", TimeSpan.Zero);
        try
        {
            int parentPid = 0;
            float netKbps = 0f;
            if (!limited)
            {
                if (NtQueryInformationProcess(h, 0, out var pbi,
                    Marshal.SizeOf<PROCESS_BASIC_INFORMATION>(), out _) == 0)
                    parentPid = (int)pbi.ParentPid;

                if (GetProcessIoCounters(h, out var io))
                {
                    var totalIo = io.ReadBytes + io.WriteBytes;
                    lock (_samplesLock)
                    {
                        if (_netSamples.TryGetValue(pid, out var prev))
                        {
                            var delta = totalIo >= prev.bytes ? totalIo - prev.bytes : 0UL;
                            var ms    = (now - prev.ts).TotalMilliseconds;
                            _netSamples[pid] = (totalIo, now);
                            netKbps = ms > 100 ? (float)(delta / 1024.0 / (ms / 1000.0)) : 0f;
                        }
                        else _netSamples[pid] = (totalIo, now);
                    }
                }
            }

            var sb = new System.Text.StringBuilder(1024);
            uint sz = 1024;
            string exePath = QueryFullProcessImageName(h, 0, sb, ref sz) ? sb.ToString() : "";

            TimeSpan cpuTime = TimeSpan.Zero;
            if (GetProcessTimes(h, out _, out _, out long kernelTime, out long userTime))
                cpuTime = TimeSpan.FromTicks(kernelTime + userTime);

            return (parentPid, netKbps, exePath, cpuTime);
        }
        catch { return (0, 0f, "", TimeSpan.Zero); }
        finally { CloseHandle(h); }
    }

    // Single EnumWindows call → PID→title map, replacing p.MainWindowTitle per-process.
    private static Dictionary<int, string> GetWindowTitles()
    {
        var map = new Dictionary<int, string>();
        EnumWindows((hwnd, _) =>
        {
            if (!IsWindowVisible(hwnd)) return true;
            GetWindowThreadProcessId(hwnd, out uint pid);
            if (map.ContainsKey((int)pid)) return true;
            int len = GetWindowTextLength(hwnd);
            if (len > 0)
            {
                var sb = new System.Text.StringBuilder(len + 1);
                GetWindowText(hwnd, sb, len + 1);
                string title = sb.ToString();
                if (!string.IsNullOrEmpty(title)) map[(int)pid] = title;
            }
            return true;
        }, IntPtr.Zero);
        return map;
    }

    internal static string GetProcessList(bool fresh = false)
    {
        if (fresh) ResetSentIcons();
        return GetProcessListCore();
    }

    private static string GetProcessListCore()
    {
        var now = DateTime.UtcNow;
        var totalRamMb = GetTotalRamMb();
        var tcpCounts  = GetTcpByPid();
        var windowTitles = GetWindowTitles(); // single EnumWindows call for all processes
        var list = new List<ProcEntryStub>();
        foreach (var p in Process.GetProcesses())
        {
            try
            {
                tcpCounts.TryGetValue(p.Id, out var remIps);
                var (parentPid, netKbps, exePath, cpuTime) = GetProcessInfoNative(p.Id, now);

                float cpuPct = 0f;
                if (cpuTime != TimeSpan.Zero)
                {
                    lock (_samplesLock)
                    {
                        if (_cpuSamples.TryGetValue(p.Id, out var prev))
                        {
                            var deltaCpu = (cpuTime - prev.cpu).TotalMilliseconds;
                            var deltaMs  = (now - prev.ts).TotalMilliseconds;
                            if (deltaMs > 0)
                                cpuPct = (float)(deltaCpu / (deltaMs * _cpuCount) * 100.0);
                            cpuPct = Math.Max(0f, Math.Min(100f, cpuPct));
                        }
                        _cpuSamples[p.Id] = (cpuTime, now);
                    }
                }

                windowTitles.TryGetValue(p.Id, out var title);
                list.Add(new ProcEntryStub
                {
                    Pid       = p.Id,
                    ParentPid = parentPid,
                    Name      = p.ProcessName,
                    Memory    = p.WorkingSet64 / 1024,
                    CpuUsage  = cpuPct,
                    TcpConns  = remIps?.Count ?? 0,
                    RemoteIps = remIps,
                    NetKbps   = netKbps,
                    Title     = title ?? "",
                    ExePath   = exePath,
                    // IconB64 populated below after parallel pre-warm
                });
            }
            catch { list.Add(new ProcEntryStub { Pid = p.Id, Name = p.ProcessName }); }
            finally { try { p.Dispose(); } catch { } }
        }

        // Pre-warm icon cache for new paths in parallel (SHGetFileInfo is the bottleneck on first open)
        var newPaths = list
            .Select(e => e.ExePath)
            .Where(path => !string.IsNullOrEmpty(path) && !_iconCache.ContainsKey(path))
            .Distinct()
            .ToList();
        if (newPaths.Count > 0)
        {
            Parallel.ForEach(newPaths, new ParallelOptions { MaxDegreeOfParallelism = Math.Min(32, Environment.ProcessorCount * 2) }, path =>
            {
                var b64 = StubIconHelper.ExtractExeIcon(path);
                _iconCache.TryAdd(path, string.IsNullOrEmpty(b64) ? StubIconHelper.GetGenericExeIcon() : b64);
            });
        }

        // Assign icons — skip paths already sent to this session to avoid resending ~50-80KB every 2s
        lock (_sentLock)
        {
            foreach (var e in list)
            {
                var key = string.IsNullOrEmpty(e.ExePath) ? "\x00" : e.ExePath;
                if (_sentIconPaths.Contains(key)) continue;
                e.IconB64 = string.IsNullOrEmpty(e.ExePath)
                    ? StubIconHelper.GetGenericExeIcon()
                    : _iconCache.GetOrAdd(e.ExePath, _ => StubIconHelper.GetGenericExeIcon());
                _sentIconPaths.Add(key);
            }
        }

        // Remove stale samples for dead processes
        var livePids = new HashSet<int>(list.Select(x => x.Pid));
        lock (_samplesLock)
        {
            foreach (var k in _cpuSamples.Keys.Where(k => !livePids.Contains(k)).ToList())
                _cpuSamples.Remove(k);
            foreach (var k in _netSamples.Keys.Where(k => !livePids.Contains(k)).ToList())
                _netSamples.Remove(k);
        }

        list.Sort((a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return JsonSerializer.Serialize(
            new ProcListResultStub { Processes = list, TotalRamMb = totalRamMb, StubPid = Environment.ProcessId },
            SeroJson.Default.ProcListResultStub);
    }

    internal static bool Kill(int pid)
    {
        try { using var p = Process.GetProcessById(pid); p.Kill(); return true; }
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
    public string        IconB64   { get; set; } = "";
}
internal class ProcListResultStub { public List<ProcEntryStub> Processes { get; set; } = []; public long TotalRamMb { get; set; } public int StubPid { get; set; } }
internal class ProcKillDataStub   { public int Pid { get; set; } }
