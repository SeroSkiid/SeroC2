using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using SeroServer.Net;

namespace SeroServer.UI;

public partial class MinerStatsWindow : DevExpress.Xpf.Core.ThemedWindow
{
    private MinerStatsHost? _host;
    private readonly int _defaultPort;
    private readonly string _token;
    private readonly Action<MinerStatsHost?> _onHostChanged;
    private readonly DispatcherTimer _timer;

    public MinerStatsWindow(MinerStatsHost? existingHost, int defaultPort, string token, Action<MinerStatsHost?> onHostChanged)
    {
        InitializeComponent();
        _host = existingHost;
        _defaultPort = defaultPort;
        _token = token;
        _onHostChanged = onHostChanged;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _timer.Tick += (_, _) => Refresh();
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        Title = Lang.Get("MNR_STATS_TITLE");
        PillOnlineLbl.Text   = " " + Lang.Get("MNR_STATS_ONLINE");
        PillAcceptedLbl.Text = " " + Lang.Get("MNR_STATS_ACCEPTED");
        TxtStatsPort.Text = (_host?.Port ?? _defaultPort).ToString();
        UpdateStartStopUI();
        if (_host != null)
        {
            _host.Changed += OnChanged;
            _timer.Start();
            Refresh();
        }
    }

    private void Window_Closed(object sender, EventArgs e)
    {
        if (_host != null)
            _host.Changed -= OnChanged;
        _timer.Stop();
    }

    private void BtnStart_Click(object sender, RoutedEventArgs e)
    {
        if (!int.TryParse(TxtStatsPort.Text.Trim(), out int port) || port < 1 || port > 65535)
        {
            System.Windows.MessageBox.Show("Invalid port number.", "Miner Stats",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        try
        {
            _host = new MinerStatsHost(port, _token);
            _host.Start();
            _host.Changed += OnChanged;
            _onHostChanged(_host);
            _timer.Start();
            UpdateStartStopUI();
            Refresh();
        }
        catch (Exception ex)
        {
            _host = null;
            System.Windows.MessageBox.Show(ex.Message, "Miner Stats — Start Error",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BtnStop_Click(object sender, RoutedEventArgs e)
    {
        if (_host == null) return;
        _host.Changed -= OnChanged;
        _host.Stop();
        _host = null;
        _onHostChanged(null);
        _timer.Stop();
        MinerGrid.ItemsSource = null;
        PillOnline.Text   = "0";
        PillHashrate.Text = "0.0 H/s";
        PillAccepted.Text = "0";
        FooterStatus.Text = "";
        UpdateStartStopUI();
    }

    private void UpdateStartStopUI()
    {
        bool running = _host != null;
        PortPanel.Visibility = running ? Visibility.Collapsed : Visibility.Visible;
        BtnStart.Visibility  = running ? Visibility.Collapsed : Visibility.Visible;
        BtnStop.Visibility   = running ? Visibility.Visible   : Visibility.Collapsed;
        StatusDot.Fill = running
            ? new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E))
            : new SolidColorBrush(Color.FromRgb(0x6B, 0x72, 0x80));
        LblStatus.Text   = running ? "Running" : "Stopped";
        LblEndpoint.Text = running ? $"  ·  http://localhost:{_host!.Port}/api/report" : "";
    }

    private void OnChanged() => Dispatcher.BeginInvoke(Refresh);

    private void BtnRefresh_Click(object sender, RoutedEventArgs e) => Refresh();

    private void Refresh()
    {
        if (_host == null) return;
        var rows = _host.Miners
            .OrderByDescending(m => m.Online)
            .ThenByDescending(m => m.H1s)
            .Select(m => new MinerRow(m))
            .ToList();

        MinerGrid.ItemsSource = rows;

        int    online = rows.Count(r => r.Online);
        double totalH = rows.Where(r => r.Online).Sum(r => r.Entry.H1s);
        int    totalA = rows.Where(r => r.Online).Sum(r => r.Entry.Accepted);

        PillOnline.Text   = online.ToString();
        PillHashrate.Text = totalH >= 1000 ? $"{totalH / 1000.0:F2} KH/s" : $"{totalH:F1} H/s";
        PillAccepted.Text = totalA.ToString();
        FooterStatus.Text = $"{Lang.Get("MNR_STATS_LAST_REFRESH")} {DateTime.Now:HH:mm:ss}  ·  {rows.Count} {Lang.Get("MNR_STATS_TOTAL")}";
    }
}

internal sealed class MinerRow(MinerEntry e)
{
    public MinerEntry Entry   => e;
    public bool   Online      => e.Online;
    public string StatusText  => e.Online ? "● ONLINE" : "○ OFFLINE";
    public string Hostname    => e.Hostname;
    public string Ip          => e.Ip;
    public string CpuShort    => e.Cpu.Length > 30 ? e.Cpu[..27] + "…" : e.Cpu;
    public string H1sStr      => e.H1s >= 1000 ? $"{e.H1s / 1000.0:F2}K" : $"{e.H1s:F1}";
    public string Algo        => e.Algo;
    public string PoolShort   => e.Pool.Length > 35 ? e.Pool[..32] + "…" : e.Pool;
    public int    Accepted    => e.Accepted;
    public string UptimeStr   => e.Uptime < 3600 ? $"{e.Uptime / 60}m" : $"{e.Uptime / 3600}h {e.Uptime % 3600 / 60}m";
    public string LastSeenStr => $"{(int)(DateTime.UtcNow - e.LastSeen).TotalMinutes}m ago";
}
