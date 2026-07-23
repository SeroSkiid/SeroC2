using System.Windows;
using System.Windows.Threading;
using SeroServer.Net;

namespace SeroServer.UI;

public partial class MinerStatsWindow : DevExpress.Xpf.Core.ThemedWindow
{
    private readonly MinerStatsHost _host;
    private readonly DispatcherTimer _timer;

    public MinerStatsWindow(MinerStatsHost host)
    {
        InitializeComponent();
        _host = host;
        _timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _timer.Tick += (_, _) => Refresh();
    }

    private void Window_Loaded(object sender, RoutedEventArgs e)
    {
        Title         = Lang.Get("MNR_STATS_TITLE");
        WndTitle.Text = Lang.Get("MNR_STATS_TITLE").ToUpper();
        LblEndpoint.Text = $"http://localhost:{_host.Port}/api/report";
        PillOnlineLbl.Text    = " " + Lang.Get("MNR_STATS_ONLINE");
        PillAcceptedLbl.Text  = " " + Lang.Get("MNR_STATS_ACCEPTED");
        _host.Changed += OnChanged;
        _timer.Start();
        Refresh();
    }

    private void Window_Closed(object sender, EventArgs e)
    {
        _host.Changed -= OnChanged;
        _timer.Stop();
    }

    private void OnChanged() => Dispatcher.BeginInvoke(Refresh);

    private void BtnRefresh_Click(object sender, RoutedEventArgs e) => Refresh();

    private void Refresh()
    {
        var rows = _host.Miners
            .OrderByDescending(m => m.Online)
            .ThenByDescending(m => m.H1s)
            .Select(m => new MinerRow(m))
            .ToList();

        MinerGrid.ItemsSource = rows;

        int online  = rows.Count(r => r.Online);
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
    public MinerEntry Entry      => e;
    public bool   Online         => e.Online;
    public string StatusText     => e.Online ? "● ONLINE" : "○ OFFLINE";
    public string Hostname       => e.Hostname;
    public string Ip             => e.Ip;
    public string CpuShort       => e.Cpu.Length > 30 ? e.Cpu[..27] + "…" : e.Cpu;
    public string H1sStr         => e.H1s >= 1000 ? $"{e.H1s / 1000.0:F2}K" : $"{e.H1s:F1}";
    public string Algo           => e.Algo;
    public string PoolShort      => e.Pool.Length > 35 ? e.Pool[..32] + "…" : e.Pool;
    public int    Accepted       => e.Accepted;
    public string UptimeStr      => e.Uptime < 3600 ? $"{e.Uptime / 60}m" : $"{e.Uptime / 3600}h {e.Uptime % 3600 / 60}m";
    public string LastSeenStr    => $"{(int)(DateTime.UtcNow - e.LastSeen).TotalMinutes}m ago";
}
