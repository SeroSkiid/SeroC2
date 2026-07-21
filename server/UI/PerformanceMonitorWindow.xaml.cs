using System.Collections.Generic;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Shapes;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class PerformanceMonitorWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;

    private readonly List<float> _cpuHistory  = [];
    private readonly List<float> _ramHistory  = [];
    private readonly List<long>  _netSHistory = [];
    private readonly List<long>  _netRHistory = [];
    private const int MaxPoints = 60;

    // Reusable poly cache per canvas (avoids per-tick allocation)
    private sealed class SparklineCache
    {
        public Polygon? FillPoly;
        public Polyline? LinePoly;
        public double PrevW, PrevH;
        public bool EnsureCreated(Canvas c, Color lineColor, Color fillColor)
        {
            if (FillPoly != null && LinePoly != null) return false;
            FillPoly = new Polygon { Fill = new SolidColorBrush(Color.FromArgb(0x40, fillColor.R, fillColor.G, fillColor.B)), StrokeThickness = 0 };
            LinePoly = new Polyline { Stroke = new SolidColorBrush(lineColor), StrokeThickness = 1.5 };
            c.Children.Add(FillPoly);
            c.Children.Add(LinePoly);
            return true;
        }
    }
    private sealed class DualSparklineCache
    {
        public Polyline? SentPoly, RecvPoly;
        public double PrevW, PrevH;
        public bool EnsureCreated(Canvas c, Color sentCol, Color recvCol)
        {
            if (SentPoly != null && RecvPoly != null) return false;
            SentPoly = new Polyline { Stroke = new SolidColorBrush(sentCol), StrokeThickness = 1.5 };
            RecvPoly = new Polyline { Stroke = new SolidColorBrush(recvCol), StrokeThickness = 1.5 };
            c.Children.Add(SentPoly);
            c.Children.Add(RecvPoly);
            return true;
        }
    }

    private readonly Dictionary<Canvas, SparklineCache> _sparkCaches = [];
    private readonly Dictionary<Canvas, DualSparklineCache> _dualSparkCaches = [];

    public PerformanceMonitorWindow(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;

        _server.RegisterHandler(clientId, PacketType.PerfMonData, OnPerfData);
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.PerfMonData);
            _ = _server.SendToClient(clientId, new Packet { Type = PacketType.PerfMonStop });
            Lang.LanguageChanged -= ApplyLanguage;
        };

        _ = _server.SendToClient(clientId, new Packet
        {
            Type = PacketType.PerfMonStart,
            Data = JsonConvert.SerializeObject(new PerfMonStartData { IntervalMs = 1000 })
        });
        TxtStatus.Text = Lang.Get("PERF_STREAMING");
    }

    private void ApplyLanguage() { this.Title = Lang.Get("FEAT_PERF_MONITOR"); }

    private void OnPerfData(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<PerfMonData>(pkt.Data);
        if (d == null) return;
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
        {
            // CPU
            AddPoint(_cpuHistory, d.CpuUsage);
            TxtCpu.Text = $"{d.CpuUsage:F1}%";
            SetBar(BarCpu, d.CpuUsage / 100f);
            DrawSparkline(SparkCpu, _cpuHistory, 100f,
                Color.FromRgb(0x4A, 0x85, 0xF5), Color.FromRgb(0x1A, 0x30, 0x60));

            // RAM
            float ramPct = d.RamTotal > 0 ? (float)d.RamUsed / d.RamTotal * 100f : 0f;
            AddPoint(_ramHistory, ramPct);
            TxtRam.Text = $"{d.RamUsed:N0} / {d.RamTotal:N0} MB";
            SetBar(BarRam, ramPct / 100f);
            DrawSparkline(SparkRam, _ramHistory, 100f,
                Color.FromRgb(0x7C, 0x5C, 0xE8), Color.FromRgb(0x28, 0x10, 0x60));

            // Network
            AddPointL(_netSHistory, d.NetworkSentKB);
            AddPointL(_netRHistory, d.NetworkRecvKB);
            TxtNetSent.Text = FormatKB(d.NetworkSentKB);
            TxtNetRecv.Text = FormatKB(d.NetworkRecvKB);
            float maxNet = Math.Max(1f, Math.Max(
                _netSHistory.Count > 0 ? _netSHistory.Max() : 1,
                _netRHistory.Count > 0 ? _netRHistory.Max() : 1));
            DrawDualSparkline(SparkNet, _netSHistory, _netRHistory, maxNet);

            TxtStatus.Text = $"Updated {DateTime.Now:HH:mm:ss}";
        });
    }

    private static void AddPoint(List<float> list, float v)
    { list.Add(v); if (list.Count > MaxPoints) list.RemoveAt(0); }

    private static void AddPointL(List<long> list, long v)
    { list.Add(v); if (list.Count > MaxPoints) list.RemoveAt(0); }

    private static void SetBar(System.Windows.Controls.Border bar, float fraction)
    {
        fraction = Math.Max(0f, Math.Min(1f, fraction));
        var parent = (System.Windows.Controls.Border)bar.Parent;
        bar.Width = Math.Max(0, parent.ActualWidth * fraction);
    }

    private void DrawSparkline(Canvas canvas, List<float> data, float max, Color lineColor, Color fillColor)
    {
        if (data.Count < 2) return;

        double w = canvas.ActualWidth;
        double h = canvas.ActualHeight;
        if (w < 2 || h < 2) return;

        if (!_sparkCaches.TryGetValue(canvas, out var cache))
        {
            cache = new SparklineCache();
            _sparkCaches[canvas] = cache;
        }
        cache.EnsureCreated(canvas, lineColor, fillColor);
        cache.PrevW = w;
        cache.PrevH = h;

        double step = w / (MaxPoints - 1);
        var fillPts = cache.FillPoly!.Points;
        var linePts = cache.LinePoly!.Points;
        fillPts.Clear();
        linePts.Clear();

        fillPts.Add(new Point((MaxPoints - data.Count) * step, h));
        for (int i = 0; i < data.Count; i++)
        {
            double x = (MaxPoints - data.Count + i) * step;
            double y = h - (data[i] / max * h);
            fillPts.Add(new Point(x, y));
            linePts.Add(new Point(x, y));
        }
        fillPts.Add(new Point(linePts[^1].X, h));
    }

    private void DrawDualSparkline(Canvas canvas, List<long> sent, List<long> recv, float max)
    {
        double w = canvas.ActualWidth;
        double h = canvas.ActualHeight;
        if (w < 2 || h < 2 || sent.Count < 2) return;

        if (!_dualSparkCaches.TryGetValue(canvas, out var cache))
        {
            cache = new DualSparklineCache();
            _dualSparkCaches[canvas] = cache;
        }
        cache.EnsureCreated(canvas, Color.FromRgb(0x22, 0xC5, 0x5E), Color.FromRgb(0x4A, 0x85, 0xF5));
        cache.PrevW = w;
        cache.PrevH = h;

        double step = w / (MaxPoints - 1);

        var sentPts = cache.SentPoly!.Points;
        sentPts.Clear();
        for (int i = 0; i < sent.Count; i++)
        {
            double x = (MaxPoints - sent.Count + i) * step;
            double y = h - (sent[i] / max * h);
            sentPts.Add(new Point(x, y));
        }

        var recvPts = cache.RecvPoly!.Points;
        recvPts.Clear();
        for (int i = 0; i < recv.Count; i++)
        {
            double x = (MaxPoints - recv.Count + i) * step;
            double y = h - (recv[i] / max * h);
            recvPts.Add(new Point(x, y));
        }
    }

    private static string FormatKB(long kb)
    {
        if (kb >= 1024) return $"{kb / 1024.0:F1} MB/s";
        return $"{kb} KB/s";
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void BtnMenu_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button btn) return;
        var mainWindow = System.Windows.Application.Current.Windows.OfType<ServerWindow>().FirstOrDefault();
        if (mainWindow == null) return;
        var menu = FeatureContextMenu.Build(_server, _clientId, mainWindow, "PerformanceMonitorWindow");
        btn.ContextMenu = menu;
        menu.PlacementTarget = btn;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.IsOpen = true;
    }
}
