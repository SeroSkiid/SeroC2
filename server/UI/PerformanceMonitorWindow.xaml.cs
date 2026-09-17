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

    private readonly List<float> _cpuHistory   = [];
    private readonly List<float> _ramHistory   = [];
    private readonly List<long>  _netSHistory  = [];
    private readonly List<long>  _netRHistory  = [];
    private readonly List<long>  _diskRHistory = [];
    private readonly List<long>  _diskWHistory = [];
    private readonly List<float> _gpuHistory   = [];
    private const int MaxPoints = 60;

    // ── Sparkline caches (avoids per-tick allocation) ──────────────────────

    private sealed class SparklineCache
    {
        public Polygon?  FillPoly;
        public Polyline? LinePoly;
        public Line?     GridMid, GridQ1, GridQ3;

        public void EnsureCreated(Canvas c, Color lineColor, Color fillColor)
        {
            if (FillPoly != null) return;
            var gridBrush = new SolidColorBrush(Color.FromArgb(0x22, 0xFF, 0xFF, 0xFF));
            var da = new DoubleCollection { 3, 5 };
            GridQ1  = new Line { Stroke = gridBrush, StrokeThickness = 0.5, StrokeDashArray = da };
            GridMid = new Line { Stroke = gridBrush, StrokeThickness = 0.5, StrokeDashArray = da };
            GridQ3  = new Line { Stroke = gridBrush, StrokeThickness = 0.5, StrokeDashArray = da };
            FillPoly = new Polygon { Fill = new SolidColorBrush(Color.FromArgb(0x40, fillColor.R, fillColor.G, fillColor.B)), StrokeThickness = 0 };
            LinePoly = new Polyline { Stroke = new SolidColorBrush(lineColor), StrokeThickness = 1.5 };
            c.Children.Add(GridQ1);
            c.Children.Add(GridMid);
            c.Children.Add(GridQ3);
            c.Children.Add(FillPoly);
            c.Children.Add(LinePoly);
        }

        public void UpdateGridLines(double w, double h)
        {
            if (GridMid == null) return;
            GridQ1!.X1  = 0; GridQ1.X2  = w; GridQ1.Y1  = GridQ1.Y2  = h * 0.75;
            GridMid.X1  = 0; GridMid.X2 = w; GridMid.Y1 = GridMid.Y2 = h * 0.50;
            GridQ3!.X1  = 0; GridQ3.X2  = w; GridQ3.Y1  = GridQ3.Y2  = h * 0.25;
        }
    }

    private sealed class DualSparklineCache
    {
        public Polygon?  SentFill, RecvFill;
        public Polyline? SentPoly, RecvPoly;
        public Line?     GridMid;

        public void EnsureCreated(Canvas c, Color sentCol, Color recvCol)
        {
            if (SentPoly != null) return;
            var gridBrush = new SolidColorBrush(Color.FromArgb(0x22, 0xFF, 0xFF, 0xFF));
            GridMid = new Line { Stroke = gridBrush, StrokeThickness = 0.5, StrokeDashArray = new DoubleCollection { 3, 5 } };
            SentFill = new Polygon { Fill = new SolidColorBrush(Color.FromArgb(0x35, sentCol.R, sentCol.G, sentCol.B)), StrokeThickness = 0 };
            RecvFill = new Polygon { Fill = new SolidColorBrush(Color.FromArgb(0x35, recvCol.R, recvCol.G, recvCol.B)), StrokeThickness = 0 };
            SentPoly = new Polyline { Stroke = new SolidColorBrush(sentCol), StrokeThickness = 1.5 };
            RecvPoly = new Polyline { Stroke = new SolidColorBrush(recvCol), StrokeThickness = 1.5 };
            c.Children.Add(GridMid);
            c.Children.Add(SentFill);
            c.Children.Add(RecvFill);
            c.Children.Add(SentPoly);
            c.Children.Add(RecvPoly);
        }
    }

    private readonly Dictionary<Canvas, SparklineCache>     _sparkCaches     = [];
    private readonly Dictionary<Canvas, DualSparklineCache> _dualSparkCaches = [];

    public PerformanceMonitorWindow(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;

        _server.RegisterHandler(clientId, PacketType.PerfMonData, OnPerfData);
        _server.ClientDisconnected += OnClientDisconnected;
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.PerfMonData);
            _server.ClientDisconnected -= OnClientDisconnected;
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

    private void ApplyLanguage()
    {
        this.Title = Lang.Get("FEAT_PERF_MONITOR");
        if (TxtBtnActions != null) TxtBtnActions.Text = Lang.Get("ACT_ACTIONS");
    }

    private void OnPerfData(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<PerfMonData>(pkt.Data);
        if (d == null) return;
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
        {
            // ── CPU ──────────────────────────────────────────────────────────
            AddPoint(_cpuHistory, d.CpuUsage);
            TxtCpu.Text = $"{d.CpuUsage:F1}%";
            SetBar(BarCpu, d.CpuUsage / 100f);
            DrawSparkline(SparkCpu, _cpuHistory, 100f,
                Color.FromRgb(0x4A, 0x85, 0xF5), Color.FromRgb(0x1A, 0x30, 0x60));

            if (!string.IsNullOrEmpty(d.CpuName) && TxtCpuName.Visibility == Visibility.Collapsed)
            {
                TxtCpuName.Text       = d.CpuName;
                TxtCpuName.Visibility = Visibility.Visible;
            }

            // ── RAM ──────────────────────────────────────────────────────────
            float ramPct = d.RamTotal > 0 ? (float)d.RamUsed / d.RamTotal * 100f : 0f;
            AddPoint(_ramHistory, ramPct);
            TxtRam.Text = FormatMemory(d.RamUsed, d.RamTotal);
            SetBar(BarRam, ramPct / 100f);
            DrawSparkline(SparkRam, _ramHistory, 100f,
                Color.FromRgb(0x7C, 0x5C, 0xE8), Color.FromRgb(0x28, 0x10, 0x60));

            // ── Network ──────────────────────────────────────────────────────
            AddPointL(_netSHistory, d.NetworkSentKB);
            AddPointL(_netRHistory, d.NetworkRecvKB);
            TxtNetSent.Text = FormatKB(d.NetworkSentKB);
            TxtNetRecv.Text = FormatKB(d.NetworkRecvKB);
            float maxNet = (float)Math.Max(1L, Math.Max(
                _netSHistory.Count > 0 ? _netSHistory.Max() : 1L,
                _netRHistory.Count > 0 ? _netRHistory.Max() : 1L));
            DrawDualSparkline(SparkNet, _netSHistory, _netRHistory, maxNet,
                Color.FromRgb(0x22, 0xC5, 0x5E), Color.FromRgb(0x4A, 0x85, 0xF5));

            // ── Disk ─────────────────────────────────────────────────────────
            AddPointL(_diskRHistory, d.DiskReadKBps);
            AddPointL(_diskWHistory, d.DiskWriteKBps);
            TxtDiskRead.Text  = FormatKB(d.DiskReadKBps);
            TxtDiskWrite.Text = FormatKB(d.DiskWriteKBps);
            float maxDisk = (float)Math.Max(1L, Math.Max(
                _diskRHistory.Count > 0 ? _diskRHistory.Max() : 1L,
                _diskWHistory.Count > 0 ? _diskWHistory.Max() : 1L));
            DrawDualSparkline(SparkDisk, _diskRHistory, _diskWHistory, maxDisk,
                Color.FromRgb(0xF5, 0x9E, 0x42), Color.FromRgb(0xEC, 0x48, 0x99));

            // ── GPU ──────────────────────────────────────────────────────────
            if (!string.IsNullOrEmpty(d.GpuName) && TxtGpuName.Text != d.GpuName)
                TxtGpuName.Text = d.GpuName;
            if (d.GpuUsage >= 0f)
            {
                if (CardGpu.Visibility != Visibility.Visible)
                    CardGpu.Visibility = Visibility.Visible;
                TxtGpuUsage.Text = $"{d.GpuUsage:F1}%";
                SetBar(BarGpu, d.GpuUsage / 100f);
                AddPoint(_gpuHistory, d.GpuUsage);
                DrawSparkline(SparkGpu, _gpuHistory, 100f,
                    Color.FromRgb(0xF0, 0xB4, 0x29), Color.FromRgb(0x60, 0x40, 0x00));
            }
            else if (!string.IsNullOrEmpty(d.GpuName) && CardGpu.Visibility != Visibility.Visible)
            {
                CardGpu.Visibility = Visibility.Visible;
            }

            // ── Status bar ───────────────────────────────────────────────────
            TxtStatus.Text      = Lang.Get("PERF_STREAMING");
            TxtSampleCount.Text = $"{_cpuHistory.Count}/{MaxPoints}";
        });
    }

    private static void AddPoint(List<float> list, float v)
    { list.Add(v); if (list.Count > MaxPoints) list.RemoveAt(0); }

    private static void AddPointL(List<long> list, long v)
    { list.Add(v); if (list.Count > MaxPoints) list.RemoveAt(0); }

    private static void SetBar(Border bar, float fraction)
    {
        fraction = Math.Max(0f, Math.Min(1f, fraction));
        if (bar.Parent is Border parentBorder)
            bar.Width = Math.Max(0, parentBorder.ActualWidth * fraction);
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
        cache.UpdateGridLines(w, h);

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

    private void DrawDualSparkline(Canvas canvas, List<long> a, List<long> b, float max,
                                   Color colorA, Color colorB)
    {
        double w = canvas.ActualWidth;
        double h = canvas.ActualHeight;
        if (w < 2 || h < 2 || a.Count < 2) return;

        if (!_dualSparkCaches.TryGetValue(canvas, out var cache))
        {
            cache = new DualSparklineCache();
            _dualSparkCaches[canvas] = cache;
        }
        cache.EnsureCreated(canvas, colorA, colorB);

        // Update grid mid line
        if (cache.GridMid != null)
        { cache.GridMid.X1 = 0; cache.GridMid.X2 = w; cache.GridMid.Y1 = cache.GridMid.Y2 = h * 0.5; }

        double step = w / (MaxPoints - 1);

        DrawDualLine(cache.SentPoly!, cache.SentFill!, a, w, h, step, max);
        DrawDualLine(cache.RecvPoly!, cache.RecvFill!, b, w, h, step, max);
    }

    private static void DrawDualLine(Polyline line, Polygon fill, List<long> data,
                                     double w, double h, double step, float max)
    {
        var linePts = line.Points;
        var fillPts = fill.Points;
        linePts.Clear();
        fillPts.Clear();

        if (data.Count < 2) return;
        fillPts.Add(new Point((MaxPoints - data.Count) * step, h));
        for (int i = 0; i < data.Count; i++)
        {
            double x = (MaxPoints - data.Count + i) * step;
            double y = h - (data[i] / max * h);
            linePts.Add(new Point(x, y));
            fillPts.Add(new Point(x, y));
        }
        fillPts.Add(new Point(linePts[^1].X, h));
    }

    private static string FormatKB(long kb)
    {
        if (kb >= 1024) return $"{kb / 1024.0:F1} MB/s";
        return $"{kb} KB/s";
    }

    private static string FormatMemory(long usedMb, long totalMb)
    {
        if (totalMb >= 1024)
            return $"{usedMb / 1024.0:F1} / {totalMb / 1024.0:F1} GB";
        return $"{usedMb:N0} / {totalMb:N0} MB";
    }

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(() => TxtStatus.Text = Lang.Get("PM_DISCONNECTED"));
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
