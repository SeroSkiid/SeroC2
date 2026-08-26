using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using DevExpress.Xpf.Core;
using SkiaSharp;
using System.ComponentModel;
using SeroServer.Data;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class RemoteDesktopWindow : ThemedWindow
{
    // Stagger auto-start across simultaneously opened windows to avoid a burst of
    // RdpStart packets all firing at the same time when the user opens many windows.
    private static int _openCount = 0;

    // Per-instance cap on concurrent JPEG decode work.
    // Each window's Parallel.ForEach is bounded to 2 threads; making this instance-level
    // prevents semaphore count drift when a window closes mid-decode.
    private readonly SemaphoreSlim _decodeSlots =
        new(Math.Max(2, Environment.ProcessorCount / 2),
            Math.Max(2, Environment.ProcessorCount / 2));

    private readonly TlsServer _server;
    private string _clientId;
    private readonly string _hwid;
    private System.Windows.Threading.DispatcherTimer? _reconnectTimer;
    private int _reconnectCountdown;
    private bool _wasStreaming;
    private int _remoteW, _remoteH;
    private volatile int _screenW, _screenH;
    private int _frameCount;
    private DateTime _fpsTime = DateTime.UtcNow;
    private int _quality = 75;
    private volatile bool _renderBusy;
    private volatile bool _streaming;
    private volatile bool _closed;
    private volatile bool _updatingMonitors;
    private WriteableBitmap? _frame;
    private H264Decoder? _h264Dec;
    private readonly object _decodeLock = new object();
    private readonly List<(int Index, string Name, int X, int Y, int W, int H)> _monitors = [];
    private bool _uiReady;
    private bool _autoStarted;

    public RemoteDesktopWindow(TlsServer server, string clientId)
    {
        _server   = server;
        _clientId = clientId;
        _hwid     = server.ConnectedClients.TryGetValue(clientId, out var cc) ? cc.Hwid : string.Empty;
        InitializeComponent();
        WindowResizer.Enable(this);
        _uiReady = true;

        Title = $"Remote Desktop — {clientId}";
        SldQuality.Value = UiPrefs.GetInt("RdpQuality", 75);
        TxtQuality.Text  = $"{(int)SldQuality.Value}";
        SldScale.Value   = UiPrefs.GetInt("RdpScale", 100);
        TxtScale.Text    = $"{(int)SldScale.Value}%";
        SldQuality.ValueChanged += (_, e) => { TxtQuality.Text = $"{(int)e.NewValue}"; _quality = (int)e.NewValue; UiPrefs.Set("RdpQuality", (int)e.NewValue); };
        SldScale.ValueChanged   += (_, e) => { TxtScale.Text = $"{(int)e.NewValue}%"; UiPrefs.Set("RdpScale", (int)e.NewValue); };


        // Checkboxes always start unchecked — user enables manually each session

        // Reclaim keyboard focus on ImgFrame whenever focus leaves it.
        // Clicking the checkboxes in the status bar steals focus, which also
        // breaks MouseMove routing on the Focusable Image element.
        int rw = UiPrefs.GetInt("RdpWinWidth", 0), rh = UiPrefs.GetInt("RdpWinHeight", 0);
        if (rw > 440 && rh > 320) { Width = rw; Height = rh; }
        Activated       += (_, _) => { InstallHook(); if (_streaming) ImgFrame.Focus(); };
        Deactivated     += (_, _) => UninstallHook();
        SizeChanged     += (_, e) =>
        {
            if (_streaming) ImgFrame.Focus();
            UiPrefs.Set("RdpWinWidth",  (int)ActualWidth);
            UiPrefs.Set("RdpWinHeight", (int)ActualHeight);
        };
        ChkClicks.Checked   += (_, _) => { UiPrefs.Set("RdpClicks",    1); if (_streaming) ImgFrame.Focus(); };
        ChkClicks.Unchecked += (_, _) =>   UiPrefs.Set("RdpClicks",    0);
        ChkCursor.Checked   += (_, _) => { UiPrefs.Set("RdpCursor",    1); if (_streaming) ImgFrame.Focus(); };
        ChkCursor.Unchecked += (_, _) =>   UiPrefs.Set("RdpCursor",    0);
        ChkKeyboard.Checked   += (_, _) => { UiPrefs.Set("RdpKeyboard",  1); if (_streaming) ImgFrame.Focus(); };
        ChkKeyboard.Unchecked += (_, _) =>   UiPrefs.Set("RdpKeyboard",  0);
        ChkClipboard.Checked   += (_, _) => UiPrefs.Set("RdpClipboard", 1);
        ChkClipboard.Unchecked += (_, _) => UiPrefs.Set("RdpClipboard", 0);

        // Use O(1) per-client handler instead of broadcast event — critical for 100+ open windows
        _server.RegisterHandler(clientId, PacketType.RdpFrame,
            pkt => OnFrame(clientId, pkt.Data));
        _server.RegisterHandler(clientId, PacketType.RdpH264Frame,
            pkt => OnH264Frame(clientId, pkt.Data));
        _server.RegisterHandler(clientId, PacketType.RdpClipboard, pkt =>
        {
            var d = Newtonsoft.Json.JsonConvert.DeserializeObject<RdpClipboardData>(pkt.Data);
            if (d?.Text is { Length: > 0 }) OnRemoteClipboard(clientId, d.Text);
        });
        _server.ClientDisconnected += OnClientDisconnected;
        _server.ClientConnected += OnClientConnected;

        Closing += (_, _) =>
        {
            if (_streaming) SendStop();
        };
        Closed += (_, _) =>
        {
            UninstallHook();
            _closed = true;
            Interlocked.Decrement(ref _openCount);
            _reconnectTimer?.Stop();
            _server.UnregisterHandler(_clientId, PacketType.RdpFrame);
            _server.UnregisterHandler(_clientId, PacketType.RdpH264Frame);
            _server.UnregisterHandler(_clientId, PacketType.RdpClipboard);
            lock (_decodeLock) { _h264Dec?.Dispose(); _h264Dec = null; }
            _decodeSlots.Dispose();
            _server.ClientDisconnected -= OnClientDisconnected;
            _server.ClientConnected -= OnClientConnected;
            Lang.LanguageChanged -= ApplyLanguage;
        };

        TxtClientId.Text = $"[ {clientId} ]";
        TxtStatus.Text = Lang.Get("RDP_CONNECTING");
        Lang.LanguageChanged += ApplyLanguage;

        // Warn when server and client share the same machine (loopback/localhost)
        if (_server.ConnectedClients.TryGetValue(clientId, out var selfCheck))
        {
            var ip = selfCheck.IP;
            bool isLocal = ip == "127.0.0.1" || ip == "::1"
                || ip.StartsWith("127.", StringComparison.Ordinal)
                || string.Equals(ip, System.Net.Dns.GetHostName(), StringComparison.OrdinalIgnoreCase);
            if (isLocal && LocalhostWarning != null)
                LocalhostWarning.Visibility = Visibility.Visible;
        }
        ApplyLanguage();

        // Fade-in animation on open
        Opacity = 0;
        Loaded += (_, _) =>
        {
            var anim = new System.Windows.Media.Animation.DoubleAnimation(0, 1,
                TimeSpan.FromMilliseconds(180));
            BeginAnimation(OpacityProperty, anim);
            // Request monitor list on open
            _ = _server.SendToClient(_clientId,
                new Packet { Type = PacketType.RdpGetMonitors, Data = "{}" });
        };
    }

    private void ApplyLanguage()
    {
        this.Title = Lang.Get("FEAT_REMOTE_DESKTOP");
        if (TxtBtnActions != null) TxtBtnActions.Text = Lang.Get("ACT_ACTIONS");
        if (BtnStart      != null) BtnStart.Content   = Lang.Get("ACT_START");
        if (BtnStop       != null) BtnStop.Content    = Lang.Get("ACT_STOP");
    }

    private async void TxtClientId_MouseLeftButtonUp(object sender, MouseButtonEventArgs e)
    {
        Clipboard.SetText(_clientId);
        TxtClientId.Text = Lang.Get("COPIED");
        TxtClientId.Foreground = new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E));
        await Task.Delay(1500);
        if (_closed) return;
        TxtClientId.Text = _clientId;
        TxtClientId.SetResourceReference(System.Windows.Controls.TextBlock.ForegroundProperty, "TitleTextBrush");
    }

    // ── Hamburger menu ───────────────────────────────────────────────────────

    private void BtnMenu_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn)
        {
            var mainWindow = Application.Current.Windows.OfType<ServerWindow>().FirstOrDefault();
            if (mainWindow == null) return;
            var menu = FeatureContextMenu.Build(_server, _clientId, mainWindow, "RemoteDesktopWindow");
            btn.ContextMenu = menu;
            menu.PlacementTarget = btn;
            menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            menu.IsOpen = true;
        }
    }

    // ── Button state ──────────────────────────────────────────────────────────

    private void SetStreamingState(bool streaming)
    {
        _streaming = streaming;
        Dispatcher.BeginInvoke(() =>
        {
            BtnStart.IsEnabled   = !streaming;
            BtnStart.Opacity     = streaming ? 0.35 : 1.0;
            BtnStop.IsEnabled    = streaming;
            BtnStop.Opacity      = streaming ? 1.0 : 0.35;
            SldQuality.IsEnabled = !streaming;
            SldScale.IsEnabled   = !streaming;
            CmbMonitor.IsEnabled = !streaming;
            TxtStatus.Text       = streaming ? Lang.Get("STATUS_STREAMING") : Lang.Get("STOPPED");
            LiveBadge.Visibility = streaming ? Visibility.Visible : Visibility.Collapsed;
            PnlNoSession.Visibility = streaming ? Visibility.Collapsed : Visibility.Visible;
            StatusDot.Fill = new SolidColorBrush(streaming
                ? Color.FromRgb(0x22, 0xC5, 0x5E)
                : Color.FromRgb(0x25, 0x28, 0x40));
            if (!streaming)
            {
                TxtFps.Text = "";
                // Reset the bitmap so the next session always starts with a blank frame.
                // Without this, EnsureFrame re-uses the old WriteableBitmap (same dimensions)
                // and stale pixels from the previous session show as visual artifacts until
                // the first full set of blocks arrives from the client.
                _frame = null;
                ImgFrame.Source = null;
            }
        });
    }

    // ── Outgoing ──────────────────────────────────────────────────────────────

    private void SendStart()
    {
        var data = Newtonsoft.Json.JsonConvert.SerializeObject(new
        {
            Quality   = (int)SldQuality.Value,
            Fps       = 0,
            Scale     = (int)SldScale.Value,
            Monitor   = CmbMonitor.SelectedIndex >= 0 ? CmbMonitor.SelectedIndex : 0,
            Mouse     = ChkClicks.IsChecked == true || ChkCursor.IsChecked == true,
            Keyboard  = ChkKeyboard.IsChecked == true,
            Clipboard = ChkClipboard.IsChecked == true,
        });
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.RdpStart, Data = data });
        ServerWindow.ReportGlobalActivity("Remote desktop started", _clientId, "running");
        SetStreamingState(true);
    }

    private void SendStop()
    {
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.RdpStop, Data = "{}" });
        ServerWindow.ReportGlobalActivity("Remote desktop stopped", _clientId, "complete");
        SetStreamingState(false);
    }

    private void SendInputPacket(RdpInputData inp) =>
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.RdpInput,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(inp)
        });

    private void SendClipboard(string text) =>
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.RdpClipboard,
            Data = $"{{\"Text\":{Newtonsoft.Json.JsonConvert.SerializeObject(text)}}}"
        });

    // ── Incoming frames — block-based (Pulsar-style) ──────────────────────────

    private void OnFrame(string clientId, string json)
    {
        if (_closed || clientId != _clientId) return;

        if (json.Contains("\"monitors\""))
        {
            Dispatcher.BeginInvoke(() => UpdateMonitorList(json));
            return;
        }

        if (!_streaming) return;
        // If busy rendering the previous frame, return the credit so the stub keeps
        // its pipeline full — without this the 8 in-flight credits drain and the stream freezes.
        if (_renderBusy) { if (!_closed) SendAck(); return; }
        _renderBusy = true;
        _bytesReceived += json.Length;

        Task.Run(async () =>
        {
            await _decodeSlots.WaitAsync();
            try
            {
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                int w = root.GetProperty("w").GetInt32();
                int h = root.GetProperty("h").GetInt32();
                if (root.TryGetProperty("sw", out var swEl)) _screenW = swEl.GetInt32();
                if (root.TryGetProperty("sh", out var shEl)) _screenH = shEl.GetInt32();

                // Decode each changed block off the UI thread
                if (!root.TryGetProperty("blocks", out var blocksEl))
                {
                    // Full-frame fallback ("j" key)
                    if (root.TryGetProperty("j", out var jEl))
                    {
                        var jpegBytes = Convert.FromBase64String(jEl.GetString() ?? "");
                        var pixels = DecodeJpeg(jpegBytes, w, h);
                        if (pixels != null && !_closed)
                        {
                            // ACK early — mirrors block path: stub starts next capture while we blit
                            if (!_closed) SendAck();
                            _ = Dispatcher.BeginInvoke(() => BlitFullFrame(w, h, pixels, w * 4));
                        }
                        else
                        {
                            _renderBusy = false;
                            if (!_closed) SendAck();
                        }
                    }
                    else { _renderBusy = false; }
                    return;
                }

                // Block-based: decode blocks in parallel, capped at ProcessorCount
                var blockList = blocksEl.EnumerateArray().ToList();
                var decoded   = new System.Collections.Concurrent.ConcurrentBag<(int X, int Y, int W, int H, byte[] Pixels, int Stride)>();
                Parallel.ForEach(blockList,
                    new ParallelOptions { MaxDegreeOfParallelism = 2 },
                    block =>
                    {
                        try
                        {
                            int bx = block.GetProperty("x").GetInt32();
                            int by = block.GetProperty("y").GetInt32();
                            int bw = block.GetProperty("w").GetInt32();
                            int bh = block.GetProperty("h").GetInt32();
                            string j64 = block.GetProperty("j").GetString() ?? "";
                            if (string.IsNullOrEmpty(j64)) return;
                            var pix = DecodeJpeg(Convert.FromBase64String(j64), bw, bh);
                            if (pix != null) decoded.Add((bx, by, bw, bh, pix, bw * 4));
                        }
                        catch { }
                    });
                var decodedList = decoded.ToList();

                if (_closed) { _renderBusy = false; return; }
                // ACK early — stub can start capturing the next frame while we blit the current one.
                // Reduces stub idle time from (decode+blit+RTT) to (decode+RTT), cutting effective
                // latency nearly in half and allowing the pipeline to stay full at high framerates.
                if (!_closed) SendAck();
                _ = Dispatcher.BeginInvoke(() => BlitBlocks(w, h, decodedList, ackAlreadySent: true));
            }
            catch { _renderBusy = false; if (!_closed) SendAck(); }
            finally { _decodeSlots.Release(); }
        });
    }

    private static byte[]? DecodeJpeg(byte[] jpegBytes, int expectedW, int expectedH)
    {
        try
        {
            int stride  = expectedW * 4;
            var pixels  = new byte[stride * expectedH];
            var info    = new SKImageInfo(expectedW, expectedH, SKColorType.Bgra8888, SKAlphaType.Opaque);
            // Pin both arrays — wrap JPEG without copying, decode straight into pixels buffer
            var jpHandle = GCHandle.Alloc(jpegBytes, GCHandleType.Pinned);
            var pxHandle = GCHandle.Alloc(pixels,    GCHandleType.Pinned);
            try
            {
                using var skData = SKData.Create(jpHandle.AddrOfPinnedObject(), jpegBytes.Length);
                using var codec  = SKCodec.Create(skData);
                if (codec == null) return null;
                var res = codec.GetPixels(info, pxHandle.AddrOfPinnedObject());
                return res == SKCodecResult.Success ? pixels : null;
            }
            finally { jpHandle.Free(); pxHandle.Free(); }
        }
        catch { return null; }
    }

    private void BlitFullFrame(int w, int h, byte[] pixels, int stride)
    {
        try
        {
            if (_closed) { _renderBusy = false; return; }
            EnsureFrame(w, h);
            _frame!.Lock();
            try { _frame.WritePixels(new Int32Rect(0, 0, w, h), pixels, stride, 0); }
            finally { _frame.Unlock(); }
            UpdateFps();
            _renderBusy = false;
        }
        catch { _renderBusy = false; }
    }

    private void BlitBlocks(int w, int h, List<(int X, int Y, int W, int H, byte[] Pixels, int Stride)> blocks, bool ackAlreadySent = false)
    {
        try
        {
            if (blocks.Count == 0) { _renderBusy = false; if (!_closed && !ackAlreadySent) SendAck(); return; }
            if (_closed) { _renderBusy = false; return; }
            EnsureFrame(w, h);
            _frame!.Lock();
            foreach (var (bx, by, bw, bh, pix, stride) in blocks)
            {
                try { _frame.WritePixels(new Int32Rect(bx, by, bw, bh), pix, stride, 0); }
                catch { }
            }
            _frame.Unlock();
            UpdateFps();
            _renderBusy = false;
            if (!_closed && !ackAlreadySent) SendAck();
        }
        catch { _renderBusy = false; }
    }

    // ── Connection resilience — reconnect overlay + auto-resume ───────────────

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(() =>
        {
            _wasStreaming = _streaming;
            if (_streaming) SetStreamingState(false);
            _reconnectCountdown = 60;
            TxtReconnectCountdown.Text = string.Format(Lang.Get("RDP_RECONNECTING"), _reconnectCountdown);
            ReconnectOverlay.Visibility = Visibility.Visible;
            TxtStatus.Text = Lang.Get("CONN_LOST");
            ServerWindow.ReportGlobalActivity("⚡ Connection lost", _clientId, "failed");

            _reconnectTimer?.Stop();
            _reconnectTimer = new System.Windows.Threading.DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
            _reconnectTimer.Tick += (_, _) =>
            {
                _reconnectCountdown--;
                TxtReconnectCountdown.Text = string.Format(Lang.Get("RDP_RECONNECTING"), _reconnectCountdown);
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
            var oldId = _clientId;
            _clientId = c.Id;

            // Re-register per-client packet handlers on the new client ID
            _server.UnregisterHandler(oldId, PacketType.RdpFrame);
            _server.UnregisterHandler(oldId, PacketType.RdpH264Frame);
            _server.UnregisterHandler(oldId, PacketType.RdpClipboard);
            lock (_decodeLock) { _h264Dec?.Dispose(); _h264Dec = null; }
            _server.RegisterHandler(_clientId, PacketType.RdpFrame,
                pkt => OnFrame(_clientId, pkt.Data));
            _server.RegisterHandler(_clientId, PacketType.RdpH264Frame,
                pkt => OnH264Frame(_clientId, pkt.Data));
            _server.RegisterHandler(_clientId, PacketType.RdpClipboard, pkt =>
            {
                var d = Newtonsoft.Json.JsonConvert.DeserializeObject<RdpClipboardData>(pkt.Data);
                if (d?.Text is { Length: > 0 }) OnRemoteClipboard(_clientId, d.Text);
            });

            // Hide overlay, cancel timer
            _reconnectTimer?.Stop();
            ReconnectOverlay.Visibility = Visibility.Collapsed;

            // Update UI
            Title = $"{Lang.Get("FEAT_REMOTE_DESKTOP")} — {_clientId}";
            TxtClientId.Text = $"[ {_clientId} ]";
            TxtStatus.Text = Lang.Get("RECONNECTED");
            ServerWindow.ReportGlobalActivity("✓ Reconnected (RDP)", _clientId, "complete");

            // Auto-resume streaming if it was active before disconnect
            if (_wasStreaming)
            {
                _wasStreaming = false;
                _autoStarted = false; // let OnRdpMonitorList trigger auto-start with its normal delay
                _ = _server.SendToClient(_clientId,
                    new Packet { Type = PacketType.RdpGetMonitors, Data = "{}" });
            }
        });
    }

    private void EnsureFrame(int w, int h)
    {
        if (_frame != null && _frame.PixelWidth == w && _frame.PixelHeight == h) return;
        _frame = new WriteableBitmap(w, h, 96, 96, PixelFormats.Bgra32, null);
        ImgFrame.Source = _frame;
        _remoteW = w; _remoteH = h;
        TxtResolution.Text = $"{w}×{h}";
    }

    private void UpdateFps()
    {
        _frameCount++;
        var now = DateTime.UtcNow;
        if ((now - _fpsTime).TotalSeconds >= 1)
        {
            TxtFps.Text = $"{_frameCount} fps";
            _frameCount = 0; _fpsTime = now;
            UpdateMetrics();
        }
    }
    
    private volatile int _bytesReceived;
    
    private void UpdateMetrics()
    {
        double mbps = (_bytesReceived * 8.0) / 1000000.0;
        TxtBandwidth.Text = $"{mbps:F1} Mbps";
        _bytesReceived = 0;
        
        if (_server.ConnectedClients.TryGetValue(_clientId, out var client))
        {
            TxtPing.Text = $"{client.PingMs} ms";
        }
    }

    private void SendAck() =>
        _ = _server.SendToClient(_clientId,
            new Packet { Type = PacketType.RdpFrameAck, Data = "{}" });

    // ── Incoming frames — H264 ────────────────────────────────────────────────

    private void OnH264Frame(string clientId, string json)
    {
        if (_closed || clientId != _clientId) return;
        if (!_streaming) { SendAck(); return; }
        if (_renderBusy) { SendAck(); return; }
        _renderBusy = true;
        _bytesReceived += json.Length;

        try
        {
            var frame = Newtonsoft.Json.JsonConvert.DeserializeObject<H264FrameData>(json);
            if (frame == null || string.IsNullOrEmpty(frame.D)) { _renderBusy = false; SendAck(); return; }
            var h264Bytes = Convert.FromBase64String(frame.D);
            int fw = frame.W, fh = frame.H;
            Task.Run(() =>
            {
                try
                {
                    H264Decoder? localDec;
                    lock (_decodeLock)
                    {
                        if (_h264Dec == null) _h264Dec = H264Decoder.Create();
                        localDec = _h264Dec;
                    }
                    var pixels = localDec?.Decode(h264Bytes, fw, fh);
                    if (pixels == null || _closed) { _renderBusy = false; SendAck(); return; }
                    SendAck();
                    _ = Dispatcher.BeginInvoke(() => BlitFullFrame(fw, fh, pixels, fw * 4));
                }
                catch { _renderBusy = false; SendAck(); }
            });
        }
        catch { _renderBusy = false; SendAck(); }
    }

    // ── Monitor list ──────────────────────────────────────────────────────────

    private void UpdateMonitorList(string json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            var mons = doc.RootElement.GetProperty("monitors");
            _monitors.Clear();
            _updatingMonitors = true;
            CmbMonitor.Items.Clear();
            foreach (var m in mons.EnumerateArray())
            {
                int i  = m.GetProperty("i").GetInt32();
                string nm = m.GetProperty("name").GetString() ?? $"Display {i + 1}";
                int mx = m.TryGetProperty("x", out var xEl) ? xEl.GetInt32() : 0;
                int my = m.TryGetProperty("y", out var yEl) ? yEl.GetInt32() : 0;
                int mw = m.GetProperty("w").GetInt32();
                int mh = m.GetProperty("h").GetInt32();
                _monitors.Add((i, nm, mx, my, mw, mh));
                // Clean display name: strip \\.\DISPLAY prefix
                string label = nm.StartsWith("\\\\.\\") ? nm[4..] : nm;
                CmbMonitor.Items.Add($"{i + 1}: {label} ({mw}×{mh})");
            }
            if (CmbMonitor.Items.Count > 0)
                CmbMonitor.SelectedIndex = 0;

            // Auto-start on first monitor list received.
            // Stagger by window index (150ms apart) so opening 20 windows at once
            // doesn't blast 20 RdpStart packets simultaneously.
            if (!_autoStarted && CmbMonitor.Items.Count > 0)
            {
                _autoStarted = true;
                int idx = Interlocked.Increment(ref _openCount);
                int delay = 300 + (idx % 20) * 150;
                Task.Delay(delay).ContinueWith(_ => Dispatcher.BeginInvoke(SendStart));
            }
        }
        catch { }
        finally { _updatingMonitors = false; }
    }

    private void OnRemoteClipboard(string clientId, string text)
    {
        if (_closed || clientId != _clientId) return;
        Dispatcher.BeginInvoke(() => { try { Clipboard.SetText(text); } catch { } });
    }

    // ── UI events ─────────────────────────────────────────────────────────────

    private void BtnStart_Click(object s, RoutedEventArgs e) => SendStart();
    private void BtnStop_Click(object s, RoutedEventArgs e)
    {
        SendStop();
        _wasStreaming = false;  // Prevent auto-resume on reconnect if user explicitly stops
    }

    private void CmbMonitor_Changed(object s, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (!_uiReady || !_streaming || _updatingMonitors) return;
        SendStop();
        Task.Delay(200).ContinueWith(_ => Dispatcher.BeginInvoke(SendStart));
    }

    // ── Mouse ─────────────────────────────────────────────────────────────────

    // Convert a click position inside ImgFrame to remote screen coordinates.
    // Stretch=Fill means the image fills the control exactly — no letterboxing.
    private Point ToRemote(Point local)
    {
        if (_remoteW == 0 || ImgFrame.ActualWidth == 0 || ImgFrame.ActualHeight == 0) return local;

        int sw = _screenW > 0 ? _screenW : _remoteW;
        int sh = _screenH > 0 ? _screenH : _remoteH;

        double rx = local.X / ImgFrame.ActualWidth  * sw;
        double ry = local.Y / ImgFrame.ActualHeight * sh;

        int sel = CmbMonitor.SelectedIndex;
        if (sel >= 0 && sel < _monitors.Count)
        {
            rx += _monitors[sel].X;
            ry += _monitors[sel].Y;
        }
        return new Point(rx, ry);
    }

    private void Img_MouseMove(object s, MouseEventArgs e)
    {
        if (ChkCursor.IsChecked != true || !_streaming) return;
        var p = ToRemote(e.GetPosition(ImgFrame));
        SendInputPacket(new RdpInputData { T = "mm", X = (int)p.X, Y = (int)p.Y });
    }

    private void Img_MouseDown(object s, MouseButtonEventArgs e)
    {
        ImgFrame.Focus();
        if (ChkClicks.IsChecked != true || !_streaming) return;
        var p = ToRemote(e.GetPosition(ImgFrame));
        // When cursor tracking is off, the remote cursor may be anywhere.
        // Send a move first so the click lands at the correct position.
        if (ChkCursor.IsChecked != true)
            SendInputPacket(new RdpInputData { T = "mm", X = (int)p.X, Y = (int)p.Y });
        int btn = e.ChangedButton == MouseButton.Left ? 0 : e.ChangedButton == MouseButton.Right ? 1 : 2;
        SendInputPacket(new RdpInputData { T = "mc", X = (int)p.X, Y = (int)p.Y, Button = btn, Down = true });
    }

    private void Img_MouseUp(object s, MouseButtonEventArgs e)
    {
        if (ChkClicks.IsChecked != true || !_streaming) return;
        var p = ToRemote(e.GetPosition(ImgFrame));
        int btn = e.ChangedButton == MouseButton.Left ? 0 : e.ChangedButton == MouseButton.Right ? 1 : 2;
        SendInputPacket(new RdpInputData { T = "mc", X = (int)p.X, Y = (int)p.Y, Button = btn, Down = false });
    }

    private void Img_MouseWheel(object s, MouseWheelEventArgs e)
    {
        if (ChkClicks.IsChecked != true || !_streaming) return;
        SendInputPacket(new RdpInputData { T = "mw", WheelDelta = e.Delta });
    }

    // ── Keyboard ──────────────────────────────────────────────────────────────

    private void Img_KeyDown(object s, KeyEventArgs e)
    {
        e.Handled = true;
        if (ChkKeyboard.IsChecked != true || !_streaming) return;
        int vk = KeyInterop.VirtualKeyFromKey(e.Key);
        bool ext = e.Key is Key.Insert or Key.Delete or Key.Home or Key.End
                       or Key.PageUp or Key.PageDown or Key.Up or Key.Down or Key.Left or Key.Right;
        SendInputPacket(new RdpInputData { T = "kk", VK = vk, Down = true, Extended = ext });
        if (ChkClipboard.IsChecked == true && e.Key == Key.V && Keyboard.Modifiers.HasFlag(ModifierKeys.Control))
        {
            try { var t = Clipboard.GetText(); if (!string.IsNullOrEmpty(t)) SendClipboard(t); } catch { }
        }
    }

    private void Img_KeyUp(object s, KeyEventArgs e)
    {
        e.Handled = true;
        if (ChkKeyboard.IsChecked != true || !_streaming) return;
        SendInputPacket(new RdpInputData { T = "kk", VK = KeyInterop.VirtualKeyFromKey(e.Key), Down = false });
    }

    // ── Special keys: low-level keyboard hook ────────────────────────────────
    // Win, Alt+Tab, Alt+F4, Ctrl+Esc are consumed by Windows before WPF KeyDown
    // fires. A WH_KEYBOARD_LL hook (installed on Activated, removed on Deactivated)
    // is the only way to intercept and forward them to the remote.

    [DllImport("user32.dll", SetLastError = true)]
    private static extern nint SetWindowsHookEx(int idHook, LowLevelKeyboardProc lpfn, nint hMod, uint dwThreadId);
    [DllImport("user32.dll", SetLastError = true)]
    private static extern bool UnhookWindowsHookEx(nint hhk);
    [DllImport("user32.dll")]
    private static extern nint CallNextHookEx(nint hhk, int nCode, nint wParam, nint lParam);
    [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
    private static extern nint GetModuleHandle(string? lpModuleName);
    [DllImport("user32.dll")]
    private static extern short GetKeyState(int nVirtKey);

    private delegate nint LowLevelKeyboardProc(int nCode, nint wParam, nint lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct KBDLLHOOKSTRUCT { public int vkCode, scanCode, flags, time; public nint dwExtraInfo; }

    private const int WH_KEYBOARD_LL = 13;
    private const int WM_KEYDOWN     = 0x0100;
    private const int WM_KEYUP       = 0x0101;
    private const int WM_SYSKEYDOWN  = 0x0104;
    private const int WM_SYSKEYUP    = 0x0105;

    private nint _hookHandle;
    private LowLevelKeyboardProc? _hookProc; // field keeps delegate alive — GC must not collect it

    private void InstallHook()
    {
        if (_hookHandle != 0) return;
        _hookProc = HookCallback;
        // GetModuleHandle(null) returns the current executable's HINSTANCE — more reliable
        // than Process.MainModule which can return null in certain security contexts.
        var hMod = GetModuleHandle(null);
        _hookHandle = SetWindowsHookEx(WH_KEYBOARD_LL, _hookProc, hMod, 0);
    }

    private void UninstallHook()
    {
        if (_hookHandle == 0) return;
        UnhookWindowsHookEx(_hookHandle);
        _hookHandle = 0;
    }

    private nint HookCallback(int nCode, nint wParam, nint lParam)
    {
        if (nCode >= 0 && ChkKeyboard.IsChecked == true && _streaming)
        {
            var info = Marshal.PtrToStructure<KBDLLHOOKSTRUCT>(lParam);
            int  vk   = info.vkCode;
            bool down = wParam == WM_KEYDOWN    || wParam == WM_SYSKEYDOWN;
            bool sys  = wParam == WM_SYSKEYDOWN || wParam == WM_SYSKEYUP;

            if (vk is 0x5B or 0x5C) // VK_LWIN, VK_RWIN — Start menu
            {
                SendInputPacket(new RdpInputData { T = "kk", VK = vk, Down = down, Extended = true });
                return 1;
            }
            if (sys && vk == 0x09) // Alt+Tab — app switcher
            {
                SendInputPacket(new RdpInputData { T = "kk", VK = vk, Down = down });
                return 1;
            }
            if (sys && vk == 0x73) // Alt+F4 — close command
            {
                SendInputPacket(new RdpInputData { T = "kk", VK = vk, Down = down });
                return 1;
            }
            if (!sys && vk == 0x1B && (GetKeyState(0x11) & 0x8000) != 0) // Ctrl+Esc — Start menu
            {
                SendInputPacket(new RdpInputData { T = "kk", VK = vk, Down = down });
                return 1;
            }
        }
        return CallNextHookEx(_hookHandle, nCode, wParam, lParam);
    }

    private void Img_Loaded(object s, RoutedEventArgs e) => ImgFrame.Focus();
    private void Close_Click(object s, RoutedEventArgs e)  => Close();
}
