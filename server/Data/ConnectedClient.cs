using System.ComponentModel;
using System.Net.Security;
using System.Runtime.CompilerServices;

namespace SeroServer.Data;

public class ConnectedClient : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? p = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));

    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
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
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime ConnectedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastHeartbeat { get; set; } = DateTime.UtcNow;
    public DateTime PingSentAt { get; set; }
    public SslStream? Stream { get; set; }
    public SemaphoreSlim WriteLock { get; } = new(1, 1);
    public CancellationTokenSource Cts { get; set; } = new();
    public bool PendingUninstall { get; set; }
    public bool IsAlive => (DateTime.UtcNow - LastHeartbeat).TotalSeconds < 30;

    private string _os = string.Empty;
    public string OS { get => _os; set { if (_os != value) { _os = value; Notify(); } } }

    private bool _isAdmin;
    public bool IsAdmin { get => _isAdmin; set { if (_isAdmin != value) { _isAdmin = value; Notify(); Notify(nameof(Privilege)); } } }
    public string Privilege => _isAdmin ? "Admin" : "User";

    private string _tag = string.Empty;
    public string Tag { get => _tag; set { if (_tag != value) { _tag = value; Notify(); } } }

    private int _pingMs = -1;
    public int PingMs
    {
        get => _pingMs;
        set { if (_pingMs != value) { _pingMs = value; Notify(); Notify(nameof(PingDisplay)); } }
    }
    public string PingDisplay => _pingMs < 0 ? "..." : $"{_pingMs} ms";
}
