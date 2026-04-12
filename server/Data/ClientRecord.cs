namespace SeroServer.Data;

/// <summary>
/// Persistent record for every client HWID ever seen.
/// Survives server restarts. Stored in clients.json.
/// </summary>
public class ClientRecord
{
    public string Hwid { get; set; } = string.Empty;
    public string LastUsername { get; set; } = string.Empty;
    public string LastIP { get; set; } = string.Empty;
    public string LastCountry { get; set; } = string.Empty;
    public string LastMachineName { get; set; } = string.Empty;
    public string LastOS { get; set; } = string.Empty;
    public bool LastIsAdmin { get; set; }
    public string Tag { get; set; } = string.Empty;
    public DateTime FirstSeen { get; set; } = DateTime.UtcNow;
    public DateTime LastSeen { get; set; } = DateTime.UtcNow;
    public List<ActivityEntry> ActivityLog { get; set; } = [];
}

public class ActivityEntry
{
    public DateTime Time { get; set; } = DateTime.UtcNow;
    public string Action { get; set; } = string.Empty;
}
