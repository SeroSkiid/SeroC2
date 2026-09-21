using System.Windows;
using DevExpress.Xpf.Core;
using NAudio.Wave;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class SpeakToClientWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;

    private WaveInEvent? _waveIn;
    private volatile bool _speaking;
    private long _bytesSent;

    public SpeakToClientWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;

        _server.ClientDisconnected += OnClientDisconnected;

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        PopulateMicDevices();

        Closed += (_, _) =>
        {
            _server.ClientDisconnected -= OnClientDisconnected;
            if (_speaking) StopInternal();
            Lang.LanguageChanged -= ApplyLanguage;
        };
    }

    private void ApplyLanguage()
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(ApplyLanguage); return; }
        Title = Lang.Get("FEAT_SPEAK_TO_CLIENT");
        if (TxtLblDevice  != null) TxtLblDevice.Text     = Lang.Get("SPK_INJECT_DEVICE");
        if (BtnSpeakStart != null) BtnSpeakStart.Content = Lang.Get("SPK_INJECT_START");
        if (BtnSpeakStop  != null) BtnSpeakStop.Content  = Lang.Get("ACT_STOP");
    }

    private void PopulateMicDevices()
    {
        CmbMicDevice.Items.Clear();
        for (int i = 0; i < WaveIn.DeviceCount; i++)
        {
            var caps = WaveIn.GetCapabilities(i);
            CmbMicDevice.Items.Add(new SpeakerMicItem(i, caps.ProductName));
        }
        if (CmbMicDevice.Items.Count > 0) CmbMicDevice.SelectedIndex = 0;
    }

    private async void SpeakStart_Click(object s, RoutedEventArgs e)
    {
        if (_speaking) return;
        if (CmbMicDevice.SelectedItem is not SpeakerMicItem mic) { TxtStatus.Text = Lang.Get("NO_INPUT_DEVICE"); return; }

        const int SampleRate    = 44100;
        const int Channels      = 1;
        const int BitsPerSample = 16;

        _bytesSent = 0;
        _speaking  = true;
        BtnSpeakStart.IsEnabled = false;
        BtnSpeakStop.IsEnabled  = true;

        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.SpeakerInjectStart,
            Data = JsonConvert.SerializeObject(new SpeakerInjectStartData
                { SampleRate = SampleRate, Channels = Channels, BitsPerSample = BitsPerSample })
        });

        _waveIn = new WaveInEvent
        {
            DeviceNumber       = mic.Index,
            WaveFormat         = new WaveFormat(SampleRate, BitsPerSample, Channels),
            BufferMilliseconds = 80,
        };
        _waveIn.DataAvailable    += OnMicData;
        _waveIn.RecordingStopped += (_, _) => { };
        _waveIn.StartRecording();

        TxtStatus.Text = string.Format(Lang.Get("SPK_INJECTING"), 0);
    }

    private void SpeakStop_Click(object s, RoutedEventArgs e)
    {
        if (!_speaking) return;
        StopInternal();
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.SpeakerInjectStop });
        TxtStatus.Text = Lang.Get("SPK_INJECT_STOPPED");
    }

    private async void OnMicData(object? sender, WaveInEventArgs args)
    {
        if (!_speaking || args.BytesRecorded == 0) return;
        _bytesSent += args.BytesRecorded;

        var chunk = new byte[args.BytesRecorded];
        Array.Copy(args.Buffer, chunk, args.BytesRecorded);

        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.SpeakerInjectData,
            Data = JsonConvert.SerializeObject(new SpeakerDataPacket { Data = Convert.ToBase64String(chunk) })
        });

        long kb = _bytesSent / 1024;
        await Dispatcher.BeginInvoke(() =>
        {
            if (_speaking)
                TxtStatus.Text = string.Format(Lang.Get("SPK_INJECTING"), kb);
        });
    }

    private void StopInternal()
    {
        _speaking = false;
        Dispatcher.BeginInvoke(() =>
        {
            BtnSpeakStart.IsEnabled = true;
            BtnSpeakStop.IsEnabled  = false;
        });
        if (_waveIn != null)
        {
            _waveIn.DataAvailable -= OnMicData;
            try { _waveIn.StopRecording(); } catch { }
            _waveIn.Dispose();
            _waveIn = null;
        }
    }

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(async () =>
        {
            if (_speaking)
            {
                StopInternal();
                await _server.SendToClient(_clientId, new Packet { Type = PacketType.SpeakerInjectStop });
            }
            TxtStatus.Text = Lang.Get("PM_DISCONNECTED");
        });
    }
}

public record SpeakerMicItem(int Index, string Name)
{
    public override string ToString() => Name;
}
