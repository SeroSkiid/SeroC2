using System.Collections.Generic;
using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Threading;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class SpeakerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;

    // ── Loopback state ──────────────────────────────────────
    private volatile bool _listening;
    private volatile WaveOutPlayer? _player;
    private readonly List<byte[]> _chunks = [];
    private long _chunkBytes;
    private const long MaxChunkBytes = 256L * 1024 * 1024; // 256MB rolling cap
    private (int SampleRate, int Channels, int BitsPerSample) _captureFmt = (44100, 2, 32);

    private readonly DispatcherTimer _recTimer  = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly DispatcherTimer _waveTimer = new() { Interval = TimeSpan.FromMilliseconds(50) };
    private int     _recSeconds;
    private float[] _waveform = new float[100];
    private volatile int _wavePos;
    private long    _lastStatusMs;

    private static readonly SolidColorBrush _waveAccent;
    static SpeakerWindow()
    {
        _waveAccent = new SolidColorBrush(Color.FromArgb(0xCC, 0x3B, 0x82, 0xF6));
        _waveAccent.Freeze();
    }

    public SpeakerWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;

        _server.RegisterHandler(clientId, PacketType.SpeakerDevicesResult, OnDevices);
        _server.RegisterHandler(clientId, PacketType.SpeakerData,          OnAudioChunk);
        _server.ClientDisconnected += OnClientDisconnected;

        _recTimer.Tick  += (_, _) => { _recSeconds++; TxtRecTime.Text = $"{_recSeconds / 60}:{_recSeconds % 60:D2}"; };
        _waveTimer.Tick += (_, _) => DrawWaveform();

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();

        Closed += (_, _) =>
        {
            _recTimer.Stop(); _waveTimer.Stop();
            _server.UnregisterHandler(clientId, PacketType.SpeakerDevicesResult);
            _server.UnregisterHandler(clientId, PacketType.SpeakerData);
            _server.ClientDisconnected -= OnClientDisconnected;
            if (_listening) SendStop();
            _player?.Dispose();
            _player = null;
            Lang.LanguageChanged -= ApplyLanguage;
        };

        Loaded += async (_, _) =>
        {
            await Task.Delay(System.Random.Shared.Next(0, 200));
            try { await _server.SendToClient(_clientId, new Packet { Type = PacketType.SpeakerGetDevices }); } catch { }
        };
    }

    private void ApplyLanguage()
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(ApplyLanguage); return; }
        Title = Lang.Get("FEAT_SPEAKER");
        if (TxtLblDevice != null) TxtLblDevice.Text = Lang.Get("SPK_DEVICE");
        if (TxtIdleHint  != null) TxtIdleHint.Text  = Lang.Get("SPK_IDLE_HINT");
        if (BtnListen    != null) BtnListen.Content  = Lang.Get("SPK_LISTEN");
        if (BtnStop      != null) BtnStop.Content    = Lang.Get("ACT_STOP");
        if (BtnSave      != null) BtnSave.Content    = Lang.Get("SPK_SAVE_WAV");
    }

    // ── Loopback ────────────────────────────────────────────

    private void OnDevices(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<SpeakerDevicesResult>(pkt.Data);
        if (data == null) return;
        Dispatcher.BeginInvoke(() =>
        {
            CmbDevice.Items.Clear();
            foreach (var d in data.Devices)
                CmbDevice.Items.Add(new SpeakerDeviceItem(d.Index, d.Name, d.SampleRate, d.Channels, d.BitsPerSample));
            if (CmbDevice.Items.Count > 0) CmbDevice.SelectedIndex = 0;
        });
    }

    private void OnAudioChunk(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<SpeakerDataPacket>(pkt.Data);
        if (data == null || string.IsNullOrEmpty(data.Data)) return;
        var raw = Convert.FromBase64String(data.Data);
        lock (_chunks)
        {
            _chunks.Add(raw);
            _chunkBytes += raw.Length;
            while (_chunkBytes > MaxChunkBytes && _chunks.Count > 1)
            {
                _chunkBytes -= _chunks[0].Length;
                _chunks.RemoveAt(0);
            }
        }
        try { _player?.Enqueue(raw); } catch { }

        float peak = 0;
        if (_captureFmt.BitsPerSample == 32)
        {
            for (int i = 0; i + 3 < raw.Length; i += 4)
                peak = Math.Max(peak, Math.Abs(BitConverter.ToSingle(raw, i)));
        }
        else // PCM-16
        {
            for (int i = 0; i + 1 < raw.Length; i += 2)
                peak = Math.Max(peak, Math.Abs(BitConverter.ToInt16(raw, i)) / 32768f);
        }
        lock (_waveform) { _waveform[_wavePos % _waveform.Length] = Math.Min(peak, 1f); _wavePos++; }

        long nowMs = Environment.TickCount64;
        if (nowMs - _lastStatusMs >= 500)
        {
            _lastStatusMs = nowMs;
            int count; lock (_chunks) count = _chunks.Count;
            Dispatcher.BeginInvoke(() => TxtStatus.Text = string.Format(Lang.Get("SPK_LISTENING"), count));
        }
    }

    private async void Listen_Click(object s, RoutedEventArgs e)
    {
        if (_listening) return;
        if (CmbDevice.SelectedItem is not SpeakerDeviceItem dev) { TxtStatus.Text = Lang.Get("NO_DEVICE_SELECTED"); return; }

        _listening  = true;
        _captureFmt = (dev.SampleRate, dev.Channels, dev.BitsPerSample);
        lock (_chunks) { _chunks.Clear(); _chunkBytes = 0; }
        _recSeconds = 0; _wavePos = 0;
        Array.Clear(_waveform);
        _player?.Dispose();
        _player = new WaveOutPlayer(_captureFmt.SampleRate, _captureFmt.Channels, _captureFmt.BitsPerSample);
        PnlIdle.Visibility           = Visibility.Collapsed;
        ListeningIndicator.Visibility = Visibility.Visible;
        BtnListen.IsEnabled = false;
        BtnStop.IsEnabled   = true;
        _recTimer.Start();
        _waveTimer.Start();

        try
        {
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.SpeakerStart,
                Data = JsonConvert.SerializeObject(new SpeakerStartData { DeviceIndex = dev.Index })
            });
        }
        catch
        {
            _listening = false;
            _recTimer.Stop(); _waveTimer.Stop();
            _player?.Dispose(); _player = null;
            ListeningIndicator.Visibility = Visibility.Collapsed;
            BtnListen.IsEnabled = true; BtnStop.IsEnabled = false;
            TxtStatus.Text = Lang.Get("PM_DISCONNECTED");
        }
    }

    private void Stop_Click(object s, RoutedEventArgs e)
    {
        if (!_listening) return;
        _listening = false;
        _recTimer.Stop(); _waveTimer.Stop();
        SendStop();
        _player?.Dispose();
        _player = null;
        ListeningIndicator.Visibility = Visibility.Collapsed;
        BtnListen.IsEnabled = true;
        BtnStop.IsEnabled   = false;
        int total = 0; lock (_chunks) total = _chunks.Sum(c => c.Length);
        double secs = total / (double)(_captureFmt.SampleRate * _captureFmt.Channels * (_captureFmt.BitsPerSample / 8));
        TxtStatus.Text = string.Format(Lang.Get("MIC_STOPPED"), secs.ToString("F1"), _chunks.Count);
    }

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(() =>
        {
            if (_listening)
            {
                _listening = false; _recTimer.Stop(); _waveTimer.Stop();
                _player?.Dispose(); _player = null;
                ListeningIndicator.Visibility = Visibility.Collapsed;
                BtnListen.IsEnabled = true; BtnStop.IsEnabled = false;
            }
            TxtStatus.Text = Lang.Get("PM_DISCONNECTED");
        });
    }

    private void SendStop() => _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.SpeakerStop });

    private async void SaveWav_Click(object s, RoutedEventArgs e)
    {
        List<byte[]> data; lock (_chunks) data = [.. _chunks];
        if (data.Count == 0) { MessageBox.Show(Lang.Get("SPK_NOTHING"), "Sero"); return; }

        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter   = "WAV Audio (*.wav)|*.wav",
            FileName = $"speaker_{DateTime.Now:yyyyMMdd_HHmmss}.wav"
        };
        if (dlg.ShowDialog() != true) return;
        var fileName = dlg.FileName;

        // Use the actual capture format (fixed when listening started)
        var fmt      = _captureFmt;
        int dataSize = data.Sum(d => d.Length);
        int byteRate = fmt.SampleRate * fmt.Channels * (fmt.BitsPerSample / 8);
        // IEEE_FLOAT (3) when 32-bit, PCM (1) when 16-bit
        short formatTag = (short)(fmt.BitsPerSample == 32 ? 3 : 1);
        // IEEE_FLOAT fmt chunk requires 18 bytes (extra 2-byte cbSize field); PCM is 16
        int fmtSize = fmt.BitsPerSample == 32 ? 18 : 16;

        try
        {
            await Task.Run(() =>
            {
                using var fs = File.Create(fileName);
                using var bw = new BinaryWriter(fs);
                bw.Write(System.Text.Encoding.ASCII.GetBytes("RIFF"));
                bw.Write(4 + 8 + fmtSize + 8 + dataSize); // correct RIFF chunk size
                bw.Write(System.Text.Encoding.ASCII.GetBytes("WAVE"));
                bw.Write(System.Text.Encoding.ASCII.GetBytes("fmt "));
                bw.Write(fmtSize);
                bw.Write(formatTag);
                bw.Write((short)fmt.Channels);
                bw.Write(fmt.SampleRate);
                bw.Write(byteRate);
                bw.Write((short)(fmt.Channels * fmt.BitsPerSample / 8));
                bw.Write((short)fmt.BitsPerSample);
                if (fmtSize == 18) bw.Write((short)0); // cbSize = 0 for IEEE_FLOAT
                bw.Write(System.Text.Encoding.ASCII.GetBytes("data"));
                bw.Write(dataSize);
                foreach (var chunk in data) bw.Write(chunk);
            });
        }
        catch (Exception ex) { MessageBox.Show(ex.Message, "Sero", MessageBoxButton.OK, MessageBoxImage.Error); return; }

        TxtStatus.Text = string.Format(Lang.Get("SAVED"), fileName);
    }

    // ── Waveform renderer ───────────────────────────────────

    private void DrawWaveform()
    {
        double w = WaveCanvas.ActualWidth, h = WaveCanvas.ActualHeight;
        if (w < 2 || h < 2) return;
        int bars = (int)(w / 6);
        double barW = w / bars;
        float[] snap; lock (_waveform) snap = [.. _waveform];

        while (WaveCanvas.Children.Count > bars) WaveCanvas.Children.RemoveAt(WaveCanvas.Children.Count - 1);
        while (WaveCanvas.Children.Count < bars)
        {
            var r = new System.Windows.Shapes.Rectangle { Fill = _waveAccent, RadiusX = 1, RadiusY = 1 };
            WaveCanvas.Children.Add(r);
        }
        double rectW = Math.Max(1, barW - 2);
        for (int i = 0; i < bars; i++)
        {
            int dataIdx = (_wavePos - bars + i + snap.Length) % snap.Length;
            double barH = Math.Max(3, snap[dataIdx] * h * 0.9);
            var rect = (System.Windows.Shapes.Rectangle)WaveCanvas.Children[i];
            rect.Width  = rectW; rect.Height = barH;
            System.Windows.Controls.Canvas.SetLeft(rect, i * barW);
            System.Windows.Controls.Canvas.SetTop(rect, (h - barH) / 2);
        }
    }
}

public record SpeakerDeviceItem(int Index, string Name, int SampleRate, int Channels, int BitsPerSample)
{
    public override string ToString() => Name;
}

