using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
// using System.Windows.Shapes — Rectangle referenced with full name below
using System.Windows.Threading;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

// ── Real-time WaveOut audio player (P/Invoke, no external deps) ───────────────
// Uses CALLBACK_EVENT + WaitForSingleObject instead of Thread.Sleep polling
// so multiple simultaneous instances don't compete for CPU timer slots.
// 3-slot ring buffer keeps 2 buffers always queued → eliminates inter-chunk gaps.
internal sealed class WaveOutPlayer : IDisposable
{
    [StructLayout(LayoutKind.Sequential)]
    private struct WAVEFORMATEX
    {
        public ushort wFormatTag, nChannels;
        public uint nSamplesPerSec, nAvgBytesPerSec;
        public ushort nBlockAlign, wBitsPerSample, cbSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WAVEHDR
    {
        public IntPtr lpData;
        public int dwBufferLength, dwBytesRecorded;
        public IntPtr dwUser;
        public int dwFlags, dwLoops;
        public IntPtr lpNext, reserved;
    }

    [DllImport("winmm.dll")] static extern int waveOutOpen(out IntPtr h, uint dev, ref WAVEFORMATEX fmt, IntPtr cb, IntPtr inst, uint flags);
    [DllImport("winmm.dll")] static extern int waveOutClose(IntPtr h);
    [DllImport("winmm.dll")] static extern int waveOutReset(IntPtr h);
    [DllImport("winmm.dll")] static extern int waveOutWrite(IntPtr h, IntPtr hdr, int sz);
    [DllImport("winmm.dll")] static extern int waveOutPrepareHeader(IntPtr h, IntPtr hdr, int sz);
    [DllImport("winmm.dll")] static extern int waveOutUnprepareHeader(IntPtr h, IntPtr hdr, int sz);
    [DllImport("kernel32.dll")] static extern IntPtr CreateEvent(IntPtr a, bool manual, bool init, IntPtr name);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr h, uint ms);

    private const uint WAVE_MAPPER    = 0xFFFFFFFF;
    private const uint CALLBACK_EVENT = 0x00050000;
    private const int  WHDR_DONE      = 0x00000001;
    private const int  SLOTS          = 3;

    private readonly IntPtr _hwo;
    private readonly IntPtr _hEvent;
    private readonly bool   _open;
    private readonly BlockingCollection<byte[]> _queue = new(64);
    private readonly Thread _thread;
    private volatile bool   _running;

    public WaveOutPlayer(int sampleRate)
    {
        _hEvent = CreateEvent(IntPtr.Zero, false, false, IntPtr.Zero); // auto-reset
        var fmt = new WAVEFORMATEX
        {
            wFormatTag      = 1,
            nChannels       = 1,
            nSamplesPerSec  = (uint)sampleRate,
            nAvgBytesPerSec = (uint)(sampleRate * 2),
            nBlockAlign     = 2,
            wBitsPerSample  = 16,
        };
        _open    = _hEvent != IntPtr.Zero
                && waveOutOpen(out _hwo, WAVE_MAPPER, ref fmt, _hEvent, IntPtr.Zero, CALLBACK_EVENT) == 0;
        _running = _open;
        _thread  = new Thread(Loop) { IsBackground = true, Priority = ThreadPriority.AboveNormal };
        if (_open) _thread.Start();
    }

    public void Enqueue(byte[] pcm)
    {
        if (!_open || _queue.IsAddingCompleted) return;
        if (!_queue.TryAdd(pcm, 0))
        {
            _queue.TryTake(out _);
            _queue.TryAdd(pcm, 0);
        }
    }

    private void Loop()
    {
        int hdrSz   = Marshal.SizeOf<WAVEHDR>();
        int initCap = 4096;

        var dataPtrs  = new IntPtr[SLOTS];
        var hdrPtrs   = new IntPtr[SLOTS];
        var caps      = new int[SLOTS];
        var submitted = new bool[SLOTS];

        for (int i = 0; i < SLOTS; i++)
        {
            dataPtrs[i] = Marshal.AllocHGlobal(initCap);
            hdrPtrs[i]  = Marshal.AllocHGlobal(hdrSz);
            caps[i]     = initCap;
            for (int b = 0; b < hdrSz; b++) Marshal.WriteByte(hdrPtrs[i], b, 0);
        }

        try
        {
            while (_running)
            {
                bool anyProgress = false;

                for (int i = 0; i < SLOTS; i++)
                {
                    // Release completed slot
                    if (submitted[i])
                    {
                        var h = Marshal.PtrToStructure<WAVEHDR>(hdrPtrs[i]);
                        if ((h.dwFlags & WHDR_DONE) == 0) continue;
                        waveOutUnprepareHeader(_hwo, hdrPtrs[i], hdrSz);
                        submitted[i] = false;
                    }

                    // Fill free slot from queue
                    if (!_queue.TryTake(out var pcm) || pcm == null) continue;

                    if (pcm.Length > caps[i])
                    {
                        Marshal.FreeHGlobal(dataPtrs[i]);
                        dataPtrs[i] = Marshal.AllocHGlobal(pcm.Length);
                        caps[i]     = pcm.Length;
                    }

                    Marshal.Copy(pcm, 0, dataPtrs[i], pcm.Length);
                    for (int b = 0; b < hdrSz; b++) Marshal.WriteByte(hdrPtrs[i], b, 0);
                    Marshal.StructureToPtr(new WAVEHDR { lpData = dataPtrs[i], dwBufferLength = pcm.Length }, hdrPtrs[i], false);
                    waveOutPrepareHeader(_hwo, hdrPtrs[i], hdrSz);
                    waveOutWrite(_hwo, hdrPtrs[i], hdrSz);
                    submitted[i] = true;
                    anyProgress  = true;
                }

                if (!anyProgress)
                    WaitForSingleObject(_hEvent, 12); // block until a buffer completes or 12ms timeout
            }
        }
        finally
        {
            waveOutReset(_hwo);
            for (int i = 0; i < SLOTS; i++)
            {
                if (submitted[i])
                {
                    var h = Marshal.PtrToStructure<WAVEHDR>(hdrPtrs[i]);
                    if ((h.dwFlags & WHDR_DONE) != 0)
                        waveOutUnprepareHeader(_hwo, hdrPtrs[i], hdrSz);
                }
                Marshal.FreeHGlobal(hdrPtrs[i]);
                Marshal.FreeHGlobal(dataPtrs[i]);
            }
        }
    }

    public void Dispose()
    {
        _running = false;
        _queue.CompleteAdding();
        _thread.Join(2000);
        if (_open) { waveOutReset(_hwo); waveOutClose(_hwo); }
        if (_hEvent != IntPtr.Zero) CloseHandle(_hEvent);
    }
}

public partial class MicrophoneWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;

    private bool _recording;
    private volatile WaveOutPlayer? _player;
    private readonly List<byte[]> _chunks = [];
    private const int SampleRate = 16000;
    private const int Channels   = 1;
    private const int BitsPerSample = 16;

    private readonly DispatcherTimer _recTimer  = new() { Interval = TimeSpan.FromSeconds(1) };
    private readonly DispatcherTimer _waveTimer = new() { Interval = TimeSpan.FromMilliseconds(50) };
    private int     _recSeconds;
    private float[] _waveform = new float[100];
    private int     _wavePos;

    private static readonly SolidColorBrush _waveAccent = MakeWaveBrush();
    private static SolidColorBrush MakeWaveBrush()
    {
        var b = new SolidColorBrush(Color.FromArgb(0xCC, 0xEF, 0x44, 0x44));
        b.Freeze();
        return b;
    }

    public MicrophoneWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;

        _server.RegisterHandler(clientId, PacketType.MicDevicesResult, OnDevices);
        _server.RegisterHandler(clientId, PacketType.MicData,          OnAudioChunk);

        _recTimer.Tick  += (_, _) => { _recSeconds++; TxtRecTime.Text = $"{_recSeconds / 60}:{_recSeconds % 60:D2}"; };
        _waveTimer.Tick += (_, _) => DrawWaveform();

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.MicDevicesResult);
            _server.UnregisterHandler(clientId, PacketType.MicData);
            if (_recording) SendStop();
            _player?.Dispose();
            _player = null;
            Lang.LanguageChanged -= ApplyLanguage;
        };
        Loaded += async (_, _) => { await Task.Delay(Random.Shared.Next(0, 250)); await _server.SendToClient(_clientId, new Packet { Type = PacketType.MicGetDevices }); };
    }

    private void ApplyLanguage()
    {
        this.Title = Lang.Get("FEAT_MICROPHONE");
        if (BtnRecord != null) BtnRecord.Content = Lang.Get("ACT_START");
        if (BtnStop   != null) BtnStop.Content   = Lang.Get("ACT_STOP");
    }

    private void OnDevices(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<MicDevicesResultData>(pkt.Data);
        if (data == null) return;
        Dispatcher.BeginInvoke(() =>
        {
            CmbDevice.Items.Clear();
            foreach (var d in data.Devices)
                CmbDevice.Items.Add(new MicDeviceItem(d.Index, d.Name));
            if (CmbDevice.Items.Count > 0) CmbDevice.SelectedIndex = 0;
            TxtStatus.Text = $"{data.Devices.Count} device(s) found";
        });
    }

    private void OnAudioChunk(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<MicDataPacket>(pkt.Data);
        if (data == null || string.IsNullOrEmpty(data.Data)) return;
        var pcm = Convert.FromBase64String(data.Data);
        lock (_chunks) _chunks.Add(pcm);

        // Update waveform peak — compute on network thread, store in array
        var shorts = new short[pcm.Length / 2];
        Buffer.BlockCopy(pcm, 0, shorts, 0, pcm.Length);
        float peak = 0;
        foreach (var s in shorts)
            peak = Math.Max(peak, Math.Abs(s / 32768f));
        lock (_waveform) _waveform[_wavePos % _waveform.Length] = peak;
        _wavePos++;

        // Capture to local — _player can be set null on UI thread at any moment
        _player?.Enqueue(pcm);

        // BeginInvoke (fire-and-forget) — never block the network receive thread
        int count; lock (_chunks) count = _chunks.Count;
        Dispatcher.BeginInvoke(() => TxtStatus.Text = $"Recording… {count} chunks received");
    }

    private async void Record_Click(object s, RoutedEventArgs e)
    {
        if (_recording) return;
        if (CmbDevice.SelectedItem is not MicDeviceItem dev) { TxtStatus.Text = Lang.Get("NO_DEVICE_SELECTED"); return; }

        _recording = true;
        _chunks.Clear();
        _recSeconds = 0;
        _wavePos = 0;
        Array.Clear(_waveform);

        // Auto-start playback when recording begins
        _player?.Dispose();
        _player = new WaveOutPlayer(SampleRate);

        PnlIdle.Visibility = Visibility.Collapsed;
        RecordingIndicator.Visibility = Visibility.Visible;
        BtnRecord.IsEnabled = false;
        BtnStop.IsEnabled   = true;
        _recTimer.Start();
        _waveTimer.Start();

        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.MicStart,
            Data = JsonConvert.SerializeObject(new MicStartData { DeviceIndex = dev.Index, SampleRate = SampleRate })
        });
    }

    private async void Stop_Click(object s, RoutedEventArgs e)
    {
        if (!_recording) return;
        _recording = false;
        _recTimer.Stop();
        _waveTimer.Stop();
        _player?.Dispose(); _player = null;
        SendStop();
        RecordingIndicator.Visibility = Visibility.Collapsed;
        BtnRecord.IsEnabled = true;
        BtnStop.IsEnabled   = false;
        int total = 0; lock (_chunks) total = _chunks.Sum(c => c.Length);
        TxtStatus.Text = $"Stopped — {total / (SampleRate * Channels * 2.0):F1}s recorded  ({_chunks.Count} chunks)";
        await Task.CompletedTask;
    }

    private async void SendStop()
    {
        await _server.SendToClient(_clientId, new Packet { Type = PacketType.MicStop });
    }

    private void SaveWav_Click(object s, RoutedEventArgs e)
    {
        List<byte[]> data;
        lock (_chunks) data = [.. _chunks];
        if (data.Count == 0) { MessageBox.Show(Lang.Get("MIC_NOTHING_RECORDED"), "Sero"); return; }

        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "WAV Audio (*.wav)|*.wav",
            FileName = $"mic_{DateTime.Now:yyyyMMdd_HHmmss}.wav"
        };
        if (dlg.ShowDialog() != true) return;

        using var fs = File.OpenWrite(dlg.FileName);
        using var bw = new BinaryWriter(fs);
        int dataSize = data.Sum(d => d.Length);
        int byteRate = SampleRate * Channels * (BitsPerSample / 8);
        // WAV header
        bw.Write(System.Text.Encoding.ASCII.GetBytes("RIFF"));
        bw.Write(36 + dataSize);
        bw.Write(System.Text.Encoding.ASCII.GetBytes("WAVE"));
        bw.Write(System.Text.Encoding.ASCII.GetBytes("fmt "));
        bw.Write(16);               // subchunk1 size
        bw.Write((short)1);         // PCM
        bw.Write((short)Channels);
        bw.Write(SampleRate);
        bw.Write(byteRate);
        bw.Write((short)(Channels * BitsPerSample / 8));
        bw.Write((short)BitsPerSample);
        bw.Write(System.Text.Encoding.ASCII.GetBytes("data"));
        bw.Write(dataSize);
        foreach (var chunk in data) bw.Write(chunk);

        TxtStatus.Text = $"Saved: {dlg.FileName}";
        MessageBox.Show($"WAV saved:\n{dlg.FileName}\n\nDuration: {dataSize / (double)byteRate:F1}s",
            "Sero — Microphone", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private void DrawWaveform()
    {
        double w = WaveCanvas.ActualWidth, h = WaveCanvas.ActualHeight;
        if (w < 2 || h < 2) return;

        int bars = (int)(w / 6);
        double barW = w / bars;

        float[] snap; lock (_waveform) snap = [.. _waveform];

        // Reuse existing Rectangle children; only add/remove when bar count changes
        while (WaveCanvas.Children.Count > bars)
            WaveCanvas.Children.RemoveAt(WaveCanvas.Children.Count - 1);
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
            rect.Width  = rectW;
            rect.Height = barH;
            System.Windows.Controls.Canvas.SetLeft(rect, i * barW);
            System.Windows.Controls.Canvas.SetTop(rect, (h - barH) / 2);
        }
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void BtnMenu_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button btn) return;
        var mainWindow = System.Windows.Application.Current.Windows.OfType<ServerWindow>().FirstOrDefault();
        if (mainWindow == null) return;
        var menu = FeatureContextMenu.Build(_server, _clientId, mainWindow, "MicrophoneWindow");
        btn.ContextMenu = menu;
        menu.PlacementTarget = btn;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.IsOpen = true;
    }
}

public record MicDeviceItem(int Index, string Name)
{
    public override string ToString() => Name;
}
