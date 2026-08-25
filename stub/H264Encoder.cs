using System.Runtime.InteropServices;

namespace SeroStub;

// Windows Media Foundation H264 encoder — NativeAOT-compatible COM vtable P/Invoke.
// Converts BGRA frames to H264 Annex-B NAL units using CLSID_CMSH264EncoderMFT.
// Returns null from Create() when MF is unavailable; callers fall back to JPEG.
internal sealed class H264Encoder : IDisposable
{
    // ── CLSIDs & IIDs ──────────────────────────────────────────────────────────

    static readonly Guid CLSID_CMSH264EncoderMFT = new("6CA50344-051A-4DED-9779-A43305165E35");
    static readonly Guid IID_IMFTransform         = new("BF94C121-5B05-4E6F-9E5F-26E6028A4BB7");

    static readonly Guid MFMediaType_Video             = new("73646976-0000-0010-8000-00AA00389B71");
    static readonly Guid MFVideoFormat_H264            = new("34363248-0000-0010-8000-00AA00389B71");
    static readonly Guid MFVideoFormat_NV12            = new("3231564E-0000-0010-8000-00AA00389B71");
    static readonly Guid MF_MT_MAJOR_TYPE              = new("48eba18e-f8c9-4687-bf11-0a74c9f96a8f");
    static readonly Guid MF_MT_SUBTYPE                 = new("f7e34c9a-42e8-4714-b74b-cb29d72c35e5");
    static readonly Guid MF_MT_AVG_BITRATE             = new("20332624-fb0d-4d9e-bd0d-cbf6786c102e");
    static readonly Guid MF_MT_INTERLACE_MODE          = new("e2724bb8-e676-4806-b4b2-a8d6efb44ccd");
    static readonly Guid MF_MT_FRAME_SIZE              = new("1652c33d-d6b2-4012-b834-72030849a37d");
    static readonly Guid MF_MT_FRAME_RATE              = new("c459a2e8-3d2c-4e44-b132-fee5156c7bb0");
    static readonly Guid MF_MT_MPEG2_PROFILE           = new("ad76a80b-2d5c-4e0b-b375-64e520137036");
    static readonly Guid MF_LOW_LATENCY                = new("9c27891a-ed7a-40e1-88e8-b22727a024ee");
    static readonly Guid MF_MT_ALL_SAMPLES_INDEPENDENT = new("c9173739-5e56-461c-b713-46fb995cb95f");

    // MFT_MESSAGE_TYPE constants
    const uint MFT_NOTIFY_BEGIN_STREAMING = 0x10000000;
    const uint MFT_NOTIFY_START_OF_STREAM = 0x10000001;
    const uint MFT_OUTPUT_STREAM_PROVIDES_SAMPLES = 0x100;
    const int  S_OK = 0;
    const int  MF_E_TRANSFORM_NEED_MORE_INPUT = unchecked((int)0xC00D6D72);

    // ── P/Invoke ───────────────────────────────────────────────────────────────

    [DllImport("ole32.dll")]
    static extern int CoCreateInstance(ref Guid rclsid, nint pUnkOuter, uint dwClsCtx,
                                       ref Guid riid, out nint ppv);
    [DllImport("mfplat.dll")] static extern int MFStartup(uint Version, uint dwFlags);
    [DllImport("mfplat.dll")] static extern int MFCreateMediaType(out nint ppMFType);
    [DllImport("mfplat.dll")] static extern int MFCreateSample(out nint ppIMFSample);
    [DllImport("mfplat.dll")] static extern int MFCreateMemoryBuffer(uint cbMaxLength, out nint ppBuffer);

    // ── Delegates ─────────────────────────────────────────────────────────────

    // IMFAttributes: SetUINT32=[21] SetUINT64=[22] SetGUID=[24]
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetUINT32_Del(nint p, ref Guid key, uint v);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetUINT64_Del(nint p, ref Guid key, ulong v);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetGUID_Del(nint p, ref Guid key, ref Guid v);

    // IMFTransform: GetOutputStreamInfo=[7] GetAttributes=[8]
    //   SetInputType=[15] SetOutputType=[16]
    //   ProcessMessage=[23] ProcessInput=[24] ProcessOutput=[25]
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int GetOutputStreamInfo_Del(nint p, uint streamId, out MftOutputStreamInfo info);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int GetAttributes_Del(nint p, out nint ppAttribs);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetInputType_Del(nint p, uint streamId, nint pType, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetOutputType_Del(nint p, uint streamId, nint pType, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int ProcessMessage_Del(nint p, uint msg, nint param);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int ProcessInput_Del(nint p, uint streamId, nint pSample, uint flags);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int ProcessOutput_Del(nint p, uint flags, uint count, ref MftOutputDataBuffer buf, out uint pdwStatus);

    // IMFSample (inherits IMFAttributes=33 entries):
    //   SetSampleTime=[36] SetSampleDuration=[38] ConvertToContiguousBuffer=[41] AddBuffer=[42]
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetSampleTime_Del(nint p, long hns);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetSampleDuration_Del(nint p, long hns);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int ConvertToContiguousBuffer_Del(nint p, out nint ppBuf);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int AddBuffer_Del(nint p, nint pBuf);

    // IMFMediaBuffer: Lock=[3] Unlock=[4] GetCurrentLength=[5] SetCurrentLength=[6]
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    unsafe delegate int Lock_Del(nint p, out byte* ppb, out uint maxLen, out uint curLen);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int Unlock_Del(nint p);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetCurrentLength_Del(nint p, uint len);

    // IUnknown: Release=[2]
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint Release_Del(nint p);

    // ── Structs ───────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    struct MftOutputStreamInfo { public uint dwFlags, cbSize, cbAlignment; }

    [StructLayout(LayoutKind.Sequential)]
    struct MftOutputDataBuffer
    {
        public uint  dwStreamID;
        public nint  pSample;  // IMFSample* (8 bytes on x64, 4-byte padding before on x64)
        public uint  dwStatus;
        public nint  pEvents;  // IMFCollection*
    }

    // ── Instance state ─────────────────────────────────────────────────────────

    nint _pTransform;
    int  _width, _height;
    long _sampleTime, _sampleDuration;
    bool _mftProvidesOutputSamples;

    H264Encoder() { }

    // Creates a new encoder for the given frame dimensions.
    // Returns null when MF or the H264 encoder MFT is unavailable.
    public static H264Encoder? Create(int width, int height, int fps, int bitrateBps = 0)
    {
        try
        {
            var enc = new H264Encoder();
            if (enc.Init(width, height, fps, bitrateBps)) return enc;
            enc.Dispose(); // release _pTransform if CoCreateInstance succeeded but Init failed later
            return null;
        }
        catch { return null; }
    }

    bool Init(int width, int height, int fps, int bitrateBps)
    {
        if (MFStartup(0x10070 /*MF_VERSION*/, 0) != S_OK) return false;

        var clsid = CLSID_CMSH264EncoderMFT;
        var iid   = IID_IMFTransform;
        if (CoCreateInstance(ref clsid, 0, 1 /*CLSCTX_INPROC_SERVER*/, ref iid, out _pTransform) != S_OK
            || _pTransform == 0)
            return false;

        _width         = width;
        _height        = height;
        _sampleDuration = fps > 0 ? 10_000_000L / fps : 333_333; // 100 ns units

        // Enable low-latency BEFORE setting media types so the MFT configures accordingly
        var getAttr = Fn<GetAttributes_Del>(_pTransform, 8);
        if (getAttr(_pTransform, out nint pAttribs) == S_OK && pAttribs != 0)
        {
            Set32(pAttribs, MF_LOW_LATENCY, 1);
            Rel(pAttribs);
        }

        // Output type: H264
        if (MFCreateMediaType(out nint pOut) != S_OK) return false;
        try
        {
            if (!SetG(pOut, MF_MT_MAJOR_TYPE, MFMediaType_Video)) return false;
            if (!SetG(pOut, MF_MT_SUBTYPE,     MFVideoFormat_H264)) return false;
            if (bitrateBps <= 0) bitrateBps = Math.Max(500_000, width * height * fps / 30 / 4);
            if (!Set32(pOut, MF_MT_AVG_BITRATE,    (uint)bitrateBps)) return false;
            if (!Set32(pOut, MF_MT_INTERLACE_MODE, 2 /*Progressive*/)) return false;
            if (!Set64(pOut, MF_MT_FRAME_SIZE, PackWH(width, height))) return false;
            if (!Set64(pOut, MF_MT_FRAME_RATE, PackWH(fps > 0 ? fps : 30, 1))) return false;
            if (!Set32(pOut, MF_MT_MPEG2_PROFILE, 66 /*Baseline — widest hw compatibility*/)) return false;
            var fn = Fn<SetOutputType_Del>(_pTransform, 16);
            if (fn(_pTransform, 0, pOut, 0) != S_OK) return false;
        }
        finally { Rel(pOut); }

        // Input type: NV12
        if (MFCreateMediaType(out nint pIn) != S_OK) return false;
        try
        {
            if (!SetG(pIn, MF_MT_MAJOR_TYPE, MFMediaType_Video)) return false;
            if (!SetG(pIn, MF_MT_SUBTYPE,    MFVideoFormat_NV12)) return false;
            if (!Set32(pIn, MF_MT_INTERLACE_MODE, 2)) return false;
            if (!Set64(pIn, MF_MT_FRAME_SIZE, PackWH(width, height))) return false;
            if (!Set64(pIn, MF_MT_FRAME_RATE, PackWH(fps > 0 ? fps : 30, 1))) return false;
            if (!Set32(pIn, MF_MT_ALL_SAMPLES_INDEPENDENT, 1)) return false;
            var fn = Fn<SetInputType_Del>(_pTransform, 15);
            if (fn(_pTransform, 0, pIn, 0) != S_OK) return false;
        }
        finally { Rel(pIn); }

        // Check if the MFT provides its own output samples
        var getInfo = Fn<GetOutputStreamInfo_Del>(_pTransform, 7);
        if (getInfo(_pTransform, 0, out var info) == S_OK)
            _mftProvidesOutputSamples = (info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) != 0;

        var msg = Fn<ProcessMessage_Del>(_pTransform, 23);
        msg(_pTransform, MFT_NOTIFY_BEGIN_STREAMING, 0);
        msg(_pTransform, MFT_NOTIFY_START_OF_STREAM, 0);
        return true;
    }

    // Encodes one BGRA frame. bgraBits points to W×H BGRA pixels with the given stride.
    // Returns Annex-B NAL bytes, or null on encoder error.
    public unsafe byte[]? Encode(nint bgraBits, int bgraStride)
    {
        if (_pTransform == 0) return null;
        int w = _width, h = _height;
        int nv12Size = w * h * 3 / 2;
        byte[] nv12 = new byte[nv12Size];

        fixed (byte* pNv12 = nv12)
            BgraToNv12((byte*)bgraBits, w, h, bgraStride, pNv12);

        // Fill MFMediaBuffer with NV12 pixels
        if (MFCreateMemoryBuffer((uint)nv12Size, out nint pBuf) != S_OK) return null;
        try
        {
            var lockFn   = Fn<Lock_Del>(pBuf, 3);
            var unlockFn = Fn<Unlock_Del>(pBuf, 4);
            var setLenFn = Fn<SetCurrentLength_Del>(pBuf, 6);
            if (lockFn(pBuf, out byte* pDst, out _, out _) != S_OK) return null;
            fixed (byte* pSrc = nv12)
                Buffer.MemoryCopy(pSrc, pDst, nv12Size, nv12Size);
            unlockFn(pBuf);
            setLenFn(pBuf, (uint)nv12Size);

            // Wrap in IMFSample
            if (MFCreateSample(out nint pSample) != S_OK) return null;
            try
            {
                Fn<AddBuffer_Del>(pSample, 42)(pSample, pBuf);
                Fn<SetSampleTime_Del>(pSample, 36)(pSample, _sampleTime);
                Fn<SetSampleDuration_Del>(pSample, 38)(pSample, _sampleDuration);
                _sampleTime += _sampleDuration;

                // Submit to encoder
                if (Fn<ProcessInput_Del>(_pTransform, 24)(_pTransform, 0, pSample, 0) != S_OK)
                    return null;
            }
            finally { Rel(pSample); }
        }
        finally { Rel(pBuf); }

        // Drain output NAL units
        var outFn = Fn<ProcessOutput_Del>(_pTransform, 25);
        var outBuf = new MftOutputDataBuffer();

        nint preallocSample = 0;
        if (!_mftProvidesOutputSamples)
        {
            MFCreateSample(out preallocSample);
            outBuf.pSample = preallocSample;
        }

        try
        {
            int hr = outFn(_pTransform, 0, 1, ref outBuf, out _);
            if (hr < 0 || outBuf.pSample == 0) return null;

            // ConvertToContiguousBuffer = vtable[41] on IMFSample
            if (Fn<ConvertToContiguousBuffer_Del>(outBuf.pSample, 41)(outBuf.pSample, out nint pOutBuf) != S_OK
                || pOutBuf == 0)
                return null;
            try
            {
                if (Fn<Lock_Del>(pOutBuf, 3)(pOutBuf, out byte* pData, out _, out uint cbLen) != S_OK)
                    return null;
                try
                {
                    if (cbLen == 0) return null;
                    var result = new byte[cbLen];
                    fixed (byte* pResult = result)
                        Buffer.MemoryCopy(pData, pResult, cbLen, cbLen);
                    return result;
                }
                finally { Fn<Unlock_Del>(pOutBuf, 4)(pOutBuf); }
            }
            finally { Rel(pOutBuf); }
        }
        finally
        {
            if (_mftProvidesOutputSamples && outBuf.pSample != 0) Rel(outBuf.pSample);
            else if (!_mftProvidesOutputSamples && preallocSample != 0) Rel(preallocSample);
            if (outBuf.pEvents != 0) Rel(outBuf.pEvents);
        }
    }

    // ── BGRA → NV12 conversion (BT.601 limited range) ────────────────────────

    static unsafe void BgraToNv12(byte* bgra, int w, int h, int bgraStride, byte* nv12)
    {
        byte* yPlane  = nv12;
        byte* uvPlane = nv12 + w * h;

        for (int y = 0; y < h; y++)
        {
            byte* srcRow = bgra + (long)y * bgraStride;
            byte* yRow   = yPlane + (long)y * w;

            for (int x = 0; x < w; x++)
            {
                int b = srcRow[x * 4];
                int g = srcRow[x * 4 + 1];
                int r = srcRow[x * 4 + 2];
                yRow[x] = (byte)(((66 * r + 129 * g + 25 * b + 128) >> 8) + 16);
            }

            if ((y & 1) == 0)
            {
                byte* uvRow = uvPlane + (long)(y >> 1) * w;
                for (int x = 0; x < w; x += 2)
                {
                    int b = srcRow[x * 4];
                    int g = srcRow[x * 4 + 1];
                    int r = srcRow[x * 4 + 2];
                    uvRow[x]     = (byte)(((-38 * r - 74 * g + 112 * b + 128) >> 8) + 128); // U
                    uvRow[x + 1] = (byte)(((112 * r - 94 * g -  18 * b + 128) >> 8) + 128); // V
                }
            }
        }
    }

    // ── Vtable helpers ─────────────────────────────────────────────────────────

    static T Fn<T>(nint comPtr, int vtblIndex) where T : Delegate
        => Marshal.GetDelegateForFunctionPointer<T>(
               Marshal.ReadIntPtr(Marshal.ReadIntPtr(comPtr), vtblIndex * nint.Size));

    static void Rel(nint ptr)
    {
        if (ptr != 0)
            Marshal.GetDelegateForFunctionPointer<Release_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(ptr), 2 * nint.Size))(ptr);
    }

    bool Set32(nint ptr, Guid key, uint v) => Fn<SetUINT32_Del>(ptr, 21)(ptr, ref key, v) == S_OK;
    bool Set64(nint ptr, Guid key, ulong v) => Fn<SetUINT64_Del>(ptr, 22)(ptr, ref key, v) == S_OK;
    bool SetG(nint ptr, Guid key, Guid val) => Fn<SetGUID_Del>(ptr, 24)(ptr, ref key, ref val) == S_OK;

    static ulong PackWH(int w, int h) => ((ulong)(uint)w << 32) | (uint)h;

    // ── IDisposable ────────────────────────────────────────────────────────────

    bool _disposed;
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_pTransform != 0) { Rel(_pTransform); _pTransform = 0; }
    }
}
