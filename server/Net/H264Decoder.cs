using System.Runtime.InteropServices;

namespace SeroServer.Net;

// Windows Media Foundation H264 decoder — COM vtable P/Invoke, no unsafe required.
// Decodes Annex-B H264 NAL units to BGRA pixels using CLSID_CMSH264DecoderMFT.
// Returns null from Create() when MF is unavailable; caller falls back to JPEG.
internal sealed class H264Decoder : IDisposable
{
    // ── CLSIDs / IIDs ─────────────────────────────────────────────────────────

    static readonly Guid CLSID_CMSH264DecoderMFT = new("62CE7E72-4C71-4D20-B15D-452831A87D9D");
    static readonly Guid IID_IMFTransform         = new("BF94C121-5B05-4E6F-9E5F-26E6028A4BB7");

    static readonly Guid MFMediaType_Video    = new("73646976-0000-0010-8000-00AA00389B71");
    static readonly Guid MFVideoFormat_H264   = new("34363248-0000-0010-8000-00AA00389B71");
    static readonly Guid MFVideoFormat_NV12   = new("3231564E-0000-0010-8000-00AA00389B71");
    static readonly Guid MF_MT_MAJOR_TYPE     = new("48eba18e-f8c9-4687-bf11-0a74c9f96a8f");
    static readonly Guid MF_MT_SUBTYPE        = new("f7e34c9a-42e8-4714-b74b-cb29d72c35e5");
    static readonly Guid MF_MT_INTERLACE_MODE = new("e2724bb8-e676-4806-b4b2-a8d6efb44ccd");
    static readonly Guid MF_LOW_LATENCY       = new("9c27891a-ed7a-40e1-88e8-b22727a024ee");

    const uint MFT_NOTIFY_BEGIN_STREAMING         = 0x10000000;
    const uint MFT_NOTIFY_START_OF_STREAM         = 0x10000001;
    const uint MFT_OUTPUT_STREAM_PROVIDES_SAMPLES = 0x100;
    const int  S_OK                               = 0;
    const int  MF_E_TRANSFORM_NEED_MORE_INPUT     = unchecked((int)0xC00D6D72);

    // ── P/Invoke ───────────────────────────────────────────────────────────────

    [DllImport("ole32.dll")]
    static extern int CoCreateInstance(ref Guid rclsid, nint pUnkOuter, uint dwClsCtx,
                                       ref Guid riid, out nint ppv);
    [DllImport("mfplat.dll")] static extern int MFStartup(uint Version, uint dwFlags);
    [DllImport("mfplat.dll")] static extern int MFCreateMediaType(out nint ppMFType);
    [DllImport("mfplat.dll")] static extern int MFCreateSample(out nint ppIMFSample);
    [DllImport("mfplat.dll")] static extern int MFCreateMemoryBuffer(uint cbMaxLength, out nint ppBuffer);

    // ── Delegates ─────────────────────────────────────────────────────────────

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetUINT32_Del(nint p, ref Guid key, uint v);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetUINT64_Del(nint p, ref Guid key, ulong v);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetGUID_Del(nint p, ref Guid key, ref Guid v);

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

    // IMFSample (inherits IMFAttributes 33 entries, offsets below are absolute vtable indices)
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetSampleTime_Del(nint p, long hns);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetSampleDuration_Del(nint p, long hns);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int ConvertToContiguousBuffer_Del(nint p, out nint ppBuf);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int AddBuffer_Del(nint p, nint pBuf);

    // IMFMediaBuffer — ppb as nint avoids unsafe requirement
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int Lock_Del(nint p, out nint ppb, out uint maxLen, out uint curLen);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int Unlock_Del(nint p);
    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate int SetCurrentLength_Del(nint p, uint len);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate uint Release_Del(nint p);

    // ── Structs ───────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    struct MftOutputStreamInfo { public uint dwFlags, cbSize, cbAlignment; }

    [StructLayout(LayoutKind.Sequential)]
    struct MftOutputDataBuffer
    {
        public uint dwStreamID;
        public nint pSample;
        public uint dwStatus;
        public nint pEvents;
    }

    // ── Instance state ─────────────────────────────────────────────────────────

    nint _pTransform;
    bool _mftProvidesOutputSamples;
    long _sampleTime, _sampleDuration = 333_333;

    H264Decoder() { }

    public static H264Decoder? Create()
    {
        try
        {
            var d = new H264Decoder();
            if (d.Init()) return d;
            d.Dispose();
            return null;
        }
        catch { return null; }
    }

    bool Init()
    {
        if (MFStartup(0x10070, 0) != S_OK) return false;

        var clsid = CLSID_CMSH264DecoderMFT;
        var iid   = IID_IMFTransform;
        if (CoCreateInstance(ref clsid, 0, 1, ref iid, out _pTransform) != S_OK || _pTransform == 0)
            return false;

        // Enable low-latency — decoder produces output per-input-frame with no buffering
        var getAttr = Fn<GetAttributes_Del>(_pTransform, 8);
        if (getAttr(_pTransform, out nint pAttribs) == S_OK && pAttribs != 0)
        {
            Set32(pAttribs, MF_LOW_LATENCY, 1);
            Rel(pAttribs);
        }

        // Input type: H264 (dimensions come from the in-band SPS NAL)
        if (MFCreateMediaType(out nint pIn) != S_OK) return false;
        try
        {
            if (!SetG(pIn, MF_MT_MAJOR_TYPE, MFMediaType_Video)) return false;
            if (!SetG(pIn, MF_MT_SUBTYPE, MFVideoFormat_H264)) return false;
            if (!Set32(pIn, MF_MT_INTERLACE_MODE, 2)) return false;
            if (Fn<SetInputType_Del>(_pTransform, 15)(_pTransform, 0, pIn, 0) != S_OK) return false;
        }
        finally { Rel(pIn); }

        // Output type: NV12 — decoder populates actual dimensions from SPS
        if (MFCreateMediaType(out nint pOut) != S_OK) return false;
        try
        {
            SetG(pOut, MF_MT_MAJOR_TYPE, MFMediaType_Video);
            SetG(pOut, MF_MT_SUBTYPE, MFVideoFormat_NV12);
            Set32(pOut, MF_MT_INTERLACE_MODE, 2);
            // Ignore error — some decoders reject the output type before the first SPS is processed
            Fn<SetOutputType_Del>(_pTransform, 16)(_pTransform, 0, pOut, 0);
        }
        finally { Rel(pOut); }

        if (Fn<GetOutputStreamInfo_Del>(_pTransform, 7)(_pTransform, 0, out var info) == S_OK)
            _mftProvidesOutputSamples = (info.dwFlags & MFT_OUTPUT_STREAM_PROVIDES_SAMPLES) != 0;

        Fn<ProcessMessage_Del>(_pTransform, 23)(_pTransform, MFT_NOTIFY_BEGIN_STREAMING, 0);
        Fn<ProcessMessage_Del>(_pTransform, 23)(_pTransform, MFT_NOTIFY_START_OF_STREAM, 0);
        return true;
    }

    // Decodes one H264 Annex-B frame to BGRA pixels.
    // hintW/hintH come from the packet JSON and are used to compute NV12 stride from buffer size.
    // Returns null while the decoder is priming (first 1-2 frames) or on error.
    public byte[]? Decode(byte[] h264Data, int hintW, int hintH)
    {
        if (_pTransform == 0 || h264Data == null || h264Data.Length == 0) return null;

        if (MFCreateMemoryBuffer((uint)h264Data.Length, out nint pBuf) != S_OK) return null;
        try
        {
            var lockBuf   = Fn<Lock_Del>(pBuf, 3);
            var unlockBuf = Fn<Unlock_Del>(pBuf, 4);
            if (lockBuf(pBuf, out nint pDst, out _, out _) != S_OK) return null;
            Marshal.Copy(h264Data, 0, pDst, h264Data.Length);
            unlockBuf(pBuf);
            Fn<SetCurrentLength_Del>(pBuf, 6)(pBuf, (uint)h264Data.Length);

            if (MFCreateSample(out nint pSample) != S_OK) return null;
            try
            {
                Fn<AddBuffer_Del>(pSample, 42)(pSample, pBuf);
                Fn<SetSampleTime_Del>(pSample, 36)(pSample, _sampleTime);
                Fn<SetSampleDuration_Del>(pSample, 38)(pSample, _sampleDuration);
                _sampleTime += _sampleDuration;
                if (Fn<ProcessInput_Del>(_pTransform, 24)(_pTransform, 0, pSample, 0) != S_OK)
                    return null;
            }
            finally { Rel(pSample); }
        }
        finally { Rel(pBuf); }

        // Drain output (with MF_LOW_LATENCY, one input → one output for P/I-frames)
        var outFn = Fn<ProcessOutput_Del>(_pTransform, 25);
        var outBuf = new MftOutputDataBuffer();

        nint preallocSample = 0;
        if (!_mftProvidesOutputSamples)
        {
            if (MFCreateSample(out preallocSample) != S_OK || preallocSample == 0) return null;
            outBuf.pSample = preallocSample;
        }

        try
        {
            int hr = outFn(_pTransform, 0, 1, ref outBuf, out _);
            if (hr == MF_E_TRANSFORM_NEED_MORE_INPUT || hr < 0 || outBuf.pSample == 0) return null;

            if (Fn<ConvertToContiguousBuffer_Del>(outBuf.pSample, 41)(outBuf.pSample, out nint pOutBuf) != S_OK
                || pOutBuf == 0)
                return null;
            try
            {
                if (Fn<Lock_Del>(pOutBuf, 3)(pOutBuf, out nint pNv12, out _, out uint cbLen) != S_OK)
                    return null;
                try
                {
                    if (cbLen == 0 || pNv12 == 0) return null;
                    var nv12 = new byte[cbLen];
                    Marshal.Copy(pNv12, nv12, 0, (int)cbLen);

                    // Derive actual NV12 stride from the buffer size: size = stride * h * 3/2
                    // so stride = size * 2 / (3 * h). Use hintH from packet.
                    int h = hintH > 0 ? hintH : 1;
                    int w = hintW > 0 ? hintW : 1;
                    int stride = (hintH > 0 && cbLen > 0) ? (int)((long)cbLen * 2 / 3 / hintH) : w;
                    if (stride < w) stride = w;

                    return Nv12ToBgra(nv12, w, h, stride);
                }
                finally { Fn<Unlock_Del>(pOutBuf, 4)(pOutBuf); }
            }
            finally { Rel(pOutBuf); }
        }
        finally
        {
            if (_mftProvidesOutputSamples && outBuf.pSample != 0) Rel(outBuf.pSample);
            if (!_mftProvidesOutputSamples && preallocSample != 0) Rel(preallocSample);
            if (outBuf.pEvents != 0) Rel(outBuf.pEvents);
        }
    }

    // ── NV12 → BGRA conversion (BT.601 limited range) ────────────────────────

    static byte[] Nv12ToBgra(byte[] nv12, int w, int h, int stride)
    {
        var bgra  = new byte[w * h * 4];
        int uvOff = stride * h; // start of interleaved UV plane

        for (int y = 0; y < h; y++)
        {
            int dstRow = y * w * 4;
            int yRow   = y * stride;
            int uvRow  = uvOff + (y >> 1) * stride;

            for (int x = 0; x < w; x++)
            {
                int Y = Math.Max(0, nv12[yRow + x]         - 16);
                int U = nv12[uvRow + (x & ~1)]     - 128;
                int V = nv12[uvRow + (x & ~1) + 1] - 128;

                int C = 298 * Y + 128;
                int r = (C + 409 * V) >> 8;
                int g = (C - 100 * U - 208 * V) >> 8;
                int b = (C + 516 * U) >> 8;

                int off = dstRow + x * 4;
                bgra[off]     = (byte)(b < 0 ? 0 : b > 255 ? 255 : b);
                bgra[off + 1] = (byte)(g < 0 ? 0 : g > 255 ? 255 : g);
                bgra[off + 2] = (byte)(r < 0 ? 0 : r > 255 ? 255 : r);
                bgra[off + 3] = 0xFF;
            }
        }
        return bgra;
    }

    // ── Vtable helpers (safe, no unsafe) ──────────────────────────────────────

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

    // ── IDisposable ────────────────────────────────────────────────────────────

    bool _disposed;
    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        if (_pTransform != 0) { Rel(_pTransform); _pTransform = 0; }
    }
}
