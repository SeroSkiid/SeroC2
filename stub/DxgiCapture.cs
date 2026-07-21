using System;
using System.Runtime.InteropServices;

namespace SeroStub;

// DXGI Desktop Duplication — NativeAOT-safe, zero COM marshaling.
// Uses raw vtable dispatch (nint cast to function pointer) for all COM calls.
// Call TryInit(monIdx) once; CaptureFrame() returns BGRA pixels each frame.
internal static class DxgiCapture
{
    // ── GUIDs ─────────────────────────────────────────────────────────────────
    static readonly Guid IID_IDXGIDevice     = new(0x54ec77fa,0x1377,0x44e6,0x8c,0x32,0x88,0xfd,0x5f,0x44,0xc8,0x4c);
    static readonly Guid IID_IDXGIOutput1    = new(0x00cddea8,0x939b,0x4b83,0xa3,0x40,0xa6,0x85,0x22,0x66,0x66,0xcc);
    static readonly Guid IID_ID3D11Texture2D = new(0x6f15aaf2,0xd208,0x4e89,0x9a,0xb4,0x48,0x95,0x35,0xd3,0x4f,0x9c);

    // ── P/Invoke ──────────────────────────────────────────────────────────────
    [DllImport("d3d11.dll")]
    static extern int D3D11CreateDevice(nint pAdapter, int DriverType, nint Software,
        uint Flags, nint pFL, uint nFL, uint SDKVersion,
        out nint ppDevice, nint pFLOut, out nint ppCtx);

    // ── State ─────────────────────────────────────────────────────────────────
    static nint _dev, _ctx, _dup, _stg;
    static int  _w, _h, _monIdx = -1;
    static bool _frameHeld;

    public static bool IsInitialized => _dev != 0 && _dup != 0 && _stg != 0;

    const int DXGI_ERROR_WAIT_TIMEOUT = unchecked((int)0x887A0027);

    // ── Public API ────────────────────────────────────────────────────────────

    public static bool TryInit(int monIdx)
    {
        if (IsInitialized && _monIdx == monIdx) return true;
        Release();
        try
        {
            // D3D_DRIVER_TYPE_HARDWARE=1, D3D11_SDK_VERSION=7
            if (D3D11CreateDevice(0, 1, 0, 0, 0, 0, 7, out _dev, 0, out _ctx) < 0 || _dev == 0)
                return false;

            // ID3D11Device → IDXGIDevice (QI slot 0) → GetAdapter (slot 7)
            nint dxgiDev = ComQI(_dev, IID_IDXGIDevice);
            if (dxgiDev == 0) return false;
            nint adapter = 0;
            unsafe { int hr = ((delegate* unmanaged[Stdcall]<nint, nint*, int>)VtPtr(dxgiDev, 7))(dxgiDev, &adapter); }
            ComRelease(dxgiDev);
            if (adapter == 0) return false;

            // IDXGIAdapter::EnumOutputs(monIdx) (slot 7) → IDXGIOutput
            nint output = 0;
            unsafe { ((delegate* unmanaged[Stdcall]<nint, uint, nint*, int>)VtPtr(adapter, 7))(adapter, (uint)monIdx, &output); }
            ComRelease(adapter);
            if (output == 0) return false;

            // IDXGIOutput → IDXGIOutput1 (QI) → DuplicateOutput (slot 22)
            nint out1 = ComQI(output, IID_IDXGIOutput1);
            ComRelease(output);
            if (out1 == 0) return false;
            nint dup = 0;
            unsafe { ((delegate* unmanaged[Stdcall]<nint, nint, nint*, int>)VtPtr(out1, 22))(out1, _dev, &dup); }
            ComRelease(out1);
            if (dup == 0) return false;
            _dup = dup;

            // IDXGIOutputDuplication::GetDesc (slot 7) — size + format
            DXGI_OUTDUPL_DESC dd;
            unsafe { ((delegate* unmanaged[Stdcall]<nint, DXGI_OUTDUPL_DESC*, void>)VtPtr(_dup, 7))(_dup, &dd); }
            _w = (int)dd.Width; _h = (int)dd.Height;

            // Only BGRA formats supported (87=UNORM, 91=UNORM_SRGB) — same memory layout
            if (_w == 0 || _h == 0 || (dd.Format != 87 && dd.Format != 91))
            { Release(); return false; }

            // Staging texture: CPU-readable, same dimensions, always BGRA_UNORM
            var desc = new D3D11_TEX2D_DESC
            {
                Width = (uint)_w, Height = (uint)_h, MipLevels = 1, ArraySize = 1,
                Format = 87,          // DXGI_FORMAT_B8G8R8A8_UNORM
                SC = 1, SQ = 0,
                Usage = 3,            // D3D11_USAGE_STAGING
                BindFlags = 0,
                CPUAccess = 0x20000,  // D3D11_CPU_ACCESS_READ
                MiscFlags = 0
            };
            // ID3D11Device::CreateTexture2D (slot 5) — use local for out param (&static is disallowed)
            nint stg = 0;
            unsafe { ((delegate* unmanaged[Stdcall]<nint, D3D11_TEX2D_DESC*, nint, nint*, int>)VtPtr(_dev, 5))(_dev, &desc, 0, &stg); }
            _stg = stg;
            if (_stg == 0) { Release(); return false; }

            _monIdx = monIdx;
            return true;
        }
        catch { Release(); return false; }
    }

    // Returns BGRA top-down pixels, or null when no new frame / error.
    // timeoutMs: how long to block waiting for a VBLANK (0 = poll, 16 = ~60 fps natural pacing).
    public static byte[]? CaptureFrame(out int w, out int h, uint timeoutMs = 16)
    {
        w = h = 0;
        if (!IsInitialized) return null;
        if (_frameHeld) { ReleaseFrame(); _frameHeld = false; }

        nint res = 0;
        DXGI_OUTDUPL_FRAME_INFO fi;
        int hr;
        // IDXGIOutputDuplication::AcquireNextFrame (slot 8)
        unsafe
        {
            DXGI_OUTDUPL_FRAME_INFO* p = &fi;  // local struct — already stack-fixed
            hr = ((delegate* unmanaged[Stdcall]<nint, uint, DXGI_OUTDUPL_FRAME_INFO*, nint*, int>)
                VtPtr(_dup, 8))(_dup, timeoutMs, p, &res);
        }

        if (hr == DXGI_ERROR_WAIT_TIMEOUT) return null;  // no new frame in the timeout window
        if (hr < 0) { int m = _monIdx; Release(); TryInit(m); return null; } // ACCESS_LOST / mode change
        _frameHeld = true;

        // Some drivers return S_OK for mouse-only updates with a null resource pointer.
        // Calling ComQI on a null pointer crashes the process via AccessViolationException.
        if (res == 0) { ReleaseFrame(); _frameHeld = false; return null; }

        try
        {
            nint tex = ComQI(res, IID_ID3D11Texture2D);
            ComRelease(res); res = 0;
            if (tex == 0) return null;

            // ID3D11DeviceContext::CopyResource (slot 47) — GPU→staging
            unsafe { ((delegate* unmanaged[Stdcall]<nint, nint, nint, void>)VtPtr(_ctx, 47))(_ctx, _stg, tex); }
            ComRelease(tex);

            // ID3D11DeviceContext::Map (slot 14) — staging→CPU, D3D11_MAP_READ=1
            D3D11_MAPPED msr;
            unsafe
            {
                D3D11_MAPPED* p = &msr;  // local struct — already stack-fixed
                hr = ((delegate* unmanaged[Stdcall]<nint, nint, uint, uint, uint, D3D11_MAPPED*, int>)
                    VtPtr(_ctx, 14))(_ctx, _stg, 0u, 1u, 0u, p);
            }
            if (hr < 0) return null;

            // Copy rows — row pitch may include GPU alignment padding
            int rowPitch = (int)msr.RowPitch, rowBytes = _w * 4;
            var px = System.Buffers.ArrayPool<byte>.Shared.Rent(rowBytes * _h);
            unsafe
            {
                byte* src = (byte*)msr.pData;
                fixed (byte* dst = px)
                    for (int y = 0; y < _h; y++)
                        Buffer.MemoryCopy(src + (long)y * rowPitch, dst + (long)y * rowBytes, rowBytes, rowBytes);
            }

            // ID3D11DeviceContext::Unmap (slot 15)
            unsafe { ((delegate* unmanaged[Stdcall]<nint, nint, uint, void>)VtPtr(_ctx, 15))(_ctx, _stg, 0u); }

            w = _w; h = _h;
            return px;
        }
        catch { return null; }
        finally { ReleaseFrame(); _frameHeld = false; }
    }

    public static void Release()
    {
        if (_frameHeld) { try { ReleaseFrame(); } catch { } _frameHeld = false; }
        ComRelease(ref _stg); ComRelease(ref _dup); ComRelease(ref _ctx); ComRelease(ref _dev);
        _w = _h = 0; _monIdx = -1;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static void ReleaseFrame()
    {
        if (_dup == 0) return;
        // IDXGIOutputDuplication::ReleaseFrame (slot 14)
        unsafe { ((delegate* unmanaged[Stdcall]<nint, int>)VtPtr(_dup, 14))(_dup); }
    }

    static nint ComQI(nint p, in Guid iid)
    {
        if (p == 0) return 0;
        nint r = 0;
        // IUnknown::QueryInterface (slot 0)
        unsafe { fixed (Guid* g = &iid) ((delegate* unmanaged[Stdcall]<nint, Guid*, nint*, int>)VtPtr(p, 0))(p, g, &r); }
        return r;
    }

    // Read vtable function pointer at given slot index (0-based)
    static unsafe nint VtPtr(nint obj, int slot) => *((nint*)*(nint*)obj + slot);

    static void ComRelease(nint p)
    {
        if (p == 0) return;
        // IUnknown::Release (slot 2)
        unsafe { ((delegate* unmanaged[Stdcall]<nint, uint>)VtPtr(p, 2))(p); }
    }
    static void ComRelease(ref nint p) { ComRelease(p); p = 0; }

    // ── Structs ───────────────────────────────────────────────────────────────

    [StructLayout(LayoutKind.Sequential)]
    struct DXGI_OUTDUPL_DESC
    {
        // DXGI_MODE_DESC embedded (Width, Height, RefreshRate.N/D, Format, ScanlineOrdering, Scaling)
        public uint Width, Height, RefreshN, RefreshD, Format, ScanlineOrder, Scaling;
        public uint Rotation;
        public int  InSysMem;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DXGI_OUTDUPL_FRAME_INFO
    {
        public long LastPresent, LastMouse;
        public uint AccFrames;
        public int  Coalesced, Protected;
        public int  PtrX, PtrY, PtrVisible;
        public uint MetaSz, PtrShapeSz;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct D3D11_TEX2D_DESC
    {
        public uint Width, Height, MipLevels, ArraySize, Format;
        public uint SC, SQ;        // DXGI_SAMPLE_DESC: Count, Quality
        public uint Usage, BindFlags, CPUAccess, MiscFlags;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct D3D11_MAPPED { public nint pData; public uint RowPitch, DepthPitch; }
}
