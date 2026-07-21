using System.Runtime.InteropServices;
using System.Text.Json;

namespace SeroStub;

internal static class DeviceManagerFeature
{
    // SetupApi P/Invoke — no WMI needed
    private static readonly Guid GUID_DEVCLASS_ALL = Guid.Empty;

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
    private static extern IntPtr SetupDiGetClassDevsW(ref Guid classGuid, IntPtr enumerator, IntPtr hwndParent, uint flags);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
    private static extern bool SetupDiEnumDeviceInfo(IntPtr deviceInfoSet, uint memberIndex, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
    private static extern bool SetupDiGetDeviceRegistryPropertyW(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData,
        uint property, out uint propertyRegDataType, [Out] byte[] propertyBuffer, uint propertyBufferSize, out uint requiredSize);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
    private static extern bool SetupDiRemoveDevice(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData);

    [DllImport("setupapi.dll")]
    private static extern bool SetupDiDestroyDeviceInfoList(IntPtr deviceInfoSet);

    [DllImport("setupapi.dll", CharSet = CharSet.Unicode)]
    private static extern bool SetupDiGetDeviceInstanceIdW(IntPtr deviceInfoSet, ref SP_DEVINFO_DATA deviceInfoData,
        [Out] char[] deviceInstanceId, uint deviceInstanceIdSize, out uint requiredSize);

    [StructLayout(LayoutKind.Sequential)]
    private struct SP_DEVINFO_DATA { public uint cbSize; public Guid ClassGuid; public uint DevInst; public IntPtr Reserved; }

    private const uint DIGCF_PRESENT = 0x00000002;
    private const uint DIGCF_ALLCLASSES = 0x00000004;
    private const uint SPDRP_DEVICEDESC = 0x00000000;
    private const uint SPDRP_CLASS      = 0x00000007;
    private const uint SPDRP_MFG        = 0x0000000B;

    private static readonly IntPtr INVALID_HANDLE = new IntPtr(-1);

    internal static string GetList()
    {
        var devices = new List<DeviceEntryStub>();
        var guid = GUID_DEVCLASS_ALL;
        var hSet = SetupDiGetClassDevsW(ref guid, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if (hSet == INVALID_HANDLE) return JsonSerializer.Serialize(new DevListResultStub(), SeroJson.Default.DevListResultStub);

        try
        {
            for (uint i = 0; ; i++)
            {
                var dd = new SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf<SP_DEVINFO_DATA>() };
                if (!SetupDiEnumDeviceInfo(hSet, i, ref dd)) break;
                try
                {
                    var name  = GetProp(hSet, ref dd, SPDRP_DEVICEDESC);
                    var cls   = GetProp(hSet, ref dd, SPDRP_CLASS);
                    var mfg   = GetProp(hSet, ref dd, SPDRP_MFG);
                    var devId = GetInstanceId(hSet, ref dd);
                    if (string.IsNullOrWhiteSpace(name)) continue;
                    devices.Add(new DeviceEntryStub { Name = name, Class = cls, Manufacturer = mfg, DeviceId = devId, Status = "OK" });
                }
                catch { }
            }
        }
        finally { SetupDiDestroyDeviceInfoList(hSet); }

        devices.Sort((a, b) => string.Compare(a.Class + a.Name, b.Class + b.Name, StringComparison.OrdinalIgnoreCase));
        return JsonSerializer.Serialize(new DevListResultStub { Devices = devices }, SeroJson.Default.DevListResultStub);
    }

    internal static string Uninstall(string deviceId)
    {
        var guid = GUID_DEVCLASS_ALL;
        var hSet = SetupDiGetClassDevsW(ref guid, IntPtr.Zero, IntPtr.Zero, DIGCF_PRESENT | DIGCF_ALLCLASSES);
        if (hSet == INVALID_HANDLE) return Ack(false, "SetupDi failed");
        try
        {
            for (uint i = 0; ; i++)
            {
                var dd = new SP_DEVINFO_DATA { cbSize = (uint)Marshal.SizeOf<SP_DEVINFO_DATA>() };
                if (!SetupDiEnumDeviceInfo(hSet, i, ref dd)) break;
                if (GetInstanceId(hSet, ref dd).Equals(deviceId, StringComparison.OrdinalIgnoreCase))
                {
                    bool ok = SetupDiRemoveDevice(hSet, ref dd);
                    return Ack(ok, ok ? "" : "Remove failed");
                }
            }
            return Ack(false, "Device not found");
        }
        finally { SetupDiDestroyDeviceInfoList(hSet); }
    }

    private static string GetProp(IntPtr hSet, ref SP_DEVINFO_DATA dd, uint prop)
    {
        var buf = new byte[512];
        if (!SetupDiGetDeviceRegistryPropertyW(hSet, ref dd, prop, out _, buf, (uint)buf.Length, out uint reqSize)) return "";
        var s = System.Text.Encoding.Unicode.GetString(buf, 0, (int)Math.Min(reqSize, (uint)buf.Length));
        var idx = s.IndexOf('\0');
        return (idx >= 0 ? s[..idx] : s).Trim();
    }

    private static string GetInstanceId(IntPtr hSet, ref SP_DEVINFO_DATA dd)
    {
        var buf = new char[512];
        if (!SetupDiGetDeviceInstanceIdW(hSet, ref dd, buf, (uint)buf.Length, out _)) return "";
        return new string(buf).TrimEnd('\0');
    }

    private static string Ack(bool ok, string err) =>
        JsonSerializer.Serialize(new DevAckStub { Success = ok, Error = err }, SeroJson.Default.DevAckStub);
}
