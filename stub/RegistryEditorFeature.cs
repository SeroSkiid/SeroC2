using Microsoft.Win32;
using System.Text.Json;

namespace SeroStub;

internal static class RegistryEditorFeature
{
    internal static string GetChildren(string keyPath)
    {
        try
        {
            using var key = OpenKey(keyPath);
            if (key == null)
                return Error(keyPath, "Key not found");

            var subKeys = key.GetSubKeyNames().ToList();
            var values  = new List<RegValueStub>();
            foreach (var vName in key.GetValueNames())
            {
                try
                {
                    var kind = key.GetValueKind(vName);
                    var raw  = key.GetValue(vName, null, RegistryValueOptions.DoNotExpandEnvironmentNames);
                    values.Add(new RegValueStub
                    {
                        Name      = vName,
                        ValueType = kind.ToString().Replace("Unknown", "REG_BINARY").Replace("String", "REG_SZ").Replace("ExpandString", "REG_EXPAND_SZ").Replace("DWord", "REG_DWORD").Replace("QWord", "REG_QWORD").Replace("MultiString", "REG_MULTI_SZ").Replace("Binary", "REG_BINARY"),
                        Data      = raw?.ToString() ?? ""
                    });
                }
                catch { }
            }

            return JsonSerializer.Serialize(new RegChildrenResultStub { KeyPath = keyPath, SubKeys = subKeys, Values = values }, SeroJson.Default.RegChildrenResultStub);
        }
        catch (Exception ex)
        {
            return Error(keyPath, ex.Message);
        }
    }

    internal static string SetValue(string keyPath, string name, string valueType, string data)
    {
        try
        {
            using var key = OpenKey(keyPath, writable: true);
            if (key == null) return Ack(false, "Key not found");
            var kind = ParseKind(valueType);
            object value = kind switch
            {
                RegistryValueKind.DWord => int.TryParse(data, out int d) ? d : 0,
                RegistryValueKind.QWord => long.TryParse(data, out long l) ? l : 0L,
                _                       => data
            };
            key.SetValue(name, value, kind);
            return Ack(true, "");
        }
        catch (Exception ex) { return Ack(false, ex.Message); }
    }

    internal static string DeleteValue(string keyPath, string name)
    {
        try { using var key = OpenKey(keyPath, writable: true); key?.DeleteValue(name, false); return Ack(true, ""); }
        catch (Exception ex) { return Ack(false, ex.Message); }
    }

    internal static string DeleteKey(string keyPath)
    {
        try
        {
            var (hive, sub) = Split(keyPath);
            var parent = sub.Contains('\\') ? sub[..sub.LastIndexOf('\\')] : "";
            var child  = sub[(sub.LastIndexOf('\\') + 1)..];
            using var parentKey = OpenKey(hive + (parent.Length > 0 ? "\\" + parent : ""), writable: true);
            parentKey?.DeleteSubKeyTree(child, false);
            return Ack(true, "");
        }
        catch (Exception ex) { return Ack(false, ex.Message); }
    }

    internal static string CreateKey(string keyPath)
    {
        try { using var key = OpenKey(keyPath, writable: true, create: true); return Ack(key != null, key == null ? "Failed" : ""); }
        catch (Exception ex) { return Ack(false, ex.Message); }
    }

    // ── Helpers ──────────────────────────────────────────────────────────

    private static RegistryKey? OpenKey(string keyPath, bool writable = false, bool create = false)
    {
        var (hiveStr, sub) = Split(keyPath);
        var hive = hiveStr.ToUpperInvariant() switch
        {
            "HKEY_LOCAL_MACHINE" or "HKLM" => Registry.LocalMachine,
            "HKEY_CURRENT_USER"  or "HKCU" => Registry.CurrentUser,
            "HKEY_CLASSES_ROOT"  or "HKCR" => Registry.ClassesRoot,
            "HKEY_USERS"         or "HKU"  => Registry.Users,
            _                               => Registry.LocalMachine
        };
        return create ? hive.CreateSubKey(sub, writable) : hive.OpenSubKey(sub, writable);
    }

    private static (string hive, string sub) Split(string path)
    {
        var idx = path.IndexOf('\\');
        return idx < 0 ? (path, "") : (path[..idx], path[(idx + 1)..]);
    }

    private static RegistryValueKind ParseKind(string type) => type.ToUpperInvariant() switch
    {
        "REG_DWORD"      => RegistryValueKind.DWord,
        "REG_QWORD"      => RegistryValueKind.QWord,
        "REG_BINARY"     => RegistryValueKind.Binary,
        "REG_EXPAND_SZ"  => RegistryValueKind.ExpandString,
        "REG_MULTI_SZ"   => RegistryValueKind.MultiString,
        _                => RegistryValueKind.String
    };

    private static string Ack(bool ok, string err) =>
        JsonSerializer.Serialize(new RegAckStub { Success = ok, Error = err }, SeroJson.Default.RegAckStub);

    private static string Error(string path, string msg) =>
        JsonSerializer.Serialize(new RegChildrenResultStub { KeyPath = path, Error = msg }, SeroJson.Default.RegChildrenResultStub);
}
