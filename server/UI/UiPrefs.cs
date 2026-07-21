using System.IO;

namespace SeroServer.UI;

internal static class UiPrefs
{
    private static readonly string _path = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SeroServer", "ui_prefs.json");

    private static Dictionary<string, string> _data = [];

    static UiPrefs()
    {
        try
        {
            if (File.Exists(_path))
                _data = Newtonsoft.Json.JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    File.ReadAllText(_path)) ?? [];
        }
        catch { }
    }

    public static int GetInt(string key, int defaultVal)
    {
        if (_data.TryGetValue(key, out var v) && int.TryParse(v, out var i)) return i;
        return defaultVal;
    }

    public static string GetString(string key, string defaultVal)
    {
        return _data.TryGetValue(key, out var v) ? v : defaultVal;
    }

    public static void Set(string key, int value)
    {
        _data[key] = value.ToString();
        Flush();
    }

    public static void Set(string key, string value)
    {
        _data[key] = value;
        Flush();
    }

    private static void Flush()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(_path)!);
            File.WriteAllText(_path, Newtonsoft.Json.JsonConvert.SerializeObject(_data));
        }
        catch { }
    }
}
