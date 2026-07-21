using System.Runtime.InteropServices;
using System.Text.Json;
using Microsoft.Win32;

namespace SeroStub;

internal static class StartupManagerFeature
{
    // ── WinVerifyTrust (Authenticode signature check) ──────────────────────
    [DllImport("wintrust.dll", SetLastError = false)]
    private static extern int WinVerifyTrust(nint hwnd, ref Guid pgActionID, nint pWVTData);

    private static readonly Guid _wvtAction = new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    // Returns (isSigned&trusted, companyName)
    private static (bool, string) SignatureInfo(string rawPath)
    {
        try
        {
            var exe = ExtractExePath(rawPath);
            if (!File.Exists(exe)) return (false, "");

            var pub = "";
            try { pub = System.Diagnostics.FileVersionInfo.GetVersionInfo(exe).CompanyName ?? ""; } catch { }

            // WINTRUST_FILE_INFO (x64 layout, 32 bytes):
            //  0: cbStruct(4)  4: pad(4)  8: pcwszFilePath*(8)  16: hFile*(8)  24: pgKnownSubject*(8)
            var pathPtr = Marshal.StringToHGlobalUni(exe);
            var fi      = Marshal.AllocHGlobal(32);
            try
            {
                Marshal.WriteInt32(fi,  0, 32);          // cbStruct
                Marshal.WriteInt32(fi,  4,  0);          // pad
                Marshal.WriteIntPtr(fi,  8, pathPtr);    // pcwszFilePath
                Marshal.WriteIntPtr(fi, 16, nint.Zero);  // hFile
                Marshal.WriteIntPtr(fi, 24, nint.Zero);  // pgKnownSubject

                // WINTRUST_DATA (x64 layout, 88 bytes):
                //  0: cbStruct  8: pPolicyCallbackData*  16: pSIPClientData*
                //  24: dwUIChoice  28: fdwRevocationChecks  32: dwUnionChoice
                //  40: pFile*(union)  48: dwStateAction  56: hWVTStateData*
                //  64: pwszURLReference*  72: dwProvFlags  76: dwUIContext  80: pSignatureSettings*
                var wtd = Marshal.AllocHGlobal(88);
                try
                {
                    for (int i = 0; i < 88; i++) Marshal.WriteByte(wtd, i, 0);
                    Marshal.WriteInt32(wtd,  0, 88);        // cbStruct
                    Marshal.WriteInt32(wtd, 24,  2);        // dwUIChoice = WTD_UI_NONE
                    Marshal.WriteInt32(wtd, 28,  0);        // fdwRevocationChecks = WTD_REVOKE_NONE
                    Marshal.WriteInt32(wtd, 32,  1);        // dwUnionChoice = WTD_CHOICE_FILE
                    Marshal.WriteIntPtr(wtd, 40, fi);       // pFile
                    Marshal.WriteInt32(wtd, 48,  0);        // dwStateAction = WTD_STATEACTION_IGNORE
                    Marshal.WriteInt32(wtd, 72, 0x1000);    // dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL

                    var action = _wvtAction;
                    bool ok = WinVerifyTrust(nint.Zero, ref action, wtd) == 0;
                    return (ok, pub);
                }
                finally { Marshal.FreeHGlobal(wtd); }
            }
            finally { Marshal.FreeHGlobal(fi); Marshal.FreeHGlobal(pathPtr); }
        }
        catch { return (false, ""); }
    }

    // Extract the bare exe path from a value like: "C:\app\foo.exe" -args  or  C:\app\foo.exe -args
    private static string ExtractExePath(string raw)
    {
        raw = Environment.ExpandEnvironmentVariables(raw.Trim());
        if (raw.StartsWith('"'))
        {
            int e = raw.IndexOf('"', 1);
            if (e > 0) return raw[1..e];
        }
        if (File.Exists(raw)) return raw;
        int sp = raw.IndexOf(' ');
        return sp > 0 ? raw[..sp] : raw;
    }

    // ── Main entry point ───────────────────────────────────────────────────
    internal static string GetList()
    {
        var entries = new List<StartupEntryStub>();

        AddRegEntries(entries, Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "Reg", "HKCU\\Run");
        AddRegEntries(entries, Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",     "Reg", "HKLM\\Run");
        AddRegEntries(entries, Registry.CurrentUser,  @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Reg", "HKCU\\RunOnce");
        AddRegEntries(entries, Registry.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "Reg", "HKLM\\RunOnce");

        AddStartupFolder(entries, Environment.GetFolderPath(Environment.SpecialFolder.Startup),       "File", "User Startup");
        AddStartupFolder(entries, Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup), "File", "Common Startup");

        AddScheduledTasks(entries);
        AddWmiSubscriptions(entries);

        // Enrich every entry with Authenticode info
        foreach (var e in entries)
            (e.Verified, e.Publisher) = SignatureInfo(e.Path);

        return JsonSerializer.Serialize(new StartupListResultStub { Entries = entries }, SeroJson.Default.StartupListResultStub);
    }

    // ── Scheduled tasks (non-system only) ─────────────────────────────────
    private static void AddScheduledTasks(List<StartupEntryStub> entries)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("schtasks", "/query /fo CSV /nh /v")
            {
                CreateNoWindow = true, UseShellExecute = false,
                RedirectStandardOutput = true, RedirectStandardError = true,
            };
            using var p = System.Diagnostics.Process.Start(psi);
            if (p == null) return;
            var csv = p.StandardOutput.ReadToEnd();
            p.WaitForExit(5000);
            var hostname = Environment.MachineName;
            foreach (var line in csv.Split('\n'))
            {
                var cols = SplitCsv(line);
                if (cols.Length < 9) continue;
                var status = cols[3].Trim('"');
                if (status == "Disabled") continue;
                var name = cols[0].Trim('"');
                if (name.StartsWith("\\Microsoft\\", StringComparison.OrdinalIgnoreCase)) continue;
                if (name.TrimStart('\\').StartsWith(hostname, StringComparison.OrdinalIgnoreCase)) continue;
                var action = cols[8].Trim('"');
                if (string.IsNullOrWhiteSpace(action) || action == "N/A") continue;
                var al = action.ToLowerInvariant();
                if (al.StartsWith(@"c:\windows\system32\") || al.StartsWith(@"c:\windows\syswow64\")) continue;
                if (al.StartsWith("%systemroot%\\") || al.StartsWith("%windir%\\")) continue;
                entries.Add(new StartupEntryStub
                {
                    Name     = name.TrimStart('\\'),
                    Path     = action,
                    Type     = "Task",
                    Location = "Task Scheduler",
                });
            }
        }
        catch { }
    }

    // ── WMI event subscriptions ────────────────────────────────────────────
    private static void AddWmiSubscriptions(List<StartupEntryStub> entries)
    {
        // CommandLineEventConsumer — executes a command on trigger
        QueryWmiClass("CommandLineEventConsumer", "Name", "CommandLineTemplate", entries, "WMI\\CMD");
        // ActiveScriptEventConsumer — runs a VBScript/JScript on trigger
        QueryWmiClass("ActiveScriptEventConsumer", "Name", "ScriptFileName", entries, "WMI\\Script");
    }

    private static void QueryWmiClass(string cls, string nameProp, string pathProp,
        List<StartupEntryStub> entries, string locLabel)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo("wmic",
                $@"/namespace:\\root\subscription PATH {cls} GET {nameProp},{pathProp} /FORMAT:CSV")
            { CreateNoWindow = true, UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc == null) return;
            var csv = proc.StandardOutput.ReadToEnd();
            proc.WaitForExit(5000);

            int nameCol = -1, pathCol = -1;
            bool headerParsed = false;
            foreach (var rawLine in csv.Split('\n'))
            {
                var line = rawLine.TrimEnd('\r', ' ');
                if (string.IsNullOrWhiteSpace(line)) continue;
                var cols = SplitCsv(line);
                if (!headerParsed)
                {
                    for (int i = 0; i < cols.Length; i++)
                    {
                        var h = cols[i].Trim('"');
                        if (h.Equals(nameProp, StringComparison.OrdinalIgnoreCase)) nameCol = i;
                        else if (h.Equals(pathProp, StringComparison.OrdinalIgnoreCase)) pathCol = i;
                    }
                    headerParsed = true;
                    continue;
                }
                if (nameCol < 0 || pathCol < 0) continue;
                if (cols.Length <= Math.Max(nameCol, pathCol)) continue;
                var name = cols[nameCol].Trim('"', ' ');
                var path = cols[pathCol].Trim('"', ' ');
                if (!string.IsNullOrWhiteSpace(name))
                    entries.Add(new StartupEntryStub { Name = name, Path = path, Type = "WMI", Location = locLabel });
            }
        }
        catch { }
    }

    // ── Delete ─────────────────────────────────────────────────────────────
    internal static void Delete(string name, string type, string location)
    {
        try
        {
            switch (type)
            {
                case "Reg":
                    RegistryHive hive = location.StartsWith("HKLM") ? RegistryHive.LocalMachine : RegistryHive.CurrentUser;
                    string subKey = location.Contains("RunOnce")
                        ? @"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
                        : @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run";
                    using (var key = RegistryKey.OpenBaseKey(hive, RegistryView.Default).OpenSubKey(subKey, true))
                        key?.DeleteValue(name, false);
                    break;

                case "File":
                    var startupDirs = new[]
                    {
                        Environment.GetFolderPath(Environment.SpecialFolder.Startup),
                        Environment.GetFolderPath(Environment.SpecialFolder.CommonStartup),
                    };
                    foreach (var dir in startupDirs)
                    {
                        var file = Path.Combine(dir, name);
                        if (File.Exists(file)) { File.Delete(file); break; }
                    }
                    break;

                case "Task":
                    var tPsi = new System.Diagnostics.ProcessStartInfo("schtasks",
                        $"/delete /tn \"{name}\" /f")
                    { CreateNoWindow = true, UseShellExecute = false };
                    using (var p = System.Diagnostics.Process.Start(tPsi)) p?.WaitForExit(5000);
                    break;

                case "WMI":
                    // Determine class from location label
                    var wmiClass = location == "WMI\\CMD" ? "CommandLineEventConsumer" : "ActiveScriptEventConsumer";
                    var wPsi = new System.Diagnostics.ProcessStartInfo("wmic",
                        $@"/namespace:\\root\subscription PATH {wmiClass} WHERE ""Name='{name}'"" DELETE")
                    { CreateNoWindow = true, UseShellExecute = false };
                    using (var p = System.Diagnostics.Process.Start(wPsi)) p?.WaitForExit(5000);
                    break;
            }
        }
        catch { }
    }

    // ── Helpers ────────────────────────────────────────────────────────────
    private static string[] SplitCsv(string line)
    {
        var fields = new List<string>();
        bool inQuotes = false;
        var cur = new System.Text.StringBuilder();
        foreach (var c in line)
        {
            if (c == '"') { inQuotes = !inQuotes; }
            else if (c == ',' && !inQuotes) { fields.Add(cur.ToString()); cur.Clear(); }
            else cur.Append(c);
        }
        fields.Add(cur.ToString());
        return [.. fields];
    }

    private static void AddRegEntries(List<StartupEntryStub> list, RegistryKey root, string keyPath, string type, string location)
    {
        try
        {
            using var key = root.OpenSubKey(keyPath);
            if (key == null) return;
            foreach (var name in key.GetValueNames())
            {
                var val = key.GetValue(name)?.ToString() ?? "";
                list.Add(new StartupEntryStub { Name = name, Path = val, Type = type, Location = location });
            }
        }
        catch { }
    }

    private static void AddStartupFolder(List<StartupEntryStub> list, string dir, string type, string location)
    {
        try
        {
            if (!Directory.Exists(dir)) return;
            foreach (var file in Directory.GetFiles(dir))
                list.Add(new StartupEntryStub { Name = Path.GetFileName(file), Path = file, Type = type, Location = location });
        }
        catch { }
    }
}

internal class StartupEntryStub
{
    public string Name      { get; set; } = "";
    public string Path      { get; set; } = "";
    public string Type      { get; set; } = "";
    public string Location  { get; set; } = "";
    public bool   Verified  { get; set; }
    public string Publisher { get; set; } = "";
}
internal class StartupListResultStub  { public List<StartupEntryStub> Entries { get; set; } = []; }
internal class StartupDeleteDataStub  { public string Name { get; set; } = ""; public string Type { get; set; } = ""; public string Location { get; set; } = ""; }
