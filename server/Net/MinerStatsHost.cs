using System.Collections.Concurrent;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace SeroServer.Net;

public class MinerEntry
{
    public string   Id       { get; set; } = "";
    public string   Hostname { get; set; } = "";
    public string   Ip       { get; set; } = "";
    public string   Cpu      { get; set; } = "";
    public double   H1s      { get; set; }
    public double   H60s     { get; set; }
    public string   Pool     { get; set; } = "";
    public string   Algo     { get; set; } = "";
    public int      Accepted { get; set; }
    public int      Uptime   { get; set; }
    public DateTime LastSeen { get; set; }
    [JsonIgnore] public bool Online => (DateTime.UtcNow - LastSeen).TotalMinutes < 2;
}

internal record MinerReport(
    string? id, string? hostname, string? cpu,
    double h1s, double h60s, string? pool, string? algo,
    int accepted, int uptime);

public sealed class MinerStatsHost
{
    private readonly ConcurrentDictionary<string, MinerEntry> _miners = new();
    private readonly string _token;
    private readonly int    _port;
    private HttpListener?   _listener;
    private CancellationTokenSource? _cts;

    public IReadOnlyCollection<MinerEntry> Miners => (IReadOnlyCollection<MinerEntry>)_miners.Values;
    public int Port => _port;
    public event Action? Changed;

    private static readonly JsonSerializerOptions _jsOpts = new()
        { PropertyNameCaseInsensitive = true };

    public MinerStatsHost(int port, string token)
    {
        _port  = port;
        _token = token;
    }

    public void Start()
    {
        _cts      = new CancellationTokenSource();
        _listener = new HttpListener();
        _listener.Prefixes.Add($"http://+:{_port}/");
        try { _listener.Start(); }
        catch (HttpListenerException)
        {
            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://localhost:{_port}/");
            _listener.Prefixes.Add($"http://127.0.0.1:{_port}/");
            _listener.Start();
        }
        _ = RunAsync(_cts.Token);
    }

    public void Stop()
    {
        try { _cts?.Cancel(); _listener?.Stop(); _listener?.Close(); } catch { }
    }

    private async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var ctx = await _listener!.GetContextAsync().WaitAsync(ct);
                _ = Task.Run(() => Handle(ctx), ct);
            }
            catch { if (ct.IsCancellationRequested) break; }
        }
    }

    private void Handle(HttpListenerContext ctx)
    {
        var req  = ctx.Request;
        var resp = ctx.Response;
        try
        {
            var key = req.QueryString["key"] ?? "";
            if (!string.IsNullOrEmpty(_token) && key != _token)
            { resp.StatusCode = 403; resp.Close(); return; }

            if (req.HttpMethod == "POST" && req.Url?.AbsolutePath == "/api/report")
            {
                if (req.ContentLength64 > 64 * 1024) { resp.StatusCode = 413; resp.Close(); return; }
                using var sr   = new System.IO.StreamReader(req.InputStream, req.ContentEncoding);
                var body = sr.ReadToEnd();

                MinerReport? report = null;
                try { report = JsonSerializer.Deserialize<MinerReport>(body, _jsOpts); } catch { }

                if (report?.id != null && (_miners.ContainsKey(report.id) || _miners.Count < 5000))
                {
                    var ip = ctx.Request.RemoteEndPoint?.Address?.ToString() ?? "?";
                    if (ip is "::1" or "127.0.0.1") ip = "localhost";
                    _miners[report.id] = new MinerEntry
                    {
                        Id       = report.id,
                        Hostname = report.hostname ?? "?",
                        Ip       = ip,
                        Cpu      = report.cpu      ?? "?",
                        H1s      = report.h1s,
                        H60s     = report.h60s,
                        Pool     = report.pool     ?? "?",
                        Algo     = report.algo     ?? "?",
                        Accepted = report.accepted,
                        Uptime   = report.uptime,
                        LastSeen = DateTime.UtcNow,
                    };
                    Changed?.Invoke();
                }
                resp.StatusCode = 204;
                resp.Close();
                return;
            }

            if (req.HttpMethod == "GET" && req.Url?.AbsolutePath == "/api/miners")
            {
                PruneOld();
                var snapshot = _miners.Values.OrderByDescending(m => m.LastSeen).ToList();
                var json  = JsonSerializer.Serialize(snapshot);
                var bytes = Encoding.UTF8.GetBytes(json);
                resp.ContentType     = "application/json";
                resp.ContentLength64 = bytes.Length;
                resp.OutputStream.Write(bytes, 0, bytes.Length);
                resp.Close();
                return;
            }

            resp.StatusCode = 404;
            resp.Close();
        }
        catch { try { resp.Abort(); } catch { } }
    }

    private void PruneOld()
    {
        var cutoff = DateTime.UtcNow.AddHours(-24);
        foreach (var kv in _miners)
            if (kv.Value.LastSeen < cutoff) _miners.TryRemove(kv.Key, out _);
    }
}
