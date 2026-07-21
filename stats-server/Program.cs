using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;


int port = args.Length > 0 && int.TryParse(args[0], out var p) ? p : 8080;
// Token is always required — auto-generate if not passed via args (so the server is never open)
bool autoToken = args.Length <= 1 || string.IsNullOrWhiteSpace(args[1]);
string statsToken = autoToken
    ? Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(12)).ToLower()
    : args[1];
// Optional: args[2] = public IP override (e.g. "1.2.3.4")
string? publicIpOverride = args.Length > 2 && !string.IsNullOrWhiteSpace(args[2]) ? args[2].Trim() : null;

var miners = new ConcurrentDictionary<string, MinerEntry>();

// Try http://+:{port}/ first (requires admin or urlacl grant); fall back to specific IPs
HttpListener listener;
listener = new HttpListener();
listener.Prefixes.Add($"http://+:{port}/");
try { listener.Start(); }
catch (HttpListenerException)
{
    listener = new HttpListener();
    listener.Prefixes.Add($"http://localhost:{port}/");
    listener.Prefixes.Add($"http://127.0.0.1:{port}/");
    listener.Prefixes.Add($"http://[::1]:{port}/");
    // Add each LAN IP explicitly so the dashboard is reachable on the local network
    foreach (var ip in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
        .Where(ni => ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
        .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
        .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                 && !System.Net.IPAddress.IsLoopback(a.Address)
                 && a.Address.GetAddressBytes()[0] != 169)
        .Select(a => a.Address.ToString()))
    {
        try { listener.Prefixes.Add($"http://{ip}:{port}/"); } catch { }
    }
    try { listener.Start(); }
    catch (Exception ex2)
    {
        Console.Error.WriteLine($"[!] Cannot start on port {port}: {ex2.Message}");
        Console.Error.WriteLine("    Run start_stats.bat as Administrator.");
        Console.ReadKey();
        return 1;
    }
}

// Get local IPs to display the report URL — exclude link-local (169.254.x.x) and non-operational adapters
string[] localIps = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
    .Where(ni => ni.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up)
    .SelectMany(ni => ni.GetIPProperties().UnicastAddresses)
    .Where(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
             && !System.Net.IPAddress.IsLoopback(a.Address)
             && a.Address.GetAddressBytes()[0] != 169)
    .Select(a => a.Address.ToString())
    .ToArray();

// Fetch public IP for display (miners on the internet need the public IP)
// Priority: CLI override → auto-detect (3 services tried in order)
string publicIp = publicIpOverride ?? "";
if (string.IsNullOrEmpty(publicIp))
{
    string[] ipServices = ["http://api.ipify.org", "https://checkip.amazonaws.com", "https://api4.my-ip.io/ip"];
    using var httpClient = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(4) };
    foreach (var svc in ipServices)
    {
        try { publicIp = (await httpClient.GetStringAsync(svc)).Trim(); if (!string.IsNullOrEmpty(publicIp)) break; }
        catch { }
    }
}

try { Console.Clear(); } catch { }
Console.WriteLine("╔══════════════════════════════════════════════════════╗");
Console.WriteLine("║              Sero Miner Stats Server                 ║");
Console.WriteLine("╚══════════════════════════════════════════════════════╝");
Console.WriteLine();
Console.WriteLine($"  Dashboard  →  http://localhost:{port}/");
foreach (var ip in localIps)
    Console.WriteLine($"             →  http://{ip}:{port}/");
if (!string.IsNullOrEmpty(publicIp))
    Console.WriteLine($"  Public IP  →  http://{publicIp}:{port}/  (internet)");
Console.WriteLine();
Console.WriteLine($"  Stats URL for builder:");
// Use public IP if available (miners report from internet), else LAN IP, else localhost
string reportBase = !string.IsNullOrEmpty(publicIp)  ? $"http://{publicIp}:{port}"
                  : localIps.Length > 0               ? $"http://{localIps[0]}:{port}"
                  :                                     $"http://localhost:{port}";
string reportUrl = reportBase + $"/api/report?key={statsToken}";
Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine($"    {reportUrl}");
Console.ResetColor();
if (autoToken)
{
    Console.WriteLine();
    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine($"  ⚠  Token auto-generated: {statsToken}");
    Console.WriteLine("     Paste it in the builder → STATS TOKEN, then rebuild the stub.");
    Console.ResetColor();
}
Console.WriteLine();
Console.WriteLine("  Press Ctrl+C to stop.");
Console.WriteLine();

// Auto-open browser
try { Process.Start(new ProcessStartInfo($"http://localhost:{port}/") { UseShellExecute = true }); }
catch { }

_ = Task.Run(async () =>
{
    while (true)
    {
        await Task.Delay(300_000); // cleanup after 24h of inactivity
        var cutoff = DateTime.UtcNow.AddHours(-24);
        foreach (var kv in miners)
            if (kv.Value.LastSeen < cutoff)
                miners.TryRemove(kv.Key, out _);
    }
});

while (true)
{
    HttpListenerContext ctx;
    try { ctx = await listener.GetContextAsync(); }
    catch { break; }
    _ = Task.Run(() => Handle(ctx, miners, port, statsToken));
}

return 0;

static async Task Handle(HttpListenerContext ctx, ConcurrentDictionary<string, MinerEntry> miners, int port, string token)
{
    var req  = ctx.Request;
    var resp = ctx.Response;

    try
    {
        if (req.HttpMethod == "POST" && req.Url?.AbsolutePath == "/api/report")
        {
            // Token is always required (never empty at this point)
            var key = (req.Url?.Query?.TrimStart('?') ?? "")
                .Split('&')
                .Select(p => p.Split('='))
                .Where(p => p.Length == 2 && p[0] == "key")
                .Select(p => Uri.UnescapeDataString(p[1]))
                .FirstOrDefault() ?? "";
            if (key != token) { resp.StatusCode = 403; resp.Close(); return; }

            // Reject oversized bodies — a valid miner report is never more than a few KB
            if (req.ContentLength64 > 64 * 1024) { resp.StatusCode = 413; resp.Close(); return; }

            using var sr = new StreamReader(req.InputStream, req.ContentEncoding);
            var body = await sr.ReadToEndAsync();
            if (body.Length > 64 * 1024) { resp.StatusCode = 413; resp.Close(); return; }

            MinerReport? report = null;
            try { report = JsonSerializer.Deserialize<MinerReport>(body); } catch { }

            // Cap the dictionary to prevent memory bloat from rogue stubs with valid tokens
            if (report?.id != null && (miners.ContainsKey(report.id) || miners.Count < 5000))
            {
                var ip = ctx.Request.RemoteEndPoint?.Address?.ToString() ?? "?";
                // Normalize ::1 / 127.0.0.1 to "localhost" for display
                if (ip is "::1" or "127.0.0.1") ip = "localhost";
                miners[report.id] = new MinerEntry
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
            }

            resp.StatusCode = 204;
            resp.Close();
            return;
        }

        if (req.HttpMethod == "GET" && (req.Url?.AbsolutePath == "/" || req.Url?.AbsolutePath == "/index.html"))
        {
            var html = BuildHtml(port);
            var bytes = Encoding.UTF8.GetBytes(html);
            resp.ContentType     = "text/html; charset=utf-8";
            resp.ContentLength64 = bytes.Length;
            await resp.OutputStream.WriteAsync(bytes);
            resp.Close();
            return;
        }

        if (req.HttpMethod == "GET" && req.Url?.AbsolutePath == "/api/miners")
        {
            var snapshot = miners.Values.OrderByDescending(m => m.LastSeen).ToArray();
            var json = JsonSerializer.Serialize(snapshot.Select(m => new
            {
                m.Id, m.Hostname, m.Ip, m.Cpu, m.H1s, m.H60s, m.Pool, m.Algo,
                m.Accepted, m.Uptime, m.LastSeen,
                Online = (DateTime.UtcNow - m.LastSeen).TotalMinutes < 2
            }));
            var bytes = Encoding.UTF8.GetBytes(json);
            resp.ContentType     = "application/json";
            resp.ContentLength64 = bytes.Length;
            await resp.OutputStream.WriteAsync(bytes);
            resp.Close();
            return;
        }

        resp.StatusCode = 404;
        resp.Close();
    }
    catch
    {
        try { resp.Abort(); } catch { }
    }
}

static string BuildHtml(int port) => $@"<!DOCTYPE html>
<html lang='en'>
<head>
<meta charset='utf-8'/>
<meta name='viewport' content='width=device-width,initial-scale=1'/>
<title>Sero — Miner Stats</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  :root{{--bg:#0a0a0f;--surface:#12121a;--border:#1e1e2e;--text:#cdd6f4;--muted:#6c7086;--green:#a6e3a1;--red:#f38ba8;--blue:#89b4fa;--yellow:#f9e2af;--purple:#cba6f7}}
  body{{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;font-size:13px;min-height:100vh}}
  nav{{background:var(--surface);border-bottom:1px solid var(--border);padding:0 24px;height:52px;display:flex;align-items:center;justify-content:space-between}}
  .brand{{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:700;color:#fff;letter-spacing:.3px}}
  .brand svg{{opacity:.9}}
  .live{{display:flex;align-items:center;gap:6px;font-size:11px;color:var(--muted)}}
  .live-dot{{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 6px var(--green);animation:pulse 2s infinite}}
  @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:.4}}}}
  .cards{{display:flex;gap:16px;padding:20px 24px 0;flex-wrap:wrap}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px 20px;min-width:130px}}
  .card .n{{font-size:28px;font-weight:700;line-height:1}}
  .card .l{{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;margin-top:5px}}
  .card.c-green .n{{color:var(--green)}}
  .card.c-blue  .n{{color:var(--blue)}}
  .card.c-yellow .n{{color:var(--yellow)}}
  .card.c-red   .n{{color:var(--red)}}
  .section-header{{display:flex;align-items:center;gap:10px;padding:20px 24px 10px;cursor:pointer;user-select:none}}
  .section-header h2{{font-size:13px;font-weight:600;text-transform:uppercase;letter-spacing:.6px}}
  .section-header .badge-count{{background:var(--border);border-radius:20px;padding:1px 9px;font-size:11px;color:var(--muted)}}
  .section-header .chevron{{font-size:10px;color:var(--muted);transition:transform .2s}}
  .section-header.collapsed .chevron{{transform:rotate(-90deg)}}
  .section-online h2{{color:var(--green)}}
  .section-offline h2{{color:var(--red)}}
  .wrap{{padding:0 24px 20px}}
  .wrap.hidden{{display:none}}
  table{{width:100%;border-collapse:collapse;background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden}}
  thead th{{background:#0e0e18;color:var(--muted);font-weight:500;font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:10px 14px;border-bottom:1px solid var(--border);text-align:left;white-space:nowrap}}
  tbody td{{padding:9px 14px;border-bottom:1px solid var(--border);vertical-align:middle}}
  tbody tr:last-child td{{border-bottom:none}}
  tbody tr:hover td{{background:#161622}}
  .cpu-cell{{max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:12px}}
  .badge{{display:inline-flex;align-items:center;gap:5px;padding:2px 9px;border-radius:20px;font-size:11px;font-weight:600;letter-spacing:.3px}}
  .badge.on{{background:rgba(166,227,161,.12);color:var(--green)}}
  .badge.off{{background:rgba(243,139,168,.10);color:var(--red)}}
  .hash{{color:var(--blue);font-variant-numeric:tabular-nums}}
  .accepted{{color:var(--purple)}}
  .pool-cell{{max-width:160px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--yellow);font-size:12px}}
  .ago{{color:var(--muted);font-size:11px}}
  .ip-cell{{color:var(--blue);font-size:12px;font-variant-numeric:tabular-nums}}
  .empty{{text-align:center;padding:40px 20px;color:var(--muted)}}
  .empty h3{{font-size:15px;font-weight:600;color:var(--text);margin-bottom:6px}}
  .empty code{{background:var(--border);border-radius:4px;padding:2px 7px;font-size:12px;color:var(--blue)}}
  .offline-row td{{opacity:.6}}
  footer{{padding:12px 24px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);margin-top:8px;display:flex;justify-content:space-between}}
</style>
</head>
<body>
<nav>
  <div class='brand'>
    <svg width='18' height='18' viewBox='0 0 24 24' fill='none' stroke='#89b4fa' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><circle cx='12' cy='12' r='10'/><polyline points='12 6 12 12 16 14'/></svg>
    Sero Miner Stats
  </div>
  <div class='live'><span class='live-dot'></span><span id='upd'>connecting…</span></div>
</nav>

<div class='cards'>
  <div class='card c-green'><div class='n' id='c-online'>—</div><div class='l'>Online</div></div>
  <div class='card c-red'>  <div class='n' id='c-offline'>—</div><div class='l'>Offline</div></div>
  <div class='card c-blue'> <div class='n' id='c-total'>—</div> <div class='l'>Total</div></div>
  <div class='card c-yellow'><div class='n' id='c-hash'>—</div><div class='l'>H/s combined</div></div>
</div>

<!-- Online section -->
<div class='section-header section-online' id='hdr-online' onclick='toggle(""online"")'>
  <h2>Online</h2><span class='badge-count' id='cnt-online'>0</span><span class='chevron'>▼</span>
</div>
<div class='wrap' id='wrap-online'>
  <table>
    <thead><tr><th>Hostname</th><th>IP</th><th>CPU</th><th>H/s 1m</th><th>H/s 60m</th><th>Pool</th><th>Algo</th><th>Accepted</th><th>Uptime</th><th>Last seen</th></tr></thead>
    <tbody id='tbody-online'><tr><td colspan='10'><div class='empty'><h3>Waiting for data…</h3></div></td></tr></tbody>
  </table>
</div>

<!-- Offline section -->
<div class='section-header section-offline' id='hdr-offline' onclick='toggle(""offline"")'>
  <h2>Offline</h2><span class='badge-count' id='cnt-offline'>0</span><span class='chevron'>▼</span>
</div>
<div class='wrap' id='wrap-offline'>
  <table>
    <thead><tr><th>Hostname</th><th>IP</th><th>CPU</th><th>Pool</th><th>Algo</th><th>Best H/s 1m</th><th>Accepted</th><th>Last seen</th></tr></thead>
    <tbody id='tbody-offline'><tr><td colspan='8'><div class='empty'><h3>No offline clients</h3></div></td></tr></tbody>
  </table>
</div>

<footer><span id='ts'></span><span>Report URL: <code>http://&lt;your-ip&gt;:{port}/api/report</code></span></footer>
<script>
function fmtUptime(s){{
  if(!s) return '-';
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sc=s%60;
  if(h>0) return h+'h '+m+'m';
  if(m>0) return m+'m '+sc+'s';
  return sc+'s';
}}
function fmtAgo(ts){{
  const d=(Date.now()-new Date(ts).getTime())/1000;
  if(d<60) return Math.floor(d)+'s ago';
  if(d<3600) return Math.floor(d/60)+'m ago';
  if(d<86400) return Math.floor(d/3600)+'h ago';
  return Math.floor(d/86400)+'d ago';
}}
function txt(s){{return document.createTextNode(String(s??''));}}
function td(content,cls){{
  const el=document.createElement('td');
  if(cls) el.className=cls;
  if(content instanceof Node) el.appendChild(content);
  else el.appendChild(document.createTextNode(String(content??'')));
  return el;
}}
function toggle(section){{
  const hdr=document.getElementById('hdr-'+section);
  const wrap=document.getElementById('wrap-'+section);
  hdr.classList.toggle('collapsed');
  wrap.classList.toggle('hidden');
}}
async function refresh(){{
  try{{
    const data=await(await fetch('/api/miners')).json();
    const online=data.filter(m=>m.Online);
    const offline=data.filter(m=>!m.Online);
    const totalH=online.reduce((a,m)=>a+m.H1s,0);
    document.getElementById('c-online').textContent=online.length;
    document.getElementById('c-offline').textContent=offline.length;
    document.getElementById('c-total').textContent=data.length;
    document.getElementById('c-hash').textContent=totalH.toFixed(1);
    document.getElementById('cnt-online').textContent=online.length;
    document.getElementById('cnt-offline').textContent=offline.length;
    document.getElementById('upd').textContent='Updated '+new Date().toLocaleTimeString();
    document.getElementById('ts').textContent=new Date().toLocaleTimeString()+' local';

    // Online table
    const tOn=document.getElementById('tbody-online');
    if(online.length===0){{
      tOn.innerHTML=`<tr><td colspan='10'><div class='empty'><h3>No miners online</h3><p>Set Stats URL in the builder to <code>/api/report</code></p></div></td></tr>`;
    }} else {{
      tOn.innerHTML='';
      for(const m of online){{
        const tr=document.createElement('tr');
        tr.appendChild(td(m.Hostname));
        tr.appendChild(td(m.Ip,'ip-cell'));
        const cpuTd=document.createElement('td'); cpuTd.className='cpu-cell'; cpuTd.title=m.Cpu; cpuTd.appendChild(txt(m.Cpu)); tr.appendChild(cpuTd);
        tr.appendChild(td(m.H1s.toFixed(2),'hash'));
        tr.appendChild(td(m.H60s.toFixed(2),'hash'));
        const poolTd=document.createElement('td'); poolTd.className='pool-cell'; poolTd.title=m.Pool; poolTd.appendChild(txt(m.Pool)); tr.appendChild(poolTd);
        tr.appendChild(td(m.Algo));
        tr.appendChild(td(m.Accepted,'accepted'));
        tr.appendChild(td(fmtUptime(m.Uptime)));
        tr.appendChild(td(fmtAgo(m.LastSeen),'ago'));
        tOn.appendChild(tr);
      }}
    }}

    // Offline table
    const tOff=document.getElementById('tbody-offline');
    if(offline.length===0){{
      tOff.innerHTML=`<tr><td colspan='8'><div class='empty'><h3>No offline clients</h3></div></td></tr>`;
    }} else {{
      tOff.innerHTML='';
      for(const m of offline){{
        const tr=document.createElement('tr'); tr.className='offline-row';
        tr.appendChild(td(m.Hostname));
        tr.appendChild(td(m.Ip,'ip-cell'));
        const cpuTd=document.createElement('td'); cpuTd.className='cpu-cell'; cpuTd.title=m.Cpu; cpuTd.appendChild(txt(m.Cpu)); tr.appendChild(cpuTd);
        const poolTd=document.createElement('td'); poolTd.className='pool-cell'; poolTd.title=m.Pool; poolTd.appendChild(txt(m.Pool)); tr.appendChild(poolTd);
        tr.appendChild(td(m.Algo));
        tr.appendChild(td(m.H1s>0?m.H1s.toFixed(2):'-','hash'));
        tr.appendChild(td(m.Accepted,'accepted'));
        tr.appendChild(td(fmtAgo(m.LastSeen),'ago'));
        tOff.appendChild(tr);
      }}
    }}
  }}catch(e){{
    document.getElementById('upd').textContent='Error — retrying…';
  }}
}}
refresh();
setInterval(refresh,3000);
</script>
</body>
</html>";


record MinerReport(string? id, string? hostname, string? cpu,
    double h1s, double h60s, string? pool, string? algo, int accepted, int uptime);

class MinerEntry
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
}
