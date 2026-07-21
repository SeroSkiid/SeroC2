using System.Net.Http;
using System.Text.Json;

namespace SeroStub;

// Posts comments on TikTok videos or livestreams using an existing session.
// The machine sends the request — uses session cookies provided by the operator
// (or auto-detected from browsers installed on this machine).
internal static class TikTokFeature
{
    private const string BaseUrl = "https://www.tiktok.com";

    // ── Post comment on a video ─────────────────────────────────────────────

    internal static async Task<(bool success, string error)> CommentOnVideo(
        string videoId, string text, string cookie)
    {
        videoId = CleanId(videoId);
        try
        {
            using var http = MakeClient(cookie, $"{BaseUrl}/video/{videoId}");
            var payload = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["aweme_id"]        = videoId,
                ["text"]            = text,
                ["is_side_comment"] = "0",
            });
            var resp = await http.PostAsync(
                $"{BaseUrl}/api/comment/publish/?aid=1988&app_name=tiktok_web",
                payload);
            return ParseResponse(await resp.Content.ReadAsStringAsync());
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    // ── Post comment on a livestream ────────────────────────────────────────

    internal static async Task<(bool success, string error)> CommentOnLive(
        string roomId, string text, string cookie)
    {
        roomId = CleanId(roomId);
        try
        {
            using var http = MakeClient(cookie, $"{BaseUrl}/live/{roomId}");
            // TikTok live chat endpoint
            var payload = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["room_id"]   = roomId,
                ["content"]   = text,
                ["type"]      = "1",
            });
            var resp = await http.PostAsync(
                $"{BaseUrl}/api/live/comment/?aid=1988&app_name=tiktok_web",
                payload);
            return ParseResponse(await resp.Content.ReadAsStringAsync());
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    // ── Cookie detection ────────────────────────────────────────────────────

    internal static string DetectCookie()
    {
        // Check text cookie file exports placed by the operator on the machine
        var exports = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop),       "tiktok_cookies.txt"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),   "tiktok_cookies.txt"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "tiktok_cookies.txt"),
        };
        foreach (var p in exports)
        {
            try
            {
                if (!File.Exists(p)) continue;
                var c = File.ReadAllText(p).Trim();
                if (c.Contains("sessionid") || c.Contains("tiktok")) return c;
            }
            catch { }
        }

        // Check Chrome / Edge profile directories for a Cookies.txt export
        var profiles = new[]
        {
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Google\Chrome\User Data\Default"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                @"Microsoft\Edge\User Data\Default"),
        };
        foreach (var p in profiles)
        {
            var txt = Path.Combine(p, "tiktok_cookies.txt");
            try
            {
                if (File.Exists(txt))
                {
                    var c = File.ReadAllText(txt).Trim();
                    if (c.Length > 20) return c;
                }
            }
            catch { }
        }

        return "";
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static HttpClient MakeClient(string cookie, string referer)
    {
        var handler = new HttpClientHandler { UseCookies = false };
        var http = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(20) };
        http.DefaultRequestHeaders.UserAgent.ParseAdd(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
            "(KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 TikTok/26.2.0");
        http.DefaultRequestHeaders.Add("Cookie", cookie);
        http.DefaultRequestHeaders.Add("Referer", referer);
        http.DefaultRequestHeaders.Add("Origin",  BaseUrl);
        http.DefaultRequestHeaders.Add("X-Tt-Token", ExtractCookieValue(cookie, "tt_csrf_token"));
        return http;
    }

    private static (bool, string) ParseResponse(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            int status = doc.RootElement.TryGetProperty("status_code", out var sc) ? sc.GetInt32() : -1;
            return status == 0 ? (true, "") : (false, $"status={status}: {body[..Math.Min(body.Length, 200)]}");
        }
        catch { return (false, body[..Math.Min(body.Length, 200)]); }
    }

    private static string CleanId(string input)
    {
        var s = input.Split('?')[0].TrimEnd('/');
        var idx = s.LastIndexOf('/');
        if (idx >= 0 && idx < s.Length - 1)
        {
            var part = s[(idx + 1)..];
            if (part.All(char.IsDigit)) return part;
        }
        return s.Trim();
    }

    private static string ExtractCookieValue(string cookie, string name)
    {
        foreach (var p in cookie.Split(';'))
        {
            var kv = p.Trim();
            if (kv.StartsWith(name + "=", StringComparison.OrdinalIgnoreCase))
                return kv[(name.Length + 1)..];
        }
        return "";
    }
}

internal class TikTokCommentStub    { public string VideoId { get; set; } = ""; public string Text { get; set; } = ""; public string Cookie { get; set; } = ""; public bool IsLiveroom { get; set; } }
internal class TikTokCommentAckStub { public bool Success { get; set; } public string Error { get; set; } = ""; }
internal class TikTokCookieResultStub { public string Cookie { get; set; } = ""; public bool Found { get; set; } }
