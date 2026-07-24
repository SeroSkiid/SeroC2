using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Media.Imaging;
using SeroServer.Data;

namespace SeroServer.UI;

internal static class FlagCache
{
    internal static Action<string>? LiveLog;

    private static readonly ConcurrentDictionary<string, BitmapImage?> _mem = new(StringComparer.OrdinalIgnoreCase);
    // Tracks in-flight download tasks per country code to prevent thundering herd:
    // without this, 1000 clients from the same country would each spawn a Task.Run for the same download.
    private static readonly ConcurrentDictionary<string, Task<BitmapImage?>> _inflight = new(StringComparer.OrdinalIgnoreCase);
    private static readonly string _dir = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "SeroServer", "flags");
    private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(8) };

    // Load flag for a ClientRecord in the All Clients grid. Serves from cache when available.
    internal static void QueueLoadForRecord(Data.ClientRecord record)
    {
        var code = record.LastCountryCode;
        if (string.IsNullOrEmpty(code)) return;
        var key = code.ToLowerInvariant();
        if (_mem.TryGetValue(key, out var hit))
        {
            // Skip dispatch if record already has the correct image — avoids 100k BeginInvoke
            // calls when RefreshAllClients rebuilds the grid and all flags are already cached.
            if (hit != null && !ReferenceEquals(record.FlagImage, hit))
                Application.Current?.Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.DataBind, () => record.FlagImage = hit);
            return;
        }
        if (key == "lan" || key == "loc")
        {
            Application.Current?.Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.DataBind, () =>
            {
                try
                {
                    var label = key == "loc" ? "LCL" : "LAN";
                    var color = key == "loc"
                        ? System.Windows.Media.Color.FromRgb(0x28, 0x60, 0x90)
                        : System.Windows.Media.Color.FromRgb(0x38, 0x70, 0x58);
                    var bmp = GenerateBadge(label, color);
                    if (bmp != null) { _mem[key] = bmp; record.FlagImage = bmp; }
                }
                catch { }
            });
            return;
        }
        var task = _inflight.GetOrAdd(key, k => Task.Run(() => DownloadAsync(k)));
        _ = task.ContinueWith(t =>
        {
            _inflight.TryRemove(key, out _);
            var img = t.Status == TaskStatus.RanToCompletion ? t.Result : null;
            if (img != null) _mem[key] = img;
            else if (!_mem.TryGetValue("?", out img))
            {
                img = GenerateBadge("?", System.Windows.Media.Color.FromRgb(0x58, 0x60, 0x78));
                if (img != null) _mem["?"] = img;
            }
            Application.Current?.Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.DataBind, () => record.FlagImage = img);
        }, TaskScheduler.Default);
    }

    // Call from TlsServer after country resolution. Fires async; sets client.FlagImage on UI thread.
    internal static void QueueLoad(ConnectedClient client, string code)
    {
        if (string.IsNullOrEmpty(code))
        {
            // Unknown country — show a "?" badge so the flag column is never empty.
            SetUnknownBadge(client);
            return;
        }
        var key = code.ToLowerInvariant();
        LiveLog?.Invoke($"[FLAG] QueueLoad: client={client.Id} code={code} ip={client.IP}");

        if (_mem.TryGetValue(key, out var hit))
        {
            LiveLog?.Invoke($"[FLAG] Cache hit pour '{key}' — hit={(hit != null ? "ok" : "null")}");
            if (hit != null)
                Application.Current?.Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.DataBind, () => client.FlagImage = hit);
            return;
        }

        if (key == "lan" || key == "loc")
        {
            LiveLog?.Invoke($"[FLAG] Génération badge local: {key}");
            Application.Current?.Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.DataBind, () =>
            {
                try
                {
                    var label = key == "loc" ? "LCL" : "LAN";
                    var color = key == "loc"
                        ? System.Windows.Media.Color.FromRgb(0x28, 0x60, 0x90)
                        : System.Windows.Media.Color.FromRgb(0x38, 0x70, 0x58);
                    var bmp = GenerateBadge(label, color);
                    if (bmp != null)
                    {
                        _mem[key] = bmp;
                        client.FlagImage = bmp;
                        LiveLog?.Invoke($"[FLAG] Badge '{label}' créé et assigné à client {client.Id}");
                    }
                    else
                    {
                        LiveLog?.Invoke($"[FLAG] GenerateBadge a retourné null pour '{label}'");
                    }
                }
                catch (Exception ex)
                {
                    LiveLog?.Invoke($"[FLAG] Exception badge local: {ex.GetType().Name}: {ex.Message}");
                }
            });
            return;
        }

        LiveLog?.Invoke($"[FLAG] Téléchargement drapeau pour '{key}'...");
        var task = _inflight.GetOrAdd(key, k => Task.Run(() => DownloadAsync(k)));
        _ = task.ContinueWith(t =>
        {
            _inflight.TryRemove(key, out _);
            var img = t.Status == TaskStatus.RanToCompletion ? t.Result : null;
            if (img == null)
            {
                LiveLog?.Invoke($"[FLAG] Download échoué pour '{key}', badge inconnu");
                Application.Current?.Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.DataBind,
                    () => SetUnknownBadge(client));
                return;
            }
            LiveLog?.Invoke($"[FLAG] Drapeau '{key}' téléchargé OK, assignation...");
            _mem[key] = img;
            Application.Current?.Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.DataBind, () => client.FlagImage = img);
        }, TaskScheduler.Default);
    }

    private static void SetUnknownBadge(ConnectedClient client)
    {
        const string key = "?";
        if (!_mem.TryGetValue(key, out var badge))
        {
            badge = GenerateBadge("?", System.Windows.Media.Color.FromRgb(0x58, 0x60, 0x78));
            if (badge != null) _mem[key] = badge;
        }
        if (badge != null) client.FlagImage = badge;
    }

    private static BitmapImage? GenerateBadge(string text, System.Windows.Media.Color color)
    {
        try
        {
            var visual = new System.Windows.Media.DrawingVisual();
            using (var dc = visual.RenderOpen())
            {
                dc.DrawRoundedRectangle(new System.Windows.Media.SolidColorBrush(color), null, new Rect(0, 0, 28, 20), 3, 3);
                var ft = new System.Windows.Media.FormattedText(
                    text,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Windows.FlowDirection.LeftToRight,
                    new System.Windows.Media.Typeface(new System.Windows.Media.FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.Bold, FontStretches.Normal),
                    10,
                    System.Windows.Media.Brushes.White,
                    1.0);
                dc.DrawText(ft, new Point((28 - ft.Width) / 2, (20 - ft.Height) / 2));
            }
            var rtb = new System.Windows.Media.Imaging.RenderTargetBitmap(28, 20, 96, 96, System.Windows.Media.PixelFormats.Pbgra32);
            rtb.Render(visual);

            var encoder = new System.Windows.Media.Imaging.PngBitmapEncoder();
            encoder.Frames.Add(System.Windows.Media.Imaging.BitmapFrame.Create(rtb));
            using var ms = new MemoryStream();
            encoder.Save(ms);
            ms.Position = 0;

            var img = new BitmapImage();
            img.BeginInit();
            img.CacheOption = BitmapCacheOption.OnLoad;
            img.StreamSource = ms;
            img.EndInit();
            img.Freeze();
            return img;
        }
        catch { return null; }
    }

    private static async Task<BitmapImage?> DownloadAsync(string key)
    {
        try
        {
            Directory.CreateDirectory(_dir);
            var file = Path.Combine(_dir, $"{key}.png");
            if (!File.Exists(file))
            {
                var bytes = await _http.GetByteArrayAsync($"https://flagcdn.com/w40/{key}.png");
                await File.WriteAllBytesAsync(file, bytes);
            }
            return LoadFromFile(file);
        }
        catch { return null; }
    }

    private static BitmapImage? LoadFromFile(string path)
    {
        try
        {
            var img = new BitmapImage();
            img.BeginInit();
            img.UriSource = new Uri(path, UriKind.Absolute);
            img.CacheOption = BitmapCacheOption.OnLoad;
            img.EndInit();
            img.Freeze();
            return img;
        }
        catch { return null; }
    }
}
