using System.Collections.Generic;
using System.Windows;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class FileSearchWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private bool _searching;

    public FileSearchWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = clientLabel;

        _server.RegisterHandler(clientId, PacketType.FmSearchResult, OnResult);
        _server.ClientDisconnected += OnDisconnected;
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();

        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.FmSearchResult);
            _server.ClientDisconnected -= OnDisconnected;
            Lang.LanguageChanged -= ApplyLanguage;
        };
    }

    public void SetRootPath(string path)
    {
        if (TxtPath != null && !string.IsNullOrEmpty(path))
            TxtPath.Text = path;
    }

    private void ApplyLanguage()
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(ApplyLanguage); return; }
        Title                          = Lang.Get("FEAT_FILE_SEARCH");
        if (TxtLblPath     != null) TxtLblPath.Text     = Lang.Get("FS_PATH");
        if (TxtLblPattern  != null) TxtLblPattern.Text  = Lang.Get("FS_PATTERN");
        if (TxtRecursive   != null) TxtRecursive.Text   = Lang.Get("FS_RECURSIVE");
        if (TxtBtnSearch   != null) TxtBtnSearch.Text   = Lang.Get("FS_SEARCH");
        if (MnuCopyPath    != null) MnuCopyPath.Header  = Lang.Get("FS_COPY_PATH");
        if (MnuOpenInFm    != null) MnuOpenInFm.Header  = Lang.Get("FS_OPEN_IN_FM");
        if (ColName        != null) ColName.Header      = Lang.Get("FM_NAME");
        if (ColFullPath    != null) ColFullPath.Header  = Lang.Get("FM_PATH");
        if (ColSize        != null) ColSize.Header      = Lang.Get("FM_SIZE");
        if (ColType        != null) ColType.Header      = Lang.Get("FS_TYPE");
    }

    private async void Search_Click(object s, RoutedEventArgs e)
    {
        if (_searching) return;
        _searching = true;
        BtnSearch.IsEnabled = false;
        TxtStatus.Text = Lang.Get("FS_SEARCHING");
        GridResults.ItemsSource = null;

        await _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.FmSearch,
            Data = JsonConvert.SerializeObject(new FmSearchData
            {
                Path       = TxtPath.Text.Trim(),
                Pattern    = string.IsNullOrWhiteSpace(TxtPattern.Text) ? "*" : TxtPattern.Text.Trim(),
                Recursive  = ChkRecursive.IsChecked == true,
                MaxResults = 500,
            })
        });
    }

    private void OnResult(Packet pkt)
    {
        var data = JsonConvert.DeserializeObject<FmSearchResultData>(pkt.Data);
        Dispatcher.BeginInvoke(() =>
        {
            _searching = false;
            BtnSearch.IsEnabled = true;

            if (data == null) { TxtStatus.Text = "Parse error."; return; }
            if (!string.IsNullOrEmpty(data.Error)) { TxtStatus.Text = data.Error; return; }

            var items = data.Results.ConvertAll(r => new SearchResultItem(r));
            GridResults.ItemsSource = items;
            TxtStatus.Text = items.Count == 0
                ? Lang.Get("FS_NO_RESULTS")
                : string.Format(Lang.Get("FS_RESULTS"), items.Count);
        });
    }

    private void OnDisconnected(SeroServer.Data.ConnectedClient c)
    {
        if (c.Id != _clientId) return;
        Dispatcher.BeginInvoke(() =>
        {
            _searching = false;
            BtnSearch.IsEnabled = true;
            TxtStatus.Text = Lang.Get("PM_DISCONNECTED");
        });
    }

    private void CopyPath_Click(object s, RoutedEventArgs e)
    {
        if (GridResults.SelectedItem is SearchResultItem item)
            Clipboard.SetText(item.FullPath);
    }

    private void OpenInFm_Click(object s, RoutedEventArgs e)
    {
        if (GridResults.SelectedItem is not SearchResultItem item) return;
        var mainWin = System.Windows.Application.Current.Windows.OfType<ServerWindow>().FirstOrDefault();
        if (mainWin == null) return;
        var dir = item.IsDir ? item.FullPath : System.IO.Path.GetDirectoryName(item.FullPath);
        mainWin.OpenFileManagerAt(_clientId, dir ?? item.FullPath);
    }
}

public class SearchResultItem
{
    public string Name     { get; }
    public string FullPath { get; }
    public string SizeText { get; }
    public string TypeText { get; }
    public bool   IsDir    { get; }

    public SearchResultItem(FmSearchEntry e)
    {
        Name     = e.Name;
        FullPath = e.FullPath;
        IsDir    = e.IsDir;
        TypeText = e.IsDir ? "Dir" : "File";
        SizeText = e.IsDir ? "" : FormatSize(e.Size);
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024)            return $"{bytes} B";
        if (bytes < 1024 * 1024)     return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / 1024.0 / 1024:F1} MB";
        return $"{bytes / 1024.0 / 1024 / 1024:F2} GB";
    }
}
