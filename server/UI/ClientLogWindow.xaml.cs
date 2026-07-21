using System.Windows;
using System.Windows.Documents;
using System.Windows.Media;
using DevExpress.Xpf.Core;
using SeroServer.Data;

namespace SeroServer.UI;

public partial class ClientLogWindow : ThemedWindow
{
    private static readonly Brush _brError   = Frozen(0xEF, 0x44, 0x44);
    private static readonly Brush _brConnect = Frozen(0x4A, 0xDE, 0x80);
    private static readonly Brush _brDisconn = Frozen(0xF9, 0xA8, 0x25);
    private static readonly Brush _brHeader  = Frozen(0x60, 0xA5, 0xFA);
    private static readonly Brush _brDefault = Frozen(0xB8, 0xC0, 0xD8);
    private static readonly Brush _brDim     = Frozen(0x60, 0x68, 0x80);

    private static Brush Frozen(byte r, byte g, byte b)
    {
        var b2 = new SolidColorBrush(Color.FromRgb(r, g, b));
        b2.Freeze();
        return b2;
    }

    public ClientLogWindow(ClientRecord record)
    {
        InitializeComponent();
        TxtTitle.Text = $"— {record.LastUsername}@{record.LastIP} ({record.Hwid[..8]}...)";

        var para = new Paragraph { Margin = new Thickness(0) };
        TxtLog.Document.Blocks.Clear();
        TxtLog.Document.Blocks.Add(para);

        void Add(string text, Brush brush) =>
            para.Inlines.Add(new Run(text) { Foreground = brush });

        Add($"HWID:       {record.Hwid}\n",       _brHeader);
        Add($"Tag:        {(string.IsNullOrEmpty(record.Tag) ? "(none)" : record.Tag)}\n", _brDim);
        string timeFmt = (UiPrefs.GetInt("ShowSeconds", 0) == 1) ? "yyyy-MM-dd h:mm:ss tt" : "yyyy-MM-dd h:mm tt";
        Add($"First Seen: {record.FirstSeen.ToString(timeFmt)}\n", _brDim);
        Add($"Last Seen:  {record.LastSeen.ToString(timeFmt)}\n",  _brDim);
        Add(new string('─', 50) + "\n\n", _brDim);

        foreach (var entry in record.ActivityLog.AsEnumerable().Reverse().Take(200))
        {
            var line = $"[{entry.Time.ToString(timeFmt)}] {entry.Action}\n";
            var brush = entry.Action.Contains("connect", StringComparison.OrdinalIgnoreCase)
                            && !entry.Action.Contains("disconnect", StringComparison.OrdinalIgnoreCase)
                ? _brConnect
                : entry.Action.Contains("disconnect", StringComparison.OrdinalIgnoreCase) ? _brDisconn
                : entry.Action.Contains("error",  StringComparison.OrdinalIgnoreCase)
                  || entry.Action.Contains("fail", StringComparison.OrdinalIgnoreCase) ? _brError
                : _brDefault;
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
