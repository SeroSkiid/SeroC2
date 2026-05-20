using System.Windows;
using System.Windows.Input;
using SeroServer.Data;

namespace SeroServer.UI;

public partial class ClientLogWindow : Window
{
    public ClientLogWindow(ClientRecord record)
    {
        InitializeComponent();
        TxtTitle.Text = $"— {record.LastUsername}@{record.LastIP} ({record.Hwid[..8]}...)";

        var sb = new System.Text.StringBuilder();
        sb.AppendLine($"HWID:      {record.Hwid}");
        sb.AppendLine($"Tag:       {(string.IsNullOrEmpty(record.Tag) ? "(none)" : record.Tag)}");
        sb.AppendLine($"First Seen: {record.FirstSeen:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Last Seen:  {record.LastSeen:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine(new string('─', 50));
        sb.AppendLine();

        foreach (var entry in record.ActivityLog.AsEnumerable().Reverse().Take(200))
        {
            sb.AppendLine($"[{entry.Time:yyyy-MM-dd HH:mm:ss}] {entry.Action}");
        }

        TxtLog.Text = sb.ToString();
    }

    private void Close_Click(object sender, RoutedEventArgs e) => Close();

    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
