using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace SeroServer.UI;

internal static class UiHelpers
{
    internal static ImageSource? DecodeIcon(string b64)
    {
        if (string.IsNullOrEmpty(b64)) return null;
        try
        {
            var bytes = Convert.FromBase64String(b64);
            using var ms = new System.IO.MemoryStream(bytes);
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.CacheOption  = BitmapCacheOption.OnLoad;
            bmp.StreamSource = ms;
            bmp.EndInit();
            bmp.Freeze();
            return bmp;
        }
        catch { return null; }
    }

    internal static string? PromptInput(string title, string hint, string btnLabel, Window? owner = null)
    {
        var res     = Application.Current.Resources;
        var bgBrush     = res["WindowBgBrush"]   as Brush ?? Brushes.Black;
        var fgBrush     = res["ContentTextBrush"] as Brush ?? Brushes.White;
        var labelBrush  = res["FieldLabelBrush"]  as Brush ?? Brushes.Gray;
        var inputBg     = res["InputBgBrush"]     as Brush ?? Brushes.DarkBlue;
        var inputBorder = res["InputBorderBrush"] as Brush ?? Brushes.Gray;

        var win = new Window
        {
            Title = title, Width = 500, Height = 148,
            WindowStyle = WindowStyle.ToolWindow,
            ResizeMode  = ResizeMode.NoResize,
            WindowStartupLocation = owner != null
                ? WindowStartupLocation.CenterOwner
                : WindowStartupLocation.CenterScreen,
            Owner = owner,
            Background = bgBrush
        };

        var hintBlock = new System.Windows.Controls.TextBlock
        {
            Text = hint, Foreground = labelBrush,
            FontSize = 10, Margin = new Thickness(0, 0, 0, 4)
        };
        var tb = new System.Windows.Controls.TextBox
        {
            Background = inputBg, Foreground = fgBrush, BorderBrush = inputBorder,
            CaretBrush = fgBrush, FontSize = 11, Height = 26,
            Margin = new Thickness(0, 0, 0, 8), Padding = new Thickness(6, 0, 6, 0)
        };
        tb.KeyDown += (_, ke) =>
        {
            if (ke.Key == System.Windows.Input.Key.Return) { win.DialogResult = true; win.Close(); }
            if (ke.Key == System.Windows.Input.Key.Escape) { win.Close(); }
        };
        var btn = new System.Windows.Controls.Button
        {
            Content = btnLabel, Height = 28,
            Background  = new SolidColorBrush(Color.FromArgb(80, 0x22, 0xC5, 0x5E)),
            Foreground  = new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E)),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0x22, 0xC5, 0x5E)),
            FontWeight  = FontWeights.SemiBold, FontSize = 11
        };
        btn.Click += (_, _) => { win.DialogResult = true; win.Close(); };

        var stack = new System.Windows.Controls.StackPanel { Margin = new Thickness(12) };
        stack.Children.Add(hintBlock);
        stack.Children.Add(tb);
        stack.Children.Add(btn);
        win.Content = stack;
        win.Loaded += (_, _) => tb.Focus();

        return win.ShowDialog() == true && !string.IsNullOrWhiteSpace(tb.Text) ? tb.Text.Trim() : null;
    }
}
