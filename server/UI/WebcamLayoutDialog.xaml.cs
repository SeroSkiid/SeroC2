using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace SeroServer.UI;

public enum WebcamLayout { Tile, Cascade }

public partial class WebcamLayoutDialog : Window
{
    // Session-only remembered preference (resets on app restart)
    private static WebcamLayout? s_rememberedLayout;
    private static bool s_remembered;

    public WebcamLayout SelectedLayout { get; private set; } = WebcamLayout.Tile;
    public bool RememberPreference => ChkRemember.IsChecked == true;

    /// <summary>
    /// Returns the layout to use. If a preference was remembered this session,
    /// returns it immediately without showing the dialog. Otherwise shows the dialog.
    /// Returns null if the user cancelled.
    /// </summary>
    public static WebcamLayout? Prompt(Window owner)
    {
        if (s_remembered && s_rememberedLayout.HasValue)
            return s_rememberedLayout.Value;

        var dlg = new WebcamLayoutDialog { Owner = owner };
        if (dlg.ShowDialog() == true)
        {
            if (dlg.RememberPreference)
            {
                s_remembered = true;
                s_rememberedLayout = dlg.SelectedLayout;
            }
            return dlg.SelectedLayout;
        }
        return null;
    }

    public WebcamLayoutDialog()
    {
        InitializeComponent();
        UpdateCardVisuals();
    }

    private void UpdateCardVisuals()
    {
        var activeBorder = SelectedLayout == WebcamLayout.Tile
            ? CardTile : CardCascade;
        var inactiveBorder = SelectedLayout == WebcamLayout.Tile
            ? CardCascade : CardTile;

        activeBorder.BorderBrush = new SolidColorBrush(
            SelectedLayout == WebcamLayout.Tile
                ? Color.FromRgb(0x4A, 0x85, 0xF5)
                : Color.FromRgb(0x7C, 0x5C, 0xE8));
        activeBorder.Background = new SolidColorBrush(
            Color.FromRgb(0x16, 0x18, 0x35));

        inactiveBorder.BorderBrush = new SolidColorBrush(
            Color.FromRgb(0x1E, 0x20, 0x38));
        inactiveBorder.Background = new SolidColorBrush(
            Color.FromRgb(0x12, 0x14, 0x2A));
    }

    private void CardTile_Click(object s, MouseButtonEventArgs e)
    {
        SelectedLayout = WebcamLayout.Tile;
        UpdateCardVisuals();
    }

    private void CardCascade_Click(object s, MouseButtonEventArgs e)
    {
        SelectedLayout = WebcamLayout.Cascade;
        UpdateCardVisuals();
    }

    private void Ok_Click(object s, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object s, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }

    private void TitleBar_Drag(object s, MouseButtonEventArgs e) => DragMove();
}
