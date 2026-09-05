using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace SeroServer.UI;

public enum WebcamLayout { Tile, Cascade }

public partial class WebcamLayoutDialog : Window
{
    public WebcamLayout SelectedLayout { get; private set; } = WebcamLayout.Tile;
    public bool RememberPreference => ChkRemember.IsChecked == true;

    public static WebcamLayout? Prompt(Window owner)
    {
        int saved = UiPrefs.GetInt("WcamLayout", -1);
        if (saved >= 0) return (WebcamLayout)saved;

        var dlg = new WebcamLayoutDialog { Owner = owner };
        if (dlg.ShowDialog() == true)
        {
            if (dlg.RememberPreference)
                UiPrefs.Set("WcamLayout", (int)dlg.SelectedLayout);
            return dlg.SelectedLayout;
        }
        return null;
    }

    public WebcamLayoutDialog()
    {
        InitializeComponent();
        BtnCancel.Content      = Lang.Get("BTN_CANCEL");
        BtnOk.Content          = Lang.Get("BTN_OK");
        ChkRemember.Content    = Lang.Get("WEBCAM_REMEMBER");
        LblTileWindows.Text    = Lang.Get("WEBCAM_TILE");
        LblCascadeWindows.Text = Lang.Get("WEBCAM_CASCADE");
        UpdateCardVisuals();
    }

    private void UpdateCardVisuals()
    {
        var activeBorder   = SelectedLayout == WebcamLayout.Tile ? CardTile : CardCascade;
        var inactiveBorder = SelectedLayout == WebcamLayout.Tile ? CardCascade : CardTile;

        activeBorder.SetResourceReference(System.Windows.Controls.Border.BorderBrushProperty, "AccentBrush");
        activeBorder.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty,  "SectionBgBrush");

        inactiveBorder.SetResourceReference(System.Windows.Controls.Border.BorderBrushProperty, "SectionBorderBrush");
        inactiveBorder.SetResourceReference(System.Windows.Controls.Border.BackgroundProperty,  "WindowBgBrush");
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
