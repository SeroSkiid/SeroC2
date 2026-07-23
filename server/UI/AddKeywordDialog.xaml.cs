using System.Windows;
using System.Windows.Input;

namespace SeroServer.UI;

public partial class AddKeywordDialog : Window
{
    public string Keyword => TxtKeyword.Text.Trim();

    public AddKeywordDialog(Window owner, string initial = "", string? prompt = null)
    {
        InitializeComponent();
        Owner = owner;
        TxtKeyword.Text = initial;
        LblPrompt.Text  = prompt ?? Lang.Get("WIN_NOTIFY_PROMPT");
        BtnCancel.Content = Lang.Get("BTN_CANCEL");
        BtnOk.Content     = Lang.Get("BTN_OK");
        Loaded += (_, _) => { TxtKeyword.Focus(); TxtKeyword.SelectAll(); };
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Close();

    private void TxtKeyword_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Ok_Click(sender, e);
        if (e.Key == Key.Escape) Close();
    }

    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
