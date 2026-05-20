using System.Windows;
using System.Windows.Input;

namespace SeroServer.UI;

public partial class TagDialog : Window
{
    public string TagValue => TxtTag.Text.Trim();

    public TagDialog(string currentTag = "")
    {
        InitializeComponent();
        TxtTag.Text = currentTag;
        Loaded += (_, _) => { TxtTag.Focus(); TxtTag.SelectAll(); };
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Close();

    private void TxtTag_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter) Ok_Click(sender, e);
        if (e.Key == Key.Escape) Close();
    }

    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
