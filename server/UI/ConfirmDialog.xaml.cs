using System.Windows;
using System.Windows.Input;

namespace SeroServer.UI;

public partial class ConfirmDialog : Window
{
    public ConfirmDialog(string title, string message, string yesLabel = "YES", string noLabel = "NO")
    {
        InitializeComponent();
        TxtTitle.Text   = title;
        TxtMessage.Text = message;
        BtnYes.Content  = yesLabel.ToUpper();
        BtnNo.Content   = noLabel.ToUpper();
    }

    private void Yes_Click(object s, RoutedEventArgs e) { DialogResult = true; Close(); }
    private void No_Click (object s, RoutedEventArgs e) => Close();

    private void Window_MouseLeftButtonDown(object s, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
