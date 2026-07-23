using System.Windows;
using System.Windows.Input;

namespace SeroServer.UI;

public partial class CustomAutoTaskDialog : Window
{
    public string TaskName    => TxtName.Text.Trim();
    public string TaskCommand => TxtCmd.Text.Trim();

    public CustomAutoTaskDialog()
    {
        InitializeComponent();
        LblTaskName.Text    = Lang.Get("AT_DLG_TASK_NAME");
        LblCommand.Text     = Lang.Get("AT_DLG_COMMAND");
        BtnCancel.Content   = Lang.Get("BTN_CANCEL");
        BtnAdd.Content      = Lang.Get("AT_DLG_ADD");
        Loaded += (_, _) => { TxtName.Focus(); };
    }

    private void Ok_Click(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(TaskName) || string.IsNullOrWhiteSpace(TaskCommand))
        {
            MessageBox.Show(Lang.Get("TASK_VALIDATE_MSG"), Lang.Get("TASK_VALIDATE_TITLE"),
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        DialogResult = true;
        Close();
    }

    private void Cancel_Click(object sender, RoutedEventArgs e) => Close();

    private void Txt_KeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape) Close();
    }

    private void Window_MouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (e.LeftButton == MouseButtonState.Pressed) DragMove();
    }
}
