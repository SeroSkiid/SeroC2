using System.Windows;
using System.Windows.Input;
using DevExpress.Xpf.Core;

namespace SeroServer.UI;

public partial class FileEditorWindow : ThemedWindow
{
    private readonly string _fileName;
    private readonly string _fullPath;
    private readonly Func<string, Task<bool>> _saveCallback;
    private bool _modified;
    private bool _saving;

    public FileEditorWindow(string fileName, string fullPath, string initialText, Func<string, Task<bool>> saveCallback)
    {
        InitializeComponent();
        _fileName     = fileName;
        _fullPath     = fullPath;
        _saveCallback = saveCallback;

        TxtEditor.Text = initialText;
        TxtFilePath.Text = fullPath;
        _modified = false;
        UpdateTitle();

        Lang.LanguageChanged += ApplyLanguage;
        ApplyLanguage();
    }

    private void ApplyLanguage()
    {
        if (!Dispatcher.CheckAccess()) { Dispatcher.BeginInvoke(ApplyLanguage); return; }
        if (BtnSave   != null) BtnSave.Content       = Lang.Get("FM_EDITOR_SAVE");
        if (ChkWordWrap!=null) ChkWordWrap.Content    = Lang.Get("FM_EDITOR_WORD_WRAP");
        UpdateTitle();
    }

    private void UpdateTitle()
    {
        Title = (_modified ? "* " : "") + _fileName + " — " + Lang.Get("FM_EDIT");
    }

    private void TxtEditor_TextChanged(object s, System.Windows.Controls.TextChangedEventArgs e)
    {
        if (!_modified)
        {
            _modified = true;
            UpdateTitle();
        }
    }

    private void TxtEditor_SelectionChanged(object s, RoutedEventArgs e)
    {
        var tb = TxtEditor;
        var idx = tb.SelectionStart;
        var text = tb.Text;
        int line = 1, col = 1;
        for (int i = 0; i < idx && i < text.Length; i++)
        {
            if (text[i] == '\n') { line++; col = 1; }
            else col++;
        }
        if (TxtCaret != null) TxtCaret.Text = $"Ln {line}, Col {col}";
    }

    private void TxtEditor_KeyDown(object s, KeyEventArgs e)
    {
        if (e.Key == Key.S && (Keyboard.Modifiers & ModifierKeys.Control) == ModifierKeys.Control)
        {
            e.Handled = true;
            _ = SaveAsync();
        }
    }

    private void ChkWordWrap_Changed(object s, RoutedEventArgs e)
    {
        TxtEditor.TextWrapping = ChkWordWrap.IsChecked == true
            ? System.Windows.TextWrapping.Wrap
            : System.Windows.TextWrapping.NoWrap;
        TxtEditor.HorizontalScrollBarVisibility = ChkWordWrap.IsChecked == true
            ? System.Windows.Controls.ScrollBarVisibility.Disabled
            : System.Windows.Controls.ScrollBarVisibility.Auto;
    }

    private async void BtnSave_Click(object s, RoutedEventArgs e) => await SaveAsync();

    private async Task SaveAsync()
    {
        if (_saving) return;
        _saving = true;
        BtnSave.IsEnabled = false;
        if (TxtStatus != null) TxtStatus.Text = Lang.Get("FM_EDITOR_LOADING");
        try
        {
            var text = TxtEditor.Text;
            var ok = await _saveCallback(text);
            if (ok)
            {
                _modified = false;
                UpdateTitle();
                if (TxtStatus != null) TxtStatus.Text = Lang.Get("FM_EDITOR_SAVED");
            }
            else
            {
                if (TxtStatus != null) TxtStatus.Text = string.Format(Lang.Get("FM_EDITOR_SAVE_FAILED"), "Server returned error");
            }
        }
        catch (Exception ex)
        {
            if (TxtStatus != null) TxtStatus.Text = string.Format(Lang.Get("FM_EDITOR_SAVE_FAILED"), ex.Message);
        }
        finally
        {
            _saving = false;
            BtnSave.IsEnabled = true;
        }
    }

    private void Window_Closing(object s, System.ComponentModel.CancelEventArgs e)
    {
        if (_modified)
        {
            var result = MessageBox.Show(
                Lang.Get("FM_EDITOR_MODIFIED"),
                Lang.Get("MSG_CONFIRM"),
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning);
            if (result != MessageBoxResult.Yes)
                e.Cancel = true;
        }
        if (!e.Cancel)
            Lang.LanguageChanged -= ApplyLanguage;
    }
}
