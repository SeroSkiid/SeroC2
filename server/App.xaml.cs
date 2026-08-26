using System.Windows;
using System.Windows.Threading;

namespace SeroServer;

public partial class App : Application
{
    // Wire this up from ServerWindow so exceptions appear live in the log panel
    internal static Action<string>? LiveLog;

    public App()
    {
        // Force software rendering for the entire process — eliminates all UCEERR/DirectComposition
        // crashes that occur with AllowsTransparency windows on VMs and certain GPU drivers.
        System.Windows.Media.RenderOptions.ProcessRenderMode = System.Windows.Interop.RenderMode.SoftwareOnly;

        DispatcherUnhandledException += OnDispatcherException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainException;
    }

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
    }

    private static void OnDispatcherException(object s, DispatcherUnhandledExceptionEventArgs e)
    {
        WriteCrashLog(e.Exception);
        // Suppress DirectComposition rendering errors (UCEERR_MISSINGENDCOMMAND 0x88980411)
        if (e.Exception is System.Runtime.InteropServices.COMException com
            && (uint)com.HResult == 0x88980411)
        {
            e.Handled = true;
            return;
        }
        // Suppress DevExpress/WPF layout rendering crash (ArgumentException from ChromeSlave/ReleaseOnChannel)
        if (e.Exception is ArgumentException
            && e.Exception.Message.StartsWith("Value does not fall within the expected range")
            && e.Exception.StackTrace is { } st
            && (st.Contains("ChromeSlave") || st.Contains("ReleaseOnChannel") || st.Contains("DevExpress.Xpf")))
        {
            e.Handled = true;
            return;
        }
        // Suppress DevExpress Seven Classic internal LinearGradientBrush color validation error
        if (e.Exception is InvalidOperationException
            && e.Exception.Message.Contains("is not a valid value for property 'Color'")
            && e.Exception.StackTrace is { } st2
            && (st2.Contains("LinearGradientBrush") || st2.Contains("GradientStop") || st2.Contains("ManualUpdateResource")))
        {
            e.Handled = true;
            return;
        }
        // Suppress WPF HwndWrapper dispatcher-suspended error from feature windows closing during rendering
        if (e.Exception is InvalidOperationException
            && e.Exception.Message.Contains("Dispatcher processing has been suspended")
            && e.Exception.StackTrace is { } st3
            && st3.Contains("HwndWrapper"))
        {
            e.Handled = true;
            return;
        }
        // Unknown crash — log full details live, show dialog, then let the process terminate.
        // Do NOT set e.Handled = true here: swallowing unknown exceptions lets the app continue
        // in a corrupted state. WPF will terminate after the handler returns.
        var shortMsg = $"{e.Exception?.GetType().Name}: {e.Exception?.Message?.Split('\n')[0]}";
        LiveLog?.Invoke($"[CRASH] {shortMsg}");
        LiveLog?.Invoke($"[CRASH] Stack: {e.Exception?.StackTrace?.Split('\n').FirstOrDefault()?.Trim()}");
        MessageBox.Show(e.Exception?.ToString() ?? "Unknown error",
                        "Crash — voir crash.log", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private static void OnDomainException(object s, UnhandledExceptionEventArgs e)
        => WriteCrashLog(e.ExceptionObject as Exception);

    private void DataGrid_SelectOnClick(object sender, System.Windows.Input.MouseButtonEventArgs e)
    {
        var grid = (System.Windows.Controls.DataGrid)sender;
        var row  = System.Windows.Controls.ItemsControl.ContainerFromElement(grid, e.OriginalSource as DependencyObject) as System.Windows.Controls.DataGridRow;
        // Let DataGrid handle Ctrl/Shift multi-select and toggle natively
        if (System.Windows.Input.Keyboard.Modifiers != System.Windows.Input.ModifierKeys.None) return;
        if (row == null) { grid.UnselectAll(); return; }
        row.IsSelected = true;
        grid.Focus();
    }

    private void DataGrid_EnableRubberBand(object sender, RoutedEventArgs e)
    {
        var grid = (System.Windows.Controls.DataGrid)sender;
        if (grid.SelectionMode == System.Windows.Controls.DataGridSelectionMode.Extended)
            SeroServer.UI.RubberBandSelector.Enable(grid);
    }

    private static void WriteCrashLog(Exception? ex)
    {
        try
        {
            var path = System.IO.Path.Combine(
                System.IO.Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) ?? ".",
                "crash.log");
            System.IO.File.AppendAllText(path,
                $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}]\r\n{ex}\r\n\r\n");
        }
        catch { }
    }
}
