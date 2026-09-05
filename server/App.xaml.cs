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
        // Check all known non-fatal exceptions first — suppress silently, no log spam.
        if (IsSuppressibleException(e.Exception))
        {
            e.Handled = true;
            return;
        }
        // Unknown crash — write to disk, surface live, show dialog, then let WPF terminate.
        // Do NOT set e.Handled = true: swallowing unknown exceptions lets the app continue
        // in a corrupted state.
        WriteCrashLog(e.Exception);
        var shortMsg = $"{e.Exception?.GetType().Name}: {e.Exception?.Message?.Split('\n')[0]}";
        LiveLog?.Invoke($"[CRASH] {shortMsg}");
        LiveLog?.Invoke($"[CRASH] Stack: {e.Exception?.StackTrace?.Split('\n').FirstOrDefault()?.Trim()}");
        MessageBox.Show(e.Exception?.ToString() ?? "Unknown error",
                        "Crash — voir crash.log", MessageBoxButton.OK, MessageBoxImage.Error);
    }

    private static bool IsSuppressibleException(Exception? ex)
    {
        if (ex == null) return false;
        // DirectComposition rendering error (UCEERR_MISSINGENDCOMMAND 0x88980411)
        if (ex is System.Runtime.InteropServices.COMException com
            && (uint)com.HResult == 0x88980411)
            return true;
        // DevExpress/WPF layout rendering crash (ChromeSlave / ReleaseOnChannel)
        if (ex is ArgumentException
            && ex.Message.StartsWith("Value does not fall within the expected range")
            && ex.StackTrace is { } st
            && (st.Contains("ChromeSlave") || st.Contains("ReleaseOnChannel") || st.Contains("DevExpress.Xpf")))
            return true;
        // DevExpress Seven Classic LinearGradientBrush color validation error
        if (ex is InvalidOperationException
            && ex.Message.Contains("is not a valid value for property 'Color'")
            && ex.StackTrace is { } st2
            && (st2.Contains("LinearGradientBrush") || st2.Contains("GradientStop") || st2.Contains("ManualUpdateResource")))
            return true;
        // WPF HwndWrapper dispatcher-suspended during feature-window close
        if (ex is InvalidOperationException
            && ex.Message.Contains("Dispatcher processing has been suspended")
            && ex.StackTrace is { } st3
            && st3.Contains("HwndWrapper"))
            return true;
        // WPF Storyboard name-scope failure on column-header drag phantom
        if (ex is InvalidOperationException
            && ex.Message.Contains("cannot be found in the name scope")
            && ex.StackTrace is { } st4
            && (st4.Contains("Storyboard") || st4.Contains("DataGridColumnHeader")))
            return true;
        // WPF DataGrid star-column infinity crash during column resize drag.
        // Star column (TAG Width="*") inside HorizontalScrollBarVisibility=Auto ScrollViewer
        // gets displayWidth=Infinity on the first measure pass; dragging any other column
        // smaller triggers UpdateWidthForStarColumn(Infinity) → ArgumentException.
        // The drag simply stops — no data loss, no corruption.
        if (ex is ArgumentException
            && ex.Message.Contains("Value should not be infinity")
            && ex.StackTrace is { } stStar
            && (stStar.Contains("UpdateWidthForStarColumn") || stStar.Contains("ReallocateStarValues")))
            return true;
        return false;
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
