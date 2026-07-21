using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;

namespace SeroServer.UI;

/// <summary>
/// Enables native 8-direction resize for WindowStyle=None windows by intercepting WM_NCHITTEST.
/// Call WindowResizer.Enable(this) in any window's constructor or Loaded handler.
/// </summary>
internal static class WindowResizer
{
    private const int WM_NCHITTEST = 0x0084;
    private const int HTLEFT        = 10;
    private const int HTRIGHT       = 11;
    private const int HTTOP         = 12;
    private const int HTTOPLEFT     = 13;
    private const int HTTOPRIGHT    = 14;
    private const int HTBOTTOM      = 15;
    private const int HTBOTTOMLEFT  = 16;
    private const int HTBOTTOMRIGHT = 17;
    private const int HTCLIENT      = 1;
    private const int GripSize      = 8; // pixels from edge

    [DllImport("user32.dll")] private static extern bool GetCursorPos(out POINT pt);
    [DllImport("user32.dll")] private static extern bool GetWindowRect(nint hWnd, out RECT lpRect);
    [StructLayout(LayoutKind.Sequential)] private struct POINT { public int X, Y; }
    [StructLayout(LayoutKind.Sequential)] private struct RECT  { public int Left, Top, Right, Bottom; }

    public static void Enable(Window window)
    {
        window.SourceInitialized += (_, _) =>
        {
            var hwndSource = HwndSource.FromHwnd(new WindowInteropHelper(window).Handle);
            hwndSource?.AddHook((nint hwnd, int msg, nint wp, nint lp, ref bool handled) =>
            {
                if (msg != WM_NCHITTEST) return 0;
                if (window.WindowState == WindowState.Maximized) return 0;

                GetCursorPos(out var pt);

                // GetWindowRect returns the window bounds in physical device pixels —
                // the same coordinate space as GetCursorPos. This avoids any DPI
                // conversion math and works correctly on every monitor regardless of
                // per-monitor DPI scaling (125 %, 150 %, mixed setups, etc.).
                GetWindowRect(hwnd, out var wr);

                // Scale the logical grip size to physical pixels so the grabbable
                // border stays the same visual size at any DPI setting.
                double dpi     = hwndSource.CompositionTarget?.TransformToDevice.M11 ?? 1.0;
                double physGrip = GripSize * dpi;

                bool onLeft   = pt.X <= wr.Left   + physGrip;
                bool onRight  = pt.X >= wr.Right  - physGrip;
                bool onTop    = pt.Y <= wr.Top    + physGrip;
                bool onBottom = pt.Y >= wr.Bottom - physGrip;

                if (onTop    && onLeft)  { handled = true; return HTTOPLEFT;     }
                if (onTop    && onRight) { handled = true; return HTTOPRIGHT;    }
                if (onBottom && onLeft)  { handled = true; return HTBOTTOMLEFT;  }
                if (onBottom && onRight) { handled = true; return HTBOTTOMRIGHT; }
                if (onLeft)              { handled = true; return HTLEFT;        }
                if (onRight)             { handled = true; return HTRIGHT;       }
                if (onTop)               { handled = true; return HTTOP;         }
                if (onBottom)            { handled = true; return HTBOTTOM;      }

                return 0;
            });
        };
    }
}
