using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using DataGrid            = System.Windows.Controls.DataGrid;
using DataGridCell        = System.Windows.Controls.DataGridCell;
using DataGridColumnHeader= System.Windows.Controls.Primitives.DataGridColumnHeader;
using DataGridRow         = System.Windows.Controls.DataGridRow;
using DataGridRowHeader   = System.Windows.Controls.Primitives.DataGridRowHeader;
using ScrollBar           = System.Windows.Controls.Primitives.ScrollBar;
using ScrollViewer        = System.Windows.Controls.ScrollViewer;

namespace SeroServer.UI;

internal static class RubberBandSelector
{
    public static void Enable(DataGrid grid)
    {
        void AddAdorner()
        {
            var layer = AdornerLayer.GetAdornerLayer(grid);
            if (layer == null) return;
            var existing = layer.GetAdorners(grid);
            if (existing != null && System.Linq.Enumerable.Any(existing, a => a is RubberBandAdorner)) return;
            layer.Add(new RubberBandAdorner(grid));
        }

        if (grid.IsLoaded) AddAdorner();
        else grid.Loaded += (_, _) => AddAdorner();
    }
}

internal sealed class RubberBandAdorner : Adorner
{
    private readonly DataGrid _grid;

    // Drag state
    private Point    _origin;         // cursor viewport coords at drag start
    private double   _originScrollY;  // scroll offset when drag started
    private Point    _current;        // latest cursor viewport coords
    private Rect     _drawRect = Rect.Empty; // viewport-space rect for rendering
    private bool     _active;
    private DateTime _lastSelect = DateTime.MinValue;

    // Auto-scroll
    private ScrollViewer?    _sv;
    private DispatcherTimer? _scrollTimer;
    private double           _scrollVelocity;

    private const double EdgeZone      = 50.0; // px from edge to start scrolling
    private const double MaxScrollPx   = 14.0; // max px per 16ms tick

    public RubberBandAdorner(DataGrid grid) : base(grid)
    {
        _grid            = grid;
        IsHitTestVisible = false;

        grid.PreviewMouseLeftButtonDown  += OnDown;
        grid.PreviewMouseMove            += OnMove;
        grid.PreviewMouseLeftButtonUp    += OnUp;
        grid.PreviewMouseRightButtonDown += OnCancel;
        grid.LostMouseCapture            += OnLostCapture;
        grid.Loaded += (_, _) => _sv = FindScrollViewer(grid);
    }

    // ── Visual tree helper ────────────────────────────────────────────────────

    private static ScrollViewer? FindScrollViewer(DependencyObject d)
    {
        for (int i = 0; i < VisualTreeHelper.GetChildrenCount(d); i++)
        {
            var child = VisualTreeHelper.GetChild(d, i);
            if (child is ScrollViewer sv) return sv;
            var found = FindScrollViewer(child);
            if (found != null) return found;
        }
        return null;
    }

    // ── Mouse events ──────────────────────────────────────────────────────────

    private void OnDown(object _, MouseButtonEventArgs e)
    {
        if (HitsRow(e.OriginalSource as DependencyObject)) return;

        _sv ??= FindScrollViewer(_grid);
        _origin        = e.GetPosition(_grid);
        _originScrollY = _sv?.VerticalOffset ?? 0;
        _current       = _origin;
        _drawRect      = Rect.Empty;
        _active        = true;
        _grid.CaptureMouse();
    }

    private void OnMove(object _, MouseEventArgs e)
    {
        if (!_active || e.LeftButton != MouseButtonState.Pressed) return;

        _current = e.GetPosition(_grid);
        RefreshDrawRect();
        UpdateAutoScroll(_current.Y);

        if (_drawRect.Width > 4 && _drawRect.Height > 4)
        {
            var now = DateTime.UtcNow;
            if ((now - _lastSelect).TotalMilliseconds >= 40)
            {
                _lastSelect = now;
                SelectInContentRange();
            }
        }

        InvalidateVisual();
    }

    private void OnUp(object _, MouseButtonEventArgs e)
    {
        if (!_active) return;
        StopAutoScroll();
        _active = false;
        _grid.ReleaseMouseCapture();

        if (_drawRect.Width > 4 && _drawRect.Height > 4)
            SelectInContentRange();
        else
            _grid.UnselectAll();

        _drawRect = Rect.Empty;
        InvalidateVisual();
    }

    private void OnCancel(object _, MouseButtonEventArgs e)
    {
        if (!_active) return;
        StopAutoScroll();
        _active = false;
        _grid.ReleaseMouseCapture();
        _drawRect = Rect.Empty;
        InvalidateVisual();
    }

    private void OnLostCapture(object _, MouseEventArgs e)
    {
        if (!_active) return;
        StopAutoScroll();
        _active = false;
        _drawRect = Rect.Empty;
        InvalidateVisual();
    }

    // ── Viewport-space draw rect ──────────────────────────────────────────────
    // The visual origin tracks content: as the user scrolls down, the rubber band's
    // top edge slides upward in viewport space (tracking where the drag started in
    // the content). This keeps the visual rect aligned with selected rows.

    private void RefreshDrawRect()
    {
        double scrollDelta  = (_sv?.VerticalOffset ?? 0) - _originScrollY;
        double visualOriginY = _origin.Y - scrollDelta;

        _drawRect = new Rect(
            Math.Min(_origin.X,    _current.X),
            Math.Min(visualOriginY, _current.Y),
            Math.Abs(_current.X - _origin.X),
            Math.Abs(_current.Y  - visualOriginY));
    }

    // ── Auto-scroll ───────────────────────────────────────────────────────────

    private void UpdateAutoScroll(double cursorY)
    {
        double h = _grid.ActualHeight;
        _scrollVelocity = 0;

        if (cursorY > h - EdgeZone)
            _scrollVelocity = Math.Min(MaxScrollPx, (cursorY - (h - EdgeZone)) / EdgeZone * MaxScrollPx);
        else if (cursorY < EdgeZone)
            _scrollVelocity = Math.Max(-MaxScrollPx, (cursorY - EdgeZone) / EdgeZone * MaxScrollPx);

        if (_scrollVelocity != 0 && _scrollTimer == null)
        {
            _scrollTimer = new DispatcherTimer { Interval = TimeSpan.FromMilliseconds(16) };
            _scrollTimer.Tick += OnScrollTick;
            _scrollTimer.Start();
        }
        else if (_scrollVelocity == 0)
        {
            StopAutoScroll();
        }
    }

    private void OnScrollTick(object? s, EventArgs e)
    {
        if (!_active) { StopAutoScroll(); return; }
        if (_sv != null)
            _sv.ScrollToVerticalOffset(_sv.VerticalOffset + _scrollVelocity);

        RefreshDrawRect();

        if (_drawRect.Width > 4 && _drawRect.Height > 4)
            SelectInContentRange();

        InvalidateVisual();
    }

    private void StopAutoScroll()
    {
        _scrollTimer?.Stop();
        _scrollTimer   = null;
        _scrollVelocity = 0;
    }

    // ── Selection — content-space coordinates ─────────────────────────────────
    // Bug in original: all selection was viewport-space. Rows that had scrolled
    // above the viewport lost their containers (virtualization) and were silently
    // deselected on the next UnselectAll(). Now we convert both origin and current
    // to content-space (Y + scrollOffset), and compare each realized row's
    // content-space Y. Rows that are still virtualized (off-screen and
    // unreachable) are skipped — auto-scroll brings them into the viewport so
    // they become realized before the selection window reaches them.

    private void SelectInContentRange()
    {
        try
        {
            double scrollY = _sv?.VerticalOffset ?? 0;

            // Content-Y = viewportY + scrollOffset at the time the point was measured
            double contentOriginY  = _origin.Y  + _originScrollY;
            double contentCurrentY = _current.Y + scrollY;
            double contentTop    = Math.Min(contentOriginY,  contentCurrentY);
            double contentBottom = Math.Max(contentOriginY,  contentCurrentY);

            _grid.UnselectAll();
            foreach (var item in _grid.Items)
            {
                if (_grid.ItemContainerGenerator.ContainerFromItem(item) is not DataGridRow row) continue;
                double rowViewY    = row.TranslatePoint(new Point(0, 0), _grid).Y;
                double rowContentY = rowViewY + scrollY;
                double rowContentB = rowContentY + Math.Max(row.ActualHeight, 1);
                if (rowContentY < contentBottom && rowContentB > contentTop)
                    row.IsSelected = true;
            }
        }
        catch { }
    }

    // ── Row hit detection ─────────────────────────────────────────────────────

    private static bool HitsRow(DependencyObject? hit)
    {
        while (hit != null)
        {
            if (hit is DataGridCell or DataGridRow or DataGridColumnHeader or DataGridRowHeader) return true;
            if (hit is ScrollBar) return true;
            hit = VisualTreeHelper.GetParent(hit);
        }
        return false;
    }

    // ── Rendering ─────────────────────────────────────────────────────────────

    protected override void OnRender(DrawingContext dc)
    {
        if (_drawRect.IsEmpty || _drawRect.Width < 1 || _drawRect.Height < 1) return;

        var gridBounds = new Rect(0, 0, _grid.ActualWidth, _grid.ActualHeight);
        var clipped    = Rect.Intersect(_drawRect, gridBounds);
        if (clipped.IsEmpty) return;

        var selColor = (_grid.TryFindResource("RowSelBgBrush") as SolidColorBrush)?.Color
                       ?? Color.FromRgb(0x00, 0x78, 0xD7);
        var fill   = new SolidColorBrush(Color.FromArgb(50,  selColor.R, selColor.G, selColor.B));
        var stroke = new SolidColorBrush(Color.FromArgb(210, selColor.R, selColor.G, selColor.B));
        dc.DrawRectangle(fill, new System.Windows.Media.Pen(stroke, 1.0), clipped);
    }
}
