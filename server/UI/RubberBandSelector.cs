using System.Windows;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using DataGrid            = System.Windows.Controls.DataGrid;
using DataGridCell        = System.Windows.Controls.DataGridCell;
using DataGridColumnHeader= System.Windows.Controls.Primitives.DataGridColumnHeader;
using DataGridRow         = System.Windows.Controls.DataGridRow;
using DataGridRowHeader   = System.Windows.Controls.Primitives.DataGridRowHeader;
using ScrollBar           = System.Windows.Controls.Primitives.ScrollBar;

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
    private Point    _origin;
    private Rect     _rect        = Rect.Empty;
    private bool     _active;
    private DateTime _lastSelect  = DateTime.MinValue;

    public RubberBandAdorner(DataGrid grid) : base(grid)
    {
        _grid            = grid;
        IsHitTestVisible = false;

        grid.PreviewMouseLeftButtonDown  += OnDown;
        grid.PreviewMouseMove            += OnMove;
        grid.PreviewMouseLeftButtonUp    += OnUp;
        grid.PreviewMouseRightButtonDown += OnCancel;
        grid.LostMouseCapture            += OnLostCapture;
    }

    private void OnDown(object _, MouseButtonEventArgs e)
    {
        if (HitsRow(e.OriginalSource as DependencyObject)) return;

        _origin = e.GetPosition(_grid);
        _rect   = Rect.Empty;
        _active = true;
        _grid.CaptureMouse();
    }

    private void OnMove(object _, MouseEventArgs e)
    {
        if (!_active || e.LeftButton != MouseButtonState.Pressed) return;

        var cur = e.GetPosition(_grid);
        _rect = new Rect(
            Math.Min(_origin.X, cur.X),
            Math.Min(_origin.Y, cur.Y),
            Math.Abs(cur.X - _origin.X),
            Math.Abs(cur.Y - _origin.Y));

        if (_rect.Width > 4 && _rect.Height > 4)
        {
            var now = DateTime.UtcNow;
            if ((now - _lastSelect).TotalMilliseconds >= 40)
            {
                _lastSelect = now;
                SelectInRect(_rect);
            }
        }

        InvalidateVisual();
    }

    private void OnUp(object _, MouseButtonEventArgs e)
    {
        if (!_active) return;
        _active = false;
        _grid.ReleaseMouseCapture();

        if (_rect.Width > 4 && _rect.Height > 4)
            SelectInRect(_rect);
        else
            _grid.UnselectAll();

        _rect = Rect.Empty;
        InvalidateVisual();
    }

    private void OnCancel(object _, MouseButtonEventArgs e)
    {
        if (!_active) return;
        _active = false;
        _grid.ReleaseMouseCapture();
        _rect = Rect.Empty;
        InvalidateVisual();
    }

    private void OnLostCapture(object _, MouseEventArgs e)
    {
        if (!_active) return;
        _active = false;
        _rect = Rect.Empty;
        InvalidateVisual();
    }

    private void SelectInRect(Rect rect)
    {
        try
        {
            _grid.UnselectAll();
            foreach (var item in _grid.Items)
            {
                if (_grid.ItemContainerGenerator.ContainerFromItem(item) is not DataGridRow row) continue;
                var pos    = row.TranslatePoint(new Point(0, 0), _grid);
                var bounds = new Rect(pos.X, pos.Y, row.ActualWidth, row.ActualHeight);
                if (rect.IntersectsWith(bounds))
                    row.IsSelected = true;
            }
        }
        catch { }
    }

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

    protected override void OnRender(DrawingContext dc)
    {
        if (_rect.IsEmpty || _rect.Width < 1 || _rect.Height < 1) return;

        // Clip to DataGrid bounds so the rectangle doesn't bleed into adjacent panels
        var gridBounds = new Rect(0, 0, _grid.ActualWidth, _grid.ActualHeight);
        var clipped    = Rect.Intersect(_rect, gridBounds);
        if (clipped.IsEmpty) return;

        // Match rubber band to row selection color (set per-theme in ApplyTheme)
        var selColor = (_grid.TryFindResource("RowSelBgBrush") as SolidColorBrush)?.Color
                       ?? Color.FromRgb(0x00, 0x78, 0xD7);
        var fill   = new SolidColorBrush(Color.FromArgb(50,  selColor.R, selColor.G, selColor.B));
        var stroke = new SolidColorBrush(Color.FromArgb(210, selColor.R, selColor.G, selColor.B));
        dc.DrawRectangle(fill, new System.Windows.Media.Pen(stroke, 1.0), clipped);
    }
}
