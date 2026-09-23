using System.Windows.Controls;
using System.Windows.Input;

namespace SeroServer.UI;

// Type-to-select for DataGrids: press a letter to jump to first match,
// press the same letter again (within 1.5s) to cycle to the next match.
internal static class TypeToSelect
{
    public static void Enable(DataGrid grid, Func<object, string> getKey)
    {
        char     lastChar  = '\0';
        DateTime lastTime  = DateTime.MinValue;
        int      matchIdx  = -1;

        grid.PreviewTextInput += (_, e) =>
        {
            if (string.IsNullOrEmpty(e.Text)) return;
            char ch = char.ToUpperInvariant(e.Text[0]);
            if (!char.IsLetterOrDigit(ch) && ch != '_') return;

            var now = DateTime.UtcNow;
            bool sameChar = ch == lastChar && (now - lastTime).TotalMilliseconds < 1500;
            lastChar = ch;
            lastTime = now;

            var items = grid.Items.Cast<object>().ToList();
            if (items.Count == 0) return;

            int startIdx = sameChar && matchIdx >= 0 && matchIdx < items.Count
                ? (matchIdx + 1) % items.Count
                : 0;

            for (int i = 0; i < items.Count; i++)
            {
                int idx = (startIdx + i) % items.Count;
                var key = getKey(items[idx]);
                if (!string.IsNullOrEmpty(key) && char.ToUpperInvariant(key[0]) == ch)
                {
                    matchIdx = idx;
                    grid.SelectedItem = items[idx];
                    grid.ScrollIntoView(items[idx]);
                    e.Handled = true;
                    return;
                }
            }
        };

        // Reset cycle state when selection changes by other means (mouse click, etc.)
        grid.SelectionChanged += (_, _) =>
        {
            var sel = grid.SelectedItem;
            if (sel == null) { matchIdx = -1; return; }
            var items = grid.Items.Cast<object>().ToList();
            int idx = items.IndexOf(sel);
            if (idx != matchIdx) { matchIdx = idx; lastChar = '\0'; }
        };
    }
}
