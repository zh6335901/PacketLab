using PacketLab.Desktop.Localization;
using PacketLab.Analyzers.Annotations;
using System.Globalization;
using System.Runtime.CompilerServices;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using PacketLab.Desktop.Models.PacketExplorer;
using static PacketLab.Desktop.Controls.PacketExplorer.ViewStyle;

namespace PacketLab.Desktop.Controls.PacketExplorer;

internal readonly record struct HexTint(IBrush Fill, IBrush Foreground, bool Overlap);

internal sealed class HexView : Grid
{
    private readonly HexSurface surface;
    private readonly ScrollBar bar;
    private readonly int columns;
    private readonly int visibleRows;

    internal HexView(byte[] bytes, bool compact, Action<int> onPicked, Func<int, HexTint?>? tintAt = null)
    {
        columns = compact ? 8 : 16;
        var rows = (bytes.Length + columns - 1) / columns;
        visibleRows = Math.Min(rows, compact ? 18 : 12);
        surface = new HexSurface(bytes, compact, onPicked, Reveal, tintAt)
        {
            Height = (compact ? 0 : 25) + visibleRows * (compact ? 19 : 24),
            Focusable = true
        };
        AutomationProperties.SetName(surface, compact ? Strings.FullBytes : Strings.HexAndAscii);
        bar = new ScrollBar
        {
            Orientation = Orientation.Vertical, SmallChange = 1, LargeChange = visibleRows, ViewportSize = visibleRows,
            Maximum = rows - visibleRows, IsVisible = rows > visibleRows
        };
        bar.ValueChanged += (_, _) => surface.ScrollTo((int)bar.Value);
        ColumnDefinitions = new ColumnDefinitions("*,Auto");
        Children.Add(surface);
        SetColumn(bar, 1);
        Children.Add(bar);
        PointerWheelChanged += (_, e) =>
        {
            var previous = bar.Value;
            bar.Value = Math.Clamp(previous - Math.Sign(e.Delta.Y) * 3, 0, bar.Maximum);
            e.Handled = bar.Value != previous;
        };
    }

    internal void SetSelection(ByteRange? range, int? exact, bool reveal)
    {
        surface.SetSelection(range, exact);
        if (reveal && (exact ?? range?.Start) is { } offset)
            Reveal(offset);
    }

    private void Reveal(int offset)
    {
        var row = offset / columns;
        if (row < bar.Value)
            bar.Value = row;
        else if (row >= bar.Value + visibleRows)
            bar.Value = Math.Min(bar.Maximum, row - visibleRows + 1);
    }
}

[TransportModel]
internal readonly record struct HexSelection(ByteRange? Range, int? Exact);

internal sealed class HexSurface : Control
{
    private static readonly Typeface Typeface = new(Mono);
    private static readonly string[] Hex = Enumerable.Range(0, 256).Select(value => value.ToString("X2")).ToArray();
    // Formatted text can retain typefaces owned by the current application's font manager.
    private static readonly ConditionalWeakTable<FontManager, ByteTextCache> TextCaches = new();
    private readonly byte[] bytes;
    private readonly Action<int> onPicked;
    private readonly int columns;
    private readonly double headerHeight;
    private readonly double rowHeight;
    private readonly double offsetWidth;
    private readonly double asciiWidth;
    private readonly Action<int> reveal;
    private readonly IBrush background;
    private readonly Func<int, HexTint?>? tintAt;
    private HexSelection selection;
    private int startRow;
    private int keyboardIndex;

    internal HexSurface(byte[] bytes, bool compact, Action<int> onPicked, Action<int> reveal, Func<int, HexTint?>? tintAt)
    {
        this.bytes = bytes;
        this.onPicked = onPicked;
        this.reveal = reveal;
        this.tintAt = tintAt;
        background = compact ? Bg : PanelBrush;
        columns = compact ? 8 : 16;
        headerHeight = compact ? 0 : 25;
        rowHeight = compact ? 19 : 24;
        offsetWidth = compact ? 39 : 40;
        asciiWidth = compact ? 60 : 101;
        ClipToBounds = true;
    }

    internal void ScrollTo(int row)
    {
        startRow = row;
        InvalidateVisual();
    }

    internal void SetSelection(ByteRange? range, int? exact)
    {
        selection = new(range, exact);
        keyboardIndex = exact ?? range?.Start ?? 0;
        InvalidateVisual();
    }

    private double CellWidth
    {
        get
        {
            var usableWidth = Bounds.Width - offsetWidth - asciiWidth - 5;

            return Math.Max(10, usableWidth / columns);
        }
    }

    public override void Render(DrawingContext context)
    {
        var textCache = TextCaches.GetValue(FontManager.Current, static _ => new ByteTextCache());
        var area = new Rect(Bounds.Size);
        context.FillRectangle(background, area);
        var width = CellWidth;
        var asciiStart = offsetWidth + width * columns + 5;
        var asciiCell = asciiWidth / columns;
        if (headerHeight > 0)
        {
            Draw(context, Strings.ByteOffset, 10, Soft, 0, 4);
            Draw(context, "ASCII", 10, Soft, asciiStart, 4);
            for (var col = 0; col < columns; col++)
            {
                var center = offsetWidth + width * (col + .5);
                Center(context, MakeText(Hex[col], 10, Soft), center, 4);
            }
        }
        var rowsToDraw = (int)Math.Ceiling((area.Height - headerHeight) / rowHeight);
        for (var line = 0; line < rowsToDraw; line++)
        {
            var start = (startRow + line) * columns;
            if (start >= bytes.Length)
                break;

            var y = headerHeight + rowHeight * line;
            Draw(context, start.ToString("X4"), 11, Soft, 0,
                y + 4);
            context.DrawLine(new Pen(Line), new Point(asciiStart - 4, y + 1), new Point(asciiStart - 4, y + rowHeight - 2));
            for (var col = 0; col < columns && start + col < bytes.Length; col++)
            {
                var index = start + col;
                var byteValue = bytes[index];
                var selected = selection.Range?.Contains(index) == true;
                var x = offsetWidth + width * col;
                var asciiX = asciiStart + asciiCell * col;
                var hexRect = new Rect(x, y + 1, width,
                    rowHeight - 2);
                var tint = tintAt?.Invoke(index);
                if (tint is { } color)
                    CoverageMatrix.DrawTint(context, hexRect, color);
                if (selected)
                {
                    context.FillRectangle(Accent, hexRect);
                    context.FillRectangle(Accent, new Rect(asciiX, y + 1, asciiCell,
                        rowHeight - 2));
                }
                if (selection.Exact == index)
                    context.DrawRectangle(null, new Pen(Text, 1.5), hexRect.Deflate(1));

                var byteText = (selected, tint) switch
                {
                    (true, _) => textCache.MarkedBytes[byteValue],
                    (false, { } tone) => MakeText(Hex[byteValue], 12, tone.Foreground),
                    _ => textCache.Bytes[byteValue]
                };
                Center(context, byteText,
                    x + width / 2,
                        y + 3);
                Center(context, selected ? textCache.MarkedAscii[byteValue] : textCache.Ascii[byteValue],
                    asciiX + asciiCell / 2,
                        y + 3);
            }
        }
    }

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed || ByteAt(e.GetPosition(this)) is not { } index)
            return;

        Focus();
        keyboardIndex = index;
        onPicked(index);
        e.Handled = true;
    }

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        var offset = ByteAt(e.GetPosition(this));
        var tip = offset is { } index ? $"0x{index:X4} · {Hex[bytes[index]]}" : null;
        if (ToolTip.GetTip(this) as string != tip)
            ToolTip.SetTip(this, tip);
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (bytes.Length == 0)
            return;

        var next = e.Key switch
        {
            Key.Left => keyboardIndex - 1, Key.Right => keyboardIndex + 1,
            Key.Up => keyboardIndex - columns, Key.Down => keyboardIndex + columns,
            Key.Home => 0, Key.End => bytes.Length - 1,
            Key.PageUp => keyboardIndex - columns * 12, Key.PageDown => keyboardIndex + columns * 12,
            _ => -1
        };
        if (next < 0 && e.Key is not (Key.Left or Key.Up or Key.PageUp))
            return;

        keyboardIndex = Math.Clamp(next, 0, bytes.Length - 1);
        onPicked(keyboardIndex);
        reveal(keyboardIndex);
        e.Handled = true;
    }

    private int? ByteAt(Point point)
    {
        if (point.X < offsetWidth || point.Y < headerHeight)
            return null;

        var asciiStart = offsetWidth + columns * CellWidth + 5;
        var cell = point.X < asciiStart ? (point.X - offsetWidth) / CellWidth : (point.X - asciiStart) / (asciiWidth / columns);
        var row = startRow + (int)((point.Y - headerHeight) / rowHeight);
        var index = row * columns + (int)cell;

        return (uint)index < (uint)bytes.Length && cell < columns ? index : null;
    }

    private static string ToAscii(int value) => value is >= 32 and < 127 ? ((char)value).ToString() : "·";

    internal static FormattedText MakeText(string content, double size, IBrush brush) =>
        new(content, CultureInfo.InvariantCulture, FlowDirection.LeftToRight, Typeface, size, brush);

    internal static void Draw(DrawingContext context, string text, double fontSize, IBrush brush, double x, double y) =>
        context.DrawText(MakeText(text, fontSize, brush), new Point(x, y));

    internal static void Center(DrawingContext context, FormattedText text, double x, double y) =>
        context.DrawText(text, new Point(x - text.Width / 2, y));

    private sealed class ByteTextCache
    {
        internal readonly FormattedText[] Bytes = Hex.Select(word => MakeText(word, 12, Text)).ToArray();
        internal readonly FormattedText[] MarkedBytes = Hex.Select(word => MakeText(word, 12, PanelBrush)).ToArray();
        internal readonly FormattedText[] Ascii = Enumerable.Range(0, 256).Select(value => MakeText(ToAscii(value), 12, Muted)).ToArray();
        internal readonly FormattedText[] MarkedAscii = Enumerable.Range(0, 256).Select(value => MakeText(ToAscii(value), 12, PanelBrush)).ToArray();
    }
}
