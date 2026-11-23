using PacketLab.Desktop.Localization;
using PacketLab.Analyzers.Annotations;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Input;
using Avalonia.Media;
using static PacketLab.Desktop.ViewStyle;

namespace PacketLab.Desktop;

[TransportModel]
internal readonly record struct CoverageHighlights(int? SelectedOffset, (int Lane, int? Offset)? Hover);

internal sealed class CoverageMatrix : Control
{
    private const double LabelWidth = 136;
    private const double MinBand = 157;
    private const double Header = 24;
    private const double Row = 36;
    private const double ResultGap = 6;
    private static readonly IBrush First = Brush("#C1E5FA");
    private static readonly IBrush Second = Brush("#E0CCEE");
    private static readonly IBrush FillFirst = Brush("#29485A");
    private static readonly IBrush FillSecond = Brush("#483B52");
    private static readonly IBrush Gap = Brush("#232426");
    private static readonly IBrush OverlapFill = Brush("#4D3036");
    private static readonly Pen Hatch = new(Brush("#694049"), 2);
    private static readonly Pen Rule = new(Line);
    private static readonly Pen Dash = new(Line, dashStyle: DashStyle.Dash);
    private readonly CoverageData data;
    private readonly Action<int, int?> choose;
    private Vector offset;
    private Size viewport;
    private int active;
    private CoverageHighlights highlights;
    private int keyboardLane;
    private int keyboardOffset = -1;

    internal CoverageMatrix(CoverageData data, Action<int, int?> choose)
    {
        this.data = data;
        this.choose = choose;
        MinWidth = LabelWidth + MinBand * data.Bands;
        var gap = data.Lanes.LastOrDefault()?.Derived == true ? ResultGap : 0;
        Height = Header + Row * data.Lanes.Count + gap;
        Focusable = true;
        ClipToBounds = true;
        AutomationProperties.SetName(this, Strings.FragmentCoverageAndBytes);
    }

    internal void SetViewport(Vector offset, Size viewport)
    {
        this.offset = offset;
        this.viewport = viewport;
        InvalidateVisual();
    }

    internal void SetSelection(int record, int? payloadOffset)
    {
        active = record;
        highlights = highlights with { SelectedOffset = payloadOffset };
        if (payloadOffset is { } index)
            keyboardOffset = index;
        InvalidateVisual();
    }

    internal static IBrush Swatch(int index) => index % 2 == 0 ? First : Second;

    internal static HexTint? TintAt(CoverageData data, CoverageLane lane, int raw)
    {
        var offset = lane.PayloadOffset(raw);
        if (!lane.Covers(offset))
            return null;

        var position = offset - data.FirstOffset;
        if (data.Owners[position] > 1)
            return new(OverlapFill, Bad, Overlap: true);

        var owner = data.FirstOwner[position];
        var fill = owner % 2 == 0 ? FillFirst : FillSecond;

        return new(fill, Swatch(owner), Overlap: false);
    }

    internal static void DrawTint(DrawingContext context, Rect rect, HexTint tint)
    {
        context.FillRectangle(tint.Fill, rect, 1);
        if (!tint.Overlap)
            return;

        using (context.PushClip(rect))
        {
            for (var stripe = rect.X - rect.Height; stripe < rect.Right; stripe += 6)
                context.DrawLine(Hatch, new Point(stripe, rect.Bottom), new Point(stripe + rect.Height, rect.Top));
        }
        context.DrawLine(new Pen(Bad, 1.5), rect.BottomLeft, rect.BottomRight);
    }

    private double BandWidth => (Bounds.Width - LabelWidth) / data.Bands;

    public override void Render(DrawingContext context)
    {
        var w = BandWidth;
        if (w <= 0)
            return;

        var startBand = Math.Clamp((int)((offset.X - LabelWidth) / w), 0, data.Bands);
        var right = viewport.Width > 0 ? offset.X + viewport.Width : Math.Min(1000, Bounds.Width);
        var endBand = Math.Clamp((int)Math.Ceiling((right - LabelWidth) / w), 0, data.Bands);
        var bottom = viewport.Height > 0 ? offset.Y + viewport.Height : Math.Min(Height, 288);
        var firstLane = Math.Clamp((int)((offset.Y - Header) / Row), 0, data.Lanes.Count);
        var endLane = Math.Clamp((int)Math.Ceiling((bottom - Header) / Row), 0, data.Lanes.Count);
        if (offset.Y < Header)
        {
            HexSurface.Draw(context, Strings.FragmentPayloadOffset, 10, Soft, 0, 3);
            for (var band = startBand; band < endBand; band++)
            {
                var x = LabelWidth + w * band;
                var first = data.FirstOffset + band * 8;
                HexSurface.Draw(context, $"{first}–{first + 7}", 10, Soft, x, 3);
                context.DrawLine(Rule, new Point(x, 18), new Point(x + w - 8, 18));
            }
        }
        for (var n = firstLane; n < endLane; n++)
        {
            var y = Header + n * Row;
            if (data.Lanes[n].Derived)
                y += ResultGap;

            DrawLabel(context, data.Lanes[n], n, y);
            for (var band = startBand; band < endBand; band++)
                DrawBand(context, data.Lanes[n], band, y, w);
        }
    }

    private void DrawLabel(DrawingContext context, CoverageLane lane, int index, double y)
    {
        if (lane.Derived)
            context.DrawLine(Dash, new Point(0, y - 1), new Point(Bounds.Width, y - 1));
        if (lane.Record == active)
            context.FillRectangle(Lift, new Rect(0, y + 1,
                LabelWidth - 8,
                    Row - 3), 3);
        context.FillRectangle(Swatch(index), new Rect(4, y + 6, 7, 7), 2);
        HexSurface.Draw(context, lane.Label, 12, Text, 18, y);
        HexSurface.Draw(context, lane.Scope, 10, Muted, 18, y + 15);
    }

    private void DrawBand(DrawingContext context, CoverageLane lane, int band, double y, double width)
    {
        var cellWidth = (width - 8) / 8;
        var x = LabelWidth + band * width;
        for (var cell = 0; cell < 8; cell++)
        {
            var position = band * 8 + cell;
            var offsetInPayload = data.FirstOffset + position;
            var rect = new Rect(x + cell * cellWidth,
                y + 3,
                    cellWidth - 1, 23);
            var available = lane.Covers(offsetInPayload);
            var tint = available ? TintAt(data, lane, lane.RawIndex(offsetInPayload)) : null;
            if (tint is { } chosen)
                DrawTint(context, rect, chosen);
            else
                context.FillRectangle(Gap, rect, 1);

            if (available && IsPointed(lane, offsetInPayload))
                context.DrawRectangle(null, new Pen(Text, 2), rect.Deflate(1));
            var value = available ? lane.Bytes[offsetInPayload - lane.Slice.Offset].ToString("X2") : "·";
            var brush = tint?.Foreground ?? Soft;
            HexSurface.Center(context, HexSurface.MakeText(value, 12, brush), rect.Center.X,
                rect.Y + 3);
        }
    }

    private bool IsPointed(CoverageLane lane, int payload) =>
        highlights.SelectedOffset == payload || highlights.Hover is { Offset: { } offset } hit &&
            offset == payload && data.Lanes[hit.Lane].Record == lane.Record;

    protected override void OnPointerPressed(PointerPressedEventArgs e)
    {
        base.OnPointerPressed(e);
        if (!e.GetCurrentPoint(this).Properties.IsLeftButtonPressed || Locate(e.GetPosition(this)) is not { } hit)
            return;

        Focus();
        keyboardLane = hit.Lane;
        keyboardOffset = hit.Offset ?? -1;
        Pick(hit.Lane, hit.Offset);
        e.Handled = true;
    }

    protected override void OnPointerMoved(PointerEventArgs e)
    {
        base.OnPointerMoved(e);
        var hit = Locate(e.GetPosition(this));
        if (highlights.Hover == hit)
            return;

        highlights = highlights with { Hover = hit };
        string? tooltip = null;
        if (hit is { Offset: { } offsetInPayload } located)
        {
            var lane = data.Lanes[located.Lane];
            var raw = lane.RawIndex(offsetInPayload);
            var value = lane.Bytes[offsetInPayload - lane.Slice.Offset];
            tooltip = UiText.Format(Strings.FragmentByteTooltip, lane.Label, raw, offsetInPayload, value);
        }
        ToolTip.SetTip(this, tooltip);
        InvalidateVisual();
    }

    protected override void OnPointerExited(PointerEventArgs e)
    {
        base.OnPointerExited(e);
        highlights = highlights with { Hover = null };
        ToolTip.SetTip(this, null);
        InvalidateVisual();
    }

    protected override void OnKeyDown(KeyEventArgs e)
    {
        base.OnKeyDown(e);
        if (data.Lanes.Count == 0)
            return;

        var lane = data.Lanes[keyboardLane];
        switch (e.Key)
        {
            case Key.Up:
                keyboardLane = Math.Max(0, keyboardLane - 1);
                break;

            case Key.Down:
                keyboardLane = Math.Min(data.Lanes.Count - 1, keyboardLane + 1);
                break;

            case Key.Left:
                keyboardOffset = keyboardOffset <= lane.Slice.Offset ? -1 : keyboardOffset - 1;
                break;

            case Key.Right:
                keyboardOffset = Math.Max(lane.Slice.Offset, keyboardOffset + 1);
                break;

            case Key.Home:
                keyboardOffset = -1;
                break;

            case Key.Enter:
            case Key.Space:
                break;

            default:
                return;
        }
        lane = data.Lanes[keyboardLane];
        if (keyboardOffset >= 0 && lane.Bytes.Length > 0)
        {
            var last = lane.Slice.Offset + lane.Bytes.Length - 1;
            keyboardOffset = Math.Clamp(keyboardOffset, lane.Slice.Offset, last);
        }
        Pick(keyboardLane, lane.Covers(keyboardOffset) ? keyboardOffset : null);
        e.Handled = true;
    }

    private void Pick(int laneIndex, int? payloadOffset)
    {
        var lane = data.Lanes[laneIndex];
        var raw = payloadOffset is { } payload ? lane.RawIndex(payload) : (int?)null;
        choose(lane.Record, raw);
    }

    private (int Lane, int? Offset)? Locate(Point position)
    {
        var rowIndex = (int)Math.Floor((position.Y - Header) / Row);
        var resultRow = data.Lanes.Count - 1;
        if (rowIndex > resultRow && data.Lanes.LastOrDefault()?.Derived == true && position.Y < Height)
            rowIndex = resultRow;
        if ((uint)rowIndex >= (uint)data.Lanes.Count)
            return null;
        if (position.X < LabelWidth)
            return (rowIndex, null);

        var x = position.X - LabelWidth;
        var band = (int)(x / BandWidth);
        var cell = (int)((x - band * BandWidth) / ((BandWidth - 8) / 8));
        var offsetInPayload = data.FirstOffset + band * 8 + cell;
        if (cell >= 8 || !data.Lanes[rowIndex].Covers(offsetInPayload))
            return null;

        return (rowIndex, offsetInPayload);
    }
}
