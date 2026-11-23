using Avalonia.Controls;
using Avalonia.Layout;
using static PacketLab.Desktop.ViewStyle;

namespace PacketLab.Desktop;

internal sealed class RecordRow : Border
{
    private readonly Border edge = new() { Width = 3, HorizontalAlignment = HorizontalAlignment.Left, Background = Accent };
    private readonly TextBlock number;
    private readonly TextBlock fragment;
    private readonly TextBlock time;
    private readonly TextBlock route;
    private readonly int index;
    private readonly CaptureRecord record;
    private readonly FragmentGroup? group;

    internal RecordRow(IndexedRow row, int selected, FragmentGroup? selectedGroup)
    {
        index = row.Index;
        record = row.Record;
        group = row.Group;
        var summary = record.Summary;
        var title = RecordStatus.Title(record, group, index);
        var status = RecordStatus.ForRecord(record, group, index);
        var timeText = record.Time.Format();
        number = Label(RecordStatus.Number(index), 11, mono: true, weight: Demi);
        var protocol = Label(summary.Name, 11, ProtocolBrush(summary.Protocol), mono: true, weight: Demi);
        time = Label(timeText, 10, Muted, mono: true);
        time.MaxWidth = 148;
        var headline = LayoutGrid("Auto,*,Auto", number, protocol, time);
        headline.ColumnSpacing = 6;
        fragment = Label("◈", 11, Muted);
        fragment.IsVisible = record.Fragment.HasValue;
        fragment.VerticalAlignment = VerticalAlignment.Top;
        fragment.HorizontalAlignment = HorizontalAlignment.Left;
        fragment.Margin = new Avalonia.Thickness(6, 3, 0, 0);
        var subtitle = Label(title, 12, weight: Demi);
        route = Label($"{summary.SourceAddress} → {summary.DestinationAddress}", 10, Muted, mono: true);
        route.MaxWidth = 190;
        var tag = Badge(status, 10);
        tag.IsVisible = status.Label is not ("✓ 正常" or "↳ 分片");
        var bottom = LayoutGrid("*,Auto,Auto", subtitle, route, tag);
        bottom.ColumnSpacing = 5;
        var text = Vertical(0, headline, bottom);
        text.Margin = new Avalonia.Thickness(23, 2, 10, 2);
        text.VerticalAlignment = VerticalAlignment.Center;
        var layer = new Grid();
        layer.Children.Add(edge);
        layer.Children.Add(fragment);
        layer.Children.Add(text);
        Child = layer;
        Height = 40;
        BorderBrush = Line;
        BorderThickness = new Avalonia.Thickness(0, 0, 0, 1);
        var tooltip = $"{number.Text} · {summary.Name} · {title} · {status.Label}\n{timeText} · {record.Context}\n{route.Text}\n捕获 {record.Length} B / 原始 {record.OriginalLength} B";
        ToolTip.SetTip(this, tooltip);
        Avalonia.Automation.AutomationProperties.SetName(this, tooltip);
        Refresh(selected, selectedGroup);
        SizeChanged += (_, _) =>
        {
            time.IsVisible = Bounds.Width > 236;
            route.IsVisible = Bounds.Width >= 440;
        };
    }

    internal void Refresh(int selected, FragmentGroup? selectedGroup)
    {
        var isSelected = index == selected;
        var linked = record.Fragment.HasValue && group is not null && group == selectedGroup;
        var parentBackground = (isSelected, linked) switch
        {
            (true, _) => Selected,
            (false, true) => PeerBackground,
            _ => null
        };
        Background = parentBackground;
        edge.IsVisible = isSelected;
        number.Foreground = isSelected ? Accent : Text;
        fragment.Foreground = linked ? Accent : Muted;
    }
}
