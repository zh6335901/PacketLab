using PacketLab.Desktop.Localization;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using PacketLab.Desktop.Models.PacketExplorer;
using PacketLab.Desktop.Services.PacketExplorer;
using static PacketLab.Desktop.Controls.PacketExplorer.ViewStyle;

namespace PacketLab.Desktop.Controls.PacketExplorer;

internal sealed class RecordRow : Border
{
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
        var timeText = record.Time.Format(date: false);
        number = Label(RecordStatus.Number(index), 11, mono: true, weight: Demi, brush: null);
        var protocol = Label(summary.Name, 11, ProtocolBrush(summary.Protocol), mono: true, weight: Demi);
        time = Label(timeText, 10, Muted, mono: true, weight: FontWeight.Normal);
        time.MaxWidth = 148;
        var headline = LayoutGrid("Auto,*,Auto", number, protocol, time);
        headline.ColumnSpacing = 6;
        fragment = Label("◈", 11, Muted, mono: false, weight: FontWeight.Normal);
        fragment.IsVisible = record.Fragment.HasValue;
        fragment.VerticalAlignment = VerticalAlignment.Top;
        fragment.HorizontalAlignment = HorizontalAlignment.Left;
        fragment.Margin = new Avalonia.Thickness(6, 3, 0, 0);
        var subtitle = Label(title, 12, weight: Demi, brush: null, mono: false);
        route = Label($"{summary.SourceAddress} → {summary.DestinationAddress}", 10, Muted, mono: true, weight: FontWeight.Normal);
        route.MaxWidth = 190;
        var tag = Badge(status, 10);
        tag.IsVisible = status.ShowBadge;
        var bottom = LayoutGrid("*,Auto,Auto", subtitle, route, tag);
        bottom.ColumnSpacing = 5;
        var text = Vertical(0, headline, bottom);
        text.Margin = new Avalonia.Thickness(23, 2, 10, 2);
        text.VerticalAlignment = VerticalAlignment.Center;
        var layer = new Grid();
        layer.Children.Add(fragment);
        layer.Children.Add(text);
        Child = layer;
        Height = 40;
        BorderBrush = Line;
        BorderThickness = new Avalonia.Thickness(0, 0, 0, 1);
        var tooltip = UIText.Format(Strings.RecordTooltip, number.Text, summary.Name, title, status.Label, timeText, record.Context, route.Text, record.Length, record.OriginalLength);
        ToolTip.SetTip(this, tooltip);
        AutomationProperties.SetAutomationId(this, FormattableString.Invariant($"CaptureRecord-{index + 1}"));
        AutomationProperties.SetName(this, tooltip);
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
        number.Foreground = isSelected ? Accent : Text;
        fragment.Foreground = linked ? Accent : Muted;
    }
}
