using PacketLab.Analysis.IpReassembly;
using System.Collections;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using PacketLab.Protocols.IP.Reassembly;
using static PacketLab.Desktop.ViewStyle;

namespace PacketLab.Desktop;

internal enum RecordFilter { All, Diagnostics, Fragments }

internal readonly record struct RecordStatus(string Label, IBrush Foreground, IBrush Background)
{
    internal static RecordStatus ForGroup(FragmentGroup group) => group.Status switch
    {
        IpReassemblyStatus.Complete => new("✓ 已重组", Good, GoodBackground),
        IpReassemblyStatus.Atomic => new("✓ 原子分片", Good, GoodBackground),
        IpReassemblyStatus.Conflict => new("× 冲突", Bad, BadBackground),
        IpReassemblyStatus.Discarded when group.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit =>
            new("! 资源限制", Warn, WarnBackground),
        IpReassemblyStatus.Discarded => new("× 已丢弃", Bad, BadBackground),
        IpReassemblyStatus.Invalid => new("× 无效字段", Bad, BadBackground),
        IpReassemblyStatus.Truncated => new("! 截断", Warn, WarnBackground),
        IpReassemblyStatus.ResourceLimit => new("! 资源限制", Warn, WarnBackground),
        IpReassemblyStatus.Incomplete => new("! 缺片", Warn, WarnBackground),
        IpReassemblyStatus.Expired => new("! 重组超时", Warn, WarnBackground),
        IpReassemblyStatus.Duplicate => new("↳ 重复分片", Blue, BlueBackground),
        _ => new("↳ 分片", Blue, BlueBackground)
    };

    internal static RecordStatus ForRecord(CaptureRecord record, FragmentGroup? group, int index)
    {
        var issue = record.Summary.Issue;
        if (group is not null && IsOutcome(group, index))
            return ForGroup(group);
        if ((issue & (PacketIssue.Invalid | PacketIssue.InvalidCaptureLength | PacketIssue.InvalidTime)) != 0)
            return new("× 无效字段", Bad, BadBackground);
        if (issue.HasFlag(PacketIssue.Truncated))
            return new("! 截断", Warn, WarnBackground);
        if (issue.HasFlag(PacketIssue.Mismatch))
            return new("! 不匹配", Warn, WarnBackground);
        if (issue.HasFlag(PacketIssue.Unsupported))
            return new("· 未支持", Neutral, NeutralBackground);
        if (issue.HasFlag(PacketIssue.NoTime))
            return new("· 无时间戳", Neutral, NeutralBackground);
        if (issue.HasFlag(PacketIssue.Unknown))
            return new("· 含未知项", Neutral, NeutralBackground);
        if (issue.HasFlag(PacketIssue.ChecksumUnavailable))
            return new("· 校验不可用", Neutral, NeutralBackground);

        return record.Fragment is null ? new("✓ 正常", Good, GoodBackground) : new("↳ 分片", Blue, BlueBackground);
    }

    private static bool IsOutcome(FragmentGroup group, int index) => group.Status switch
    {
        IpReassemblyStatus.Complete => group.Records[^1] == index,
        IpReassemblyStatus.Conflict => group.Records[^1] <= index,
        IpReassemblyStatus.Pending or IpReassemblyStatus.Duplicate => false,
        _ => true
    };

    internal static bool IsDiagnostic(CaptureRecord record, FragmentGroup? group, int index) =>
        record.Summary.Issue != PacketIssue.None || group is { Failed: true } && IsOutcome(group, index);

    internal static string Title(CaptureRecord record, FragmentGroup? group, int index)
    {
        if (record.Kind == PacketLab.Pcap.PcapNgPacketKind.Simple && record.Summary is { Protocol: Protocol.Arp, Detail: 1 })
            return "ARP 请求 · Simple Packet";
        if (record.Fragment is not { } fragment)
            return record.Summary.Title;

        return FragmentTitle(record.Summary, fragment, group, index);
    }

    private static string FragmentTitle(PacketSummary summary, FragmentSlice fragment, FragmentGroup? group, int index)
    {
        var name = summary.IpVersion == 6 ? "IPv6" : "IPv4";
        if (group is { Failed: true } && index > group.Records[^1])
            return $"{name} 分片组已丢弃";

        if (group is not null && IsOutcome(group, index))
        {
            return OutcomeTitle(name, fragment, group);
        }
        if (fragment.Offset == 0)
        {
            if (group?.Status == IpReassemblyStatus.Conflict)
                return $"{name} 重叠组 · 首片";

            return name == "IPv6" && summary.Detail > 1 ? "IPv6 首片 · 扩展链" : $"{name} 首片";
        }
        if (!fragment.More && group is not null && group.Records[0] == index)
            return $"{name} 尾片先到";

        return $"{name} {(fragment.More ? "中间片" : "尾片")} · +{fragment.Offset} B";
    }

    private static string OutcomeTitle(string name, FragmentSlice fragment, FragmentGroup group) => group.Status switch
    {
        IpReassemblyStatus.Complete => $"{name} {(fragment.Offset == 0 ? "首片" : "尾片")} · 补齐数据报",
        IpReassemblyStatus.Conflict => $"{name} 分片发生重叠",
        IpReassemblyStatus.Incomplete when fragment.Offset == 0 => $"{name} 等待后续分片",
        IpReassemblyStatus.Incomplete => $"{name} 缺片",
        IpReassemblyStatus.Truncated => $"{name} 分片截断",
        IpReassemblyStatus.ResourceLimit => "达到重组资源限制",
        IpReassemblyStatus.Atomic => "IPv6 原子分片",
        _ when group.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit => "达到关联记录上限",
        _ => $"{name} {ForGroup(group).Label[2..]}"
    };

    internal static string Describe(CaptureRecord record, FragmentGroup? group)
    {
        var details = new List<string>();
        if (record.Fragment is { } fragment)
        {
            var flag = record.Summary.IpVersion == 4 ? "MF" : "M";
            details.Add($"{flag} 为 {(fragment.More ? 1 : 0)}，片偏移为 {fragment.Offset} B。");
            if (group is not null)
            {
                if (group.HasResult && group.DerivedSlice is { } slice)
                    details.Add($"{Members(group.Records)} 共同形成 {slice.Length} B 的 IP 载荷。");
                else
                    details.Add(GroupDiagnostic(group));
            }
        }
        var issue = record.Summary.Issue;
        var messages = IssueMessages.Where(entry => issue.HasFlag(entry.Issue)).Select(entry => entry.Message);
        details.AddRange(messages);

        return details.Count == 0 ? $"{record.Summary.SourceAddress} → {record.Summary.DestinationAddress}" : string.Join(" ", details);
    }

    private static readonly (PacketIssue Issue, string Message)[] IssueMessages =
    [
        (PacketIssue.Truncated, "报文或协议首部未完整捕获。"),
        (PacketIssue.Invalid, "存在无效的协议字段。"),
        (PacketIssue.Mismatch, "捕获字节的校验和与计算值不匹配，可能与校验卸载有关。"),
        (PacketIssue.ChecksumUnavailable, "无法验证校验和。"),
        (PacketIssue.Unsupported, "封装或协议未支持，原始字节可供核对。"),
        (PacketIssue.Unknown, "保留未知字段或选项的原值。"),
        (PacketIssue.NoTime, "此记录未提供时间戳。"),
        (PacketIssue.InvalidTime, "时间戳的小数部分超出范围，保留原值。"),
        (PacketIssue.InvalidCaptureLength, "声明的原始长度小于捕获长度。")
    ];

    internal static string GroupDiagnostic(FragmentGroup group) => (group.Reason, group.Status) switch
    {
        (IpReassemblyAnalysisReason.EndOfCapture, _) => "捕获结束时仍缺少分片。",
        (IpReassemblyAnalysisReason.EndOfSection, _) => "Section 结束时仍缺少分片。",
        (IpReassemblyAnalysisReason.Aborted, _) => "读取中止时，重组尚未完成。",
        (IpReassemblyAnalysisReason.RecordAgeLimit, _) => "超过记录跨度限制，重组已结束。",
        (IpReassemblyAnalysisReason.RecordAssociationLimit, _) => "超过关联记录数限制，重组已丢弃。",
        (_, IpReassemblyStatus.Conflict) => "分片范围发生冲突，重组已丢弃。",
        (_, IpReassemblyStatus.Truncated) => "分片载荷未完整捕获。",
        _ => group.Message
    };

    internal static string Number(int index) => $"#{index + 1:000}";

    private static string Members(IReadOnlyList<int> records)
    {
        var names = records.Take(5).Select(Number);
        var shown = string.Join("、", names);

        return records.Count > 5 ? $"{shown} 等 {records.Count} 条记录" : shown;
    }
}

internal sealed class RecordItems(int count, int[]? filtered = null) : IList
{
    public int Count => filtered?.Length ?? count;
    public bool IsReadOnly => true;
    public bool IsFixedSize => true;
    public bool IsSynchronized => false;
    public object SyncRoot => this;

    internal int RecordAt(int index) => filtered is null ? index : filtered[index];

    public object? this[int index]
    {
        get => (uint)index < (uint)Count ? RecordAt(index) : throw new ArgumentOutOfRangeException(nameof(index));
        set => throw new NotSupportedException();
    }

    public int IndexOf(object? value)
    {
        if (value is not int index)
            return -1;
        if (filtered is null)
            return (uint)index < (uint)count ? index : -1;

        return Math.Max(-1, Array.BinarySearch(filtered, index));
    }

    public bool Contains(object? value) => IndexOf(value) >= 0;
    public IEnumerator GetEnumerator()
    {
        for (var i = 0; i < Count; i++)
            yield return RecordAt(i);
    }

    public void CopyTo(Array array, int index)
    {
        for (var i = 0; i < Count; i++)
            array.SetValue(RecordAt(i), index + i);
    }

    public int Add(object? value) => throw new NotSupportedException();
    public void Insert(int index, object? value) => throw new NotSupportedException();
    public void Remove(object? value) => throw new NotSupportedException();
    public void RemoveAt(int index) => throw new NotSupportedException();
    public void Clear() => throw new NotSupportedException();

    internal static int[] Search(CaptureIndex capture, int count, RecordFilter filter, string query, CancellationToken token)
    {
        var matches = new List<int>();
        var numberSearch = query.Length > 1 && query[0] == '#' && query.AsSpan(1).IndexOfAnyExceptInRange('0', '9') < 0;
        for (var i = 0; i < count; i++)
        {
            if (i % 512 == 0)
                token.ThrowIfCancellationRequested();

            if (numberSearch && !MatchesNumber(i + 1, query.AsSpan(1)))
                continue;

            var record = capture.ReadRecord(i);
            var group = record.Fragment is null ? null : capture.Group(i);
            if (filter == RecordFilter.Fragments && !record.Fragment.HasValue)
                continue;
            if (filter == RecordFilter.Diagnostics && !RecordStatus.IsDiagnostic(record, group, i))
                continue;
            if (!numberSearch && query.Length > 0 && !Matches(record, group, i, query))
                continue;

            matches.Add(i);
        }

        return matches.ToArray();
    }

    private static bool MatchesNumber(int number, ReadOnlySpan<char> prefix)
    {
        Span<char> formatted = stackalloc char[10];
        number.TryFormat(formatted, out var written, "000");

        return formatted[..written].StartsWith(prefix, StringComparison.Ordinal);
    }

    private static bool Matches(CaptureRecord record, FragmentGroup? group, int index, string query)
    {
        var text = string.Join(' ', RecordStatus.Number(index),
            (index + 1).ToString(), record.Summary.Name,
            RecordStatus.Title(record, group, index), record.Context, record.Summary.SourceAddress, record.Summary.DestinationAddress,
            RecordStatus.ForRecord(record, group, index).Label, group?.Identity);

        return text.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            (query.Contains(':') && record.Time.Format().Contains(query, StringComparison.OrdinalIgnoreCase));
    }
}

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

    internal RecordRow(CaptureIndex capture, int index, int selected, FragmentGroup? selectedGroup)
    {
        this.index = index;
        record = capture.ReadRecord(index);
        group = capture.Group(index);
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
        var tag = Badge(status.Label, status.Foreground, status.Background, 10);
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
