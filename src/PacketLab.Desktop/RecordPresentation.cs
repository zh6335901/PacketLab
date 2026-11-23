using PacketLab.Desktop.Localization;
using PacketLab.Analysis.IpReassembly;
using System.Collections;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Desktop;

internal enum RecordFilter { All, Diagnostics, Fragments }

internal enum RecordTone { Good, Bad, Warn, Blue, Neutral }

internal readonly record struct RecordStatus(string Label, RecordTone Tone, bool ShowBadge = true)
{
    internal static RecordStatus ForGroup(FragmentGroup group) => group.Status switch
    {
        IpReassemblyStatus.Complete => new(Strings.StatusReassembled, RecordTone.Good),
        IpReassemblyStatus.Atomic => new(Strings.StatusAtomicFragment, RecordTone.Good),
        IpReassemblyStatus.Conflict => new(Strings.StatusConflict, RecordTone.Bad),
        IpReassemblyStatus.Discarded when group.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit =>
            new(Strings.StatusResourceLimit, RecordTone.Warn),
        IpReassemblyStatus.Discarded => new(Strings.StatusDiscarded, RecordTone.Bad),
        IpReassemblyStatus.Invalid => new(Strings.StatusInvalidFields, RecordTone.Bad),
        IpReassemblyStatus.Truncated => new(Strings.StatusTruncated, RecordTone.Warn),
        IpReassemblyStatus.ResourceLimit => new(Strings.StatusResourceLimit, RecordTone.Warn),
        IpReassemblyStatus.Incomplete => new(Strings.StatusMissingFragments, RecordTone.Warn),
        IpReassemblyStatus.Expired => new(Strings.StatusReassemblyTimeout, RecordTone.Warn),
        IpReassemblyStatus.Duplicate => new(Strings.StatusDuplicateFragment, RecordTone.Blue),
        _ => new(Strings.StatusFragment, RecordTone.Blue, ShowBadge: false)
    };

    internal static RecordStatus ForRecord(CaptureRecord record, FragmentGroup? group, int index)
    {
        var issue = record.Summary.Issue;
        if (group is not null && IsOutcome(group, index))
            return ForGroup(group);
        if ((issue & (PacketIssue.Invalid | PacketIssue.InvalidCaptureLength | PacketIssue.InvalidTime)) != 0)
            return new(Strings.StatusInvalidFields, RecordTone.Bad);
        if (issue.HasFlag(PacketIssue.Truncated))
            return new(Strings.StatusTruncated, RecordTone.Warn);
        if (issue.HasFlag(PacketIssue.Mismatch))
            return new(Strings.StatusMismatch, RecordTone.Warn);
        if (issue.HasFlag(PacketIssue.Unsupported))
            return new(Strings.StatusUnsupported, RecordTone.Neutral);
        if (issue.HasFlag(PacketIssue.NoTime))
            return new(Strings.StatusNoTimestamp, RecordTone.Neutral);
        if (issue.HasFlag(PacketIssue.Unknown))
            return new(Strings.StatusUnknownItems, RecordTone.Neutral);
        if (issue.HasFlag(PacketIssue.ChecksumUnavailable))
            return new(Strings.StatusChecksumUnavailable, RecordTone.Neutral);

        return record.Fragment is null
            ? new(Strings.StatusNormal, RecordTone.Good, ShowBadge: false)
            : new(Strings.StatusFragment, RecordTone.Blue, ShowBadge: false);
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
            return Strings.ArpSimplePacket;
        if (record.Fragment is not { } fragment)
            return record.Summary.Title;

        return FragmentTitle(record.Summary, fragment, group, index);
    }

    private static string FragmentTitle(PacketSummary summary, FragmentSlice fragment, FragmentGroup? group, int index)
    {
        var name = summary.IpVersion == 6 ? "IPv6" : "IPv4";
        if (group is { Failed: true } && index > group.Records[^1])
            return UiText.Format(Strings.FragmentGroupDiscarded, name);

        if (group is not null && IsOutcome(group, index))
        {
            return OutcomeTitle(name, fragment, group);
        }
        if (fragment.Offset == 0)
        {
            if (group?.Status == IpReassemblyStatus.Conflict)
                return UiText.Format(Strings.OverlapFirstFragment, name);

            return name == "IPv6" && summary.Detail > 1 ? Strings.Ipv6FirstFragmentWithExtensions : UiText.Format(Strings.FirstFragmentOf, name);
        }
        if (!fragment.More && group is not null && group.Records[0] == index)
            return UiText.Format(Strings.FinalFragmentFirst, name);

        return $"{name} {(fragment.More ? Strings.MiddleFragment : Strings.FinalFragment)} · +{fragment.Offset} B";
    }

    private static string OutcomeTitle(string name, FragmentSlice fragment, FragmentGroup group) => group.Status switch
    {
        IpReassemblyStatus.Complete => UiText.Format(Strings.ReassemblyCompletion, name, (fragment.Offset == 0 ? Strings.FirstFragment : Strings.FinalFragment)),
        IpReassemblyStatus.Conflict => UiText.Format(Strings.FragmentOverlap, name),
        IpReassemblyStatus.Incomplete when fragment.Offset == 0 => UiText.Format(Strings.AwaitingMoreFragments, name),
        IpReassemblyStatus.Incomplete => UiText.Format(Strings.MissingFragments, name),
        IpReassemblyStatus.Truncated => UiText.Format(Strings.FragmentTruncated, name),
        IpReassemblyStatus.ResourceLimit => Strings.ReassemblyLimitReached,
        IpReassemblyStatus.Atomic => Strings.Ipv6AtomicFragment,
        _ when group.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit => Strings.AssociationLimitReached,
        _ => $"{name} {ForGroup(group).Label[2..]}"
    };

    internal static string Describe(CaptureRecord record, FragmentGroup? group)
    {
        var details = new List<string>();
        if (record.Fragment is { } fragment)
        {
            var flag = record.Summary.IpVersion == 4 ? "MF" : "M";
            details.Add(UiText.Format(Strings.FragmentFlagAndOffset, flag, (fragment.More ? 1 : 0), fragment.Offset));
            if (group is not null)
            {
                if (group.HasResult && group.DerivedSlice is { } slice)
                {
                    var members = Members(group.Records);
                    details.Add(UiText.Format(Strings.ReassembledPayloadMembers, members, slice.Length));
                }
                else
                    details.Add(GroupDiagnostic(group));
            }
        }
        var issue = record.Summary.Issue;
        foreach (var flag in IssueFlags)
        {
            if (issue.HasFlag(flag))
                details.Add(IssueMessage(flag));
        }

        return details.Count == 0 ? $"{record.Summary.SourceAddress} → {record.Summary.DestinationAddress}" : string.Join(" ", details);
    }

    private static ReadOnlySpan<PacketIssue> IssueFlags =>
    [
        PacketIssue.Truncated, PacketIssue.Invalid, PacketIssue.Mismatch, PacketIssue.ChecksumUnavailable,
        PacketIssue.Unsupported, PacketIssue.Unknown, PacketIssue.NoTime, PacketIssue.InvalidTime, PacketIssue.InvalidCaptureLength
    ];

    private static string IssueMessage(PacketIssue issue) => issue switch
    {
        PacketIssue.Truncated => Strings.IssueTruncated,
        PacketIssue.Invalid => Strings.IssueInvalidFields,
        PacketIssue.Mismatch => Strings.IssueChecksumMismatch,
        PacketIssue.ChecksumUnavailable => Strings.IssueChecksumUnavailable,
        PacketIssue.Unsupported => Strings.IssueUnsupportedProtocol,
        PacketIssue.Unknown => Strings.IssueUnknownValues,
        PacketIssue.NoTime => Strings.IssueNoTimestamp,
        PacketIssue.InvalidTime => Strings.IssueInvalidTimestamp,
        PacketIssue.InvalidCaptureLength => Strings.IssueInvalidCaptureLength,
        _ => throw new ArgumentOutOfRangeException(nameof(issue))
    };

    internal static string GroupDiagnostic(FragmentGroup group) => (group.Reason, group.Status) switch
    {
        (IpReassemblyAnalysisReason.EndOfCapture, _) => Strings.MissingAtEndOfCapture,
        (IpReassemblyAnalysisReason.EndOfSection, _) => Strings.MissingAtEndOfSection,
        (IpReassemblyAnalysisReason.Aborted, _) => Strings.ReassemblyAborted,
        (IpReassemblyAnalysisReason.RecordAgeLimit, _) => Strings.RecordSpanLimit,
        (IpReassemblyAnalysisReason.RecordAssociationLimit, _) => Strings.AssociationLimitDiscarded,
        (_, IpReassemblyStatus.Conflict) => Strings.OverlappingFragmentRanges,
        (_, IpReassemblyStatus.Truncated) => Strings.TruncatedFragmentPayload,
        _ => Strings.ResourceManager.GetString($"Reassembly{group.DiagnosticCode}") ?? Strings.ReassemblyIncomplete
    };

    internal static string Number(int index) => $"#{index + 1:000}";

    private static string Members(IReadOnlyList<int> records)
    {
        var names = records.Take(5).Select(Number);
        var shown = string.Join(Strings.ListSeparator, names);

        return records.Count > 5 ? UiText.Format(Strings.NamedRecordsAndTotal, shown, records.Count) : shown;
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
