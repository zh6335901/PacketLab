using PacketLab.Analysis.IpReassembly;
using PacketLab.Desktop.Localization;
using PacketLab.Desktop.Models.PacketExplorer;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Desktop.Services.PacketExplorer;

internal enum RecordTone { Good, Bad, Warn, Blue, Neutral }

internal readonly record struct RecordTitle(string Text, string? AutomationId)
{
    internal RecordTitle(string text) : this(text, null) { }
}

internal readonly record struct RecordStatus(string Label, RecordTone Tone, bool ShowBadge)
{
    internal static RecordStatus ForGroup(FragmentGroup group) => group.Status switch
    {
        IpReassemblyStatus.Complete => new(Strings.StatusReassembled, RecordTone.Good, ShowBadge: true),
        IpReassemblyStatus.Atomic => new(Strings.StatusAtomicFragment, RecordTone.Good, ShowBadge: true),
        IpReassemblyStatus.Conflict => new(Strings.StatusConflict, RecordTone.Bad, ShowBadge: true),
        IpReassemblyStatus.Discarded when group.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit =>
            new(Strings.StatusResourceLimit, RecordTone.Warn, ShowBadge: true),
        IpReassemblyStatus.Discarded => new(Strings.StatusDiscarded, RecordTone.Bad, ShowBadge: true),
        IpReassemblyStatus.Invalid => new(Strings.StatusInvalidFields, RecordTone.Bad, ShowBadge: true),
        IpReassemblyStatus.Truncated => new(Strings.StatusTruncated, RecordTone.Warn, ShowBadge: true),
        IpReassemblyStatus.ResourceLimit => new(Strings.StatusResourceLimit, RecordTone.Warn, ShowBadge: true),
        IpReassemblyStatus.Incomplete => new(Strings.StatusMissingFragments, RecordTone.Warn, ShowBadge: true),
        IpReassemblyStatus.Expired => new(Strings.StatusReassemblyTimeout, RecordTone.Warn, ShowBadge: true),
        IpReassemblyStatus.Duplicate => new(Strings.StatusDuplicateFragment, RecordTone.Blue, ShowBadge: true),
        _ => new(Strings.StatusFragment, RecordTone.Blue, ShowBadge: false)
    };

    internal static RecordStatus ForRecord(CaptureRecord record, FragmentGroup? group, int index)
    {
        var issue = record.Summary.Issue;
        if (group is not null && IsOutcome(group, index))
            return ForGroup(group);
        if ((issue & (PacketIssue.Invalid | PacketIssue.InvalidCaptureLength | PacketIssue.InvalidTime)) != 0)
            return new(Strings.StatusInvalidFields, RecordTone.Bad, ShowBadge: true);
        if (issue.HasFlag(PacketIssue.Truncated))
            return new(Strings.StatusTruncated, RecordTone.Warn, ShowBadge: true);
        if (issue.HasFlag(PacketIssue.Mismatch))
            return new(Strings.StatusMismatch, RecordTone.Warn, ShowBadge: true);
        if (issue.HasFlag(PacketIssue.Unsupported))
            return new(Strings.StatusUnsupported, RecordTone.Neutral, ShowBadge: true);
        if (issue.HasFlag(PacketIssue.NoTime))
            return new(Strings.StatusNoTimestamp, RecordTone.Neutral, ShowBadge: true);
        if (issue.HasFlag(PacketIssue.Unknown))
            return new(Strings.StatusUnknownItems, RecordTone.Neutral, ShowBadge: true);
        if (issue.HasFlag(PacketIssue.ChecksumUnavailable))
            return new(Strings.StatusChecksumUnavailable, RecordTone.Neutral, ShowBadge: true);

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

    internal static RecordTitle Title(CaptureRecord record, FragmentGroup? group, int index)
    {
        if (record.Kind == PacketLab.Pcap.PcapNgPacketKind.Simple && record.Summary is { Protocol: Protocol.Arp, Detail: 1 })
            return new(Strings.ArpSimplePacket);
        if (record.Fragment is not { } fragment)
            return new(record.Summary.Title);

        return FragmentTitle(record.Summary, fragment, group, index);
    }

    private static RecordTitle FragmentTitle(PacketSummary summary, FragmentSlice fragment, FragmentGroup? group, int index)
    {
        var name = summary.IpVersion == 6 ? "IPv6" : "IPv4";
        if (group is { Failed: true } && index > group.Records[^1])
            return new(UIText.Format(Strings.FragmentGroupDiscarded, name));

        if (group is not null && IsOutcome(group, index))
        {
            return OutcomeTitle(name, fragment, group);
        }
        if (fragment.Offset == 0)
        {
            if (group?.DiagnosticCode == IpReassemblyDiagnosticCode.OverlapDiscarded)
                return new(UIText.Format(Strings.OverlapFirstFragment, name));

            return new(name == "IPv6" && summary.Detail > 1 ? Strings.Ipv6FirstFragmentWithExtensions : UIText.Format(Strings.FirstFragmentOf, name));
        }
        if (!fragment.More && group is not null && group.Records[0] == index)
            return new(UIText.Format(Strings.FinalFragmentFirst, name));

        return new($"{name} {(fragment.More ? Strings.MiddleFragment : Strings.FinalFragment)} · +{fragment.Offset} B");
    }

    private static RecordTitle OutcomeTitle(string name, FragmentSlice fragment, FragmentGroup group) => group.Status switch
    {
        IpReassemblyStatus.Complete => CompletionTitle(name, fragment),
        IpReassemblyStatus.Conflict when group.DiagnosticCode == IpReassemblyDiagnosticCode.OverlapDiscarded =>
            new(UIText.Format(Strings.FragmentOverlap, name)),
        IpReassemblyStatus.Incomplete when fragment.Offset == 0 => new(UIText.Format(Strings.AwaitingMoreFragments, name)),
        IpReassemblyStatus.Incomplete => new(UIText.Format(Strings.MissingFragments, name)),
        IpReassemblyStatus.Truncated => new(UIText.Format(Strings.FragmentTruncated, name)),
        IpReassemblyStatus.ResourceLimit => new(Strings.ReassemblyLimitReached),
        IpReassemblyStatus.Atomic => new(Strings.Ipv6AtomicFragment),
        _ when group.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit => new(Strings.AssociationLimitReached),
        _ => new($"{name} {ForGroup(group).Label[2..]}")
    };

    private static RecordTitle CompletionTitle(string name, FragmentSlice fragment)
    {
        var (position, automationId) = fragment switch
        {
            { Offset: 0 } => (Strings.FirstFragment, "ReassemblyCompletedByFirstFragment"),
            { More: true } => (Strings.MiddleFragment, "ReassemblyCompletedByMiddleFragment"),
            _ => (Strings.FinalFragment, "ReassemblyCompletedByFinalFragment")
        };

        return new(UIText.Format(Strings.ReassemblyCompletion, name, position), automationId);
    }

    internal static string Describe(CaptureRecord record, FragmentGroup? group)
    {
        var details = new List<string>();
        if (record.Fragment is { } fragment)
        {
            var flag = record.Summary.IpVersion == 4 ? "MF" : "M";
            details.Add(UIText.Format(Strings.FragmentFlagAndOffset, flag, (fragment.More ? 1 : 0), fragment.Offset));
            if (group is not null)
            {
                if (group.HasResult && group.DerivedSlice is { } slice)
                {
                    var members = Members(group.Records);
                    details.Add(UIText.Format(Strings.ReassembledPayloadMembers, members, slice.Length));
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

    internal static string GroupDiagnostic(FragmentGroup group) => (group.Reason, group.Status, group.DiagnosticCode) switch
    {
        (IpReassemblyAnalysisReason.EndOfCapture, _, _) => Strings.MissingAtEndOfCapture,
        (IpReassemblyAnalysisReason.EndOfSection, _, _) => Strings.MissingAtEndOfSection,
        (IpReassemblyAnalysisReason.Aborted, _, _) => Strings.ReassemblyAborted,
        (IpReassemblyAnalysisReason.RecordAgeLimit, _, _) => Strings.RecordSpanLimit,
        (IpReassemblyAnalysisReason.RecordAssociationLimit, _, _) => Strings.AssociationLimitDiscarded,
        (_, IpReassemblyStatus.Conflict, IpReassemblyDiagnosticCode.OverlapDiscarded) => Strings.OverlappingFragmentRanges,
        (_, IpReassemblyStatus.Truncated, _) => Strings.TruncatedFragmentPayload,
        _ => Strings.ResourceManager.GetString($"Reassembly{group.DiagnosticCode}") ?? Strings.ReassemblyIncomplete
    };

    internal static string Number(int index) => $"#{index + 1:000}";

    internal static string LaneLabel(CoverageLane lane) => lane.Derived ? Strings.ReassembledIp : Number(lane.Record);

    private static string Members(IReadOnlyList<int> records)
    {
        var names = records.Take(5).Select(Number);
        var shown = string.Join(Strings.ListSeparator, names);

        return records.Count > 5 ? UIText.Format(Strings.NamedRecordsAndTotal, shown, records.Count) : shown;
    }
}
