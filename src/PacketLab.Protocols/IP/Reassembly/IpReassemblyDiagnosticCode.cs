namespace PacketLab.Protocols.IP.Reassembly;

public enum IpReassemblyDiagnosticCode
{
    Unspecified,
    TimedOut,
    ExpiredByCaller,
    DiscardedByCaller,
    MissingFragments,
    DatagramTableLimit,
    AtomicFragment,
    DuplicateIgnored,
    OverlapDiscarded,
    IpLengthLimit,
    DatagramByteLimit,
    CompleteCoverage,
    AwaitingFragments,
    IncompatibleHeaders,
    IncompatibleEcn,
    InconsistentFinalLength,
    FragmentCountLimit,
    BufferLimit,
    TruncatedPayload,
    InvalidLengthOrAlignment,
    RangeExceedsIpLength,
    InvalidIpv4Flags,
    InvalidIpv6ExtensionChain,
    MissingIpv6UpperLayerChain,
    AlreadyDiscarded
}

internal static class IpReassemblyDiagnosticDescriptions
{
    internal static string Detail(this IpReassemblyDiagnosticCode code) => code switch
    {
        IpReassemblyDiagnosticCode.TimedOut => "reassembly timeout reached",
        IpReassemblyDiagnosticCode.ExpiredByCaller => "datagram expired by caller",
        IpReassemblyDiagnosticCode.DiscardedByCaller => "datagram discarded by caller",
        IpReassemblyDiagnosticCode.MissingFragments => "missing fragments",
        IpReassemblyDiagnosticCode.DatagramTableLimit => "datagram table limit reached (including discarded identities)",
        IpReassemblyDiagnosticCode.AtomicFragment => "independent atomic fragment",
        IpReassemblyDiagnosticCode.DuplicateIgnored => "exact duplicate ignored",
        IpReassemblyDiagnosticCode.OverlapDiscarded => "overlap: entire datagram discarded",
        IpReassemblyDiagnosticCode.IpLengthLimit => "reassembled IP length exceeds limit",
        IpReassemblyDiagnosticCode.DatagramByteLimit => "single datagram byte limit reached",
        IpReassemblyDiagnosticCode.CompleteCoverage => "all fragment bytes captured",
        IpReassemblyDiagnosticCode.AwaitingFragments => "waiting for contiguous fragments and final length",
        IpReassemblyDiagnosticCode.IncompatibleHeaders => "incompatible IP or extension header context",
        IpReassemblyDiagnosticCode.IncompatibleEcn => "CE and Not-ECT fragments cannot be combined",
        IpReassemblyDiagnosticCode.InconsistentFinalLength => "inconsistent final fragment length",
        IpReassemblyDiagnosticCode.FragmentCountLimit => "fragment count limit reached",
        IpReassemblyDiagnosticCode.BufferLimit => "buffered byte limit reached",
        IpReassemblyDiagnosticCode.TruncatedPayload => "fragment payload was not fully captured",
        IpReassemblyDiagnosticCode.InvalidLengthOrAlignment => "invalid fragment length or eight-byte alignment",
        IpReassemblyDiagnosticCode.RangeExceedsIpLength => "fragment range exceeds IP length limit",
        IpReassemblyDiagnosticCode.InvalidIpv4Flags => "invalid IPv4 fragmentation flags",
        IpReassemblyDiagnosticCode.InvalidIpv6ExtensionChain => "invalid or incomplete IPv6 extension chain",
        IpReassemblyDiagnosticCode.MissingIpv6UpperLayerChain => "IPv6 first fragment lacks a complete upper-layer header chain",
        IpReassemblyDiagnosticCode.AlreadyDiscarded => "datagram already discarded; identity retained until expiry",
        _ => throw new ArgumentOutOfRangeException(nameof(code))
    };
}
