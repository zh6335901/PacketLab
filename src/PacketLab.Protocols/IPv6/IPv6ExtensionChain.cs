using System.Collections.Immutable;

namespace PacketLab.Protocols.IPv6;

public sealed record IPv6Fragment(ushort Offset, bool MoreFragments, uint Identification, byte NextHeader)
{
    public int OffsetBytes => Offset * 8;
    public bool IsAtomic => Offset == 0 && !MoreFragments;
}

// Offsets are measured from the start of the IPv6 fixed header.
public sealed record IPv6ExtensionHeader(byte Type, byte NextHeader, int Offset, ReadOnlyMemory<byte> Bytes,
    IPv6Fragment? Fragment = null)
{
    public int Length => Bytes.Length;
}

public enum IPv6DiagnosticCode
{
    PayloadTruncated, HeaderTruncated, HeaderExceedsPayload, InvalidHeaderLength,
    InvalidOptions, MissingJumboPayload, InvalidJumboPayload, JumboFragment,
    InvalidHopByHopPosition, DuplicateFragment, ReassemblyRequired, EncryptedEsp,
    UnsupportedNextHeader, FinalDestinationUnavailable, SourceAddressUnavailable
}

public sealed record IPv6Diagnostic(IPv6DiagnosticCode Code, int Offset, string Message);

public sealed record IPv6UpperLayer(byte Protocol, int Offset, uint DeclaredLength, ReadOnlyMemory<byte> Bytes,
    IPv6ChecksumContext ChecksumContext)
{
    public bool IsComplete => Bytes.Length == DeclaredLength;
}

public union IPv6ChecksumContext(IPv6ChecksumContext.KnownAddresses, IPv6ChecksumContext.Unavailable)
{
    public sealed record KnownAddresses(IPv6Address Source, IPv6Address FinalDestination);
    public sealed record Unavailable;
}

public union IPv6ExtensionResult(IPv6UpperLayer, IPv6FragmentPayload, IPv6NoNextHeader, IPv6PayloadUnavailable);

public sealed record IPv6FragmentPayload(IPv6Fragment Fragment, uint DeclaredLength, ReadOnlyMemory<byte> Bytes);
public sealed record IPv6NoNextHeader;
public enum IPv6PayloadFailure { Unsupported, Invalid, Truncated }
public sealed record IPv6PayloadUnavailable(IPv6PayloadFailure Reason);

public sealed record IPv6ExtensionChain(ImmutableArray<IPv6ExtensionHeader> Headers,
    int RemainingOffset, ReadOnlyMemory<byte> RemainingBytes, ImmutableArray<IPv6Diagnostic> Diagnostics,
    IPv6ExtensionResult Result);
