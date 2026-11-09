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

public enum IPv6ChainStatus { UpperLayer, NoNextHeader, Unsupported, ReassemblyRequired, Invalid, Truncated }

public enum IPv6DiagnosticCode
{
    PayloadTruncated, HeaderTruncated, HeaderExceedsPayload, InvalidHeaderLength,
    InvalidOptions, MissingJumboPayload, InvalidJumboPayload, JumboFragment,
    InvalidHopByHopPosition, DuplicateFragment, ReassemblyRequired, EncryptedEsp,
    UnsupportedNextHeader, FinalDestinationUnavailable, SourceAddressUnavailable
}

public sealed record IPv6Diagnostic(IPv6DiagnosticCode Code, int Offset, string Message);

public sealed record IPv6UpperLayer(byte Protocol, int Offset, uint DeclaredLength, ReadOnlyMemory<byte> Bytes)
{
    public bool IsComplete => Bytes.Length == DeclaredLength;
}

public sealed record IPv6ChecksumContext(IPv6Address Source, IPv6Address FinalDestination,
    byte Protocol, uint UpperLayerLength);

#pragma warning disable PL0001 // Preserve the existing low-level parser API; DecodedIPv6 exposes terminal states as a union.
public sealed record IPv6ExtensionChain(ImmutableArray<IPv6ExtensionHeader> Headers, IPv6ChainStatus Status,
    int RemainingOffset, ReadOnlyMemory<byte> RemainingBytes, IPv6UpperLayer? UpperLayer,
    IPv6ChecksumContext? ChecksumContext, ImmutableArray<IPv6Diagnostic> Diagnostics);
#pragma warning restore PL0001
