using System.Collections.Immutable;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.IPv6;

public union IPv6DecodeResult(DecodedIPv6, IPv6ParseResult.IncompleteHeader, IPv6ParseResult.InvalidVersion);

public union IPv6PayloadResult(UdpParseResult, IPv6FragmentPayload, IPv6NoNextHeader,
    IPv6PayloadUnavailable, UnsupportedIpProtocol);

public sealed record IPv6FragmentPayload(IPv6Fragment Fragment, uint DeclaredLength, ReadOnlyMemory<byte> Bytes);
public sealed record IPv6NoNextHeader;
public enum IPv6PayloadFailure { Unsupported, Invalid, Truncated }
public sealed record IPv6PayloadUnavailable(IPv6PayloadFailure Reason);

public sealed record DecodedIPv6
{
    public IPv6Header Header { get; }
    public IPv6Payload Capture { get; }
    public ImmutableArray<IPv6ExtensionHeader> Extensions { get; }
    public ImmutableArray<IPv6Diagnostic> Diagnostics { get; }
    public int RemainingOffset { get; }
    public ReadOnlyMemory<byte> RemainingBytes { get; }
    public IPv6PayloadResult Payload { get; }
    public bool CanBuildChecksumContext { get; }

    private DecodedIPv6(IPv6Packet packet)
    {
        Header = packet.Header;
        Capture = packet.Payload;
        var chain = packet.Extensions;
        Extensions = chain.Headers;
        Diagnostics = chain.Diagnostics;
        RemainingOffset = chain.RemainingOffset;
        RemainingBytes = chain.RemainingBytes;
        CanBuildChecksumContext = chain.ChecksumContext is not null;
        // Consume the location result; retain one terminal payload state in the decoded tree.
        Payload = chain.Status switch
        {
            IPv6ChainStatus.UpperLayer when chain.UpperLayer is { Protocol: 17 } upper =>
                UdpDecoder.Decode(upper, chain.ChecksumContext),
            IPv6ChainStatus.UpperLayer when chain.UpperLayer is { } upper =>
                new UnsupportedIpProtocol(upper.Protocol, upper.DeclaredLength, upper.Bytes),
            IPv6ChainStatus.ReassemblyRequired when chain.Headers[^1].Fragment is { } fragment
                && packet.Payload is IPv6Payload.KnownLength known =>
                new IPv6FragmentPayload(fragment, known.DeclaredLength - (uint)(chain.RemainingOffset - 40), chain.RemainingBytes),
            IPv6ChainStatus.NoNextHeader => new IPv6NoNextHeader(),
            IPv6ChainStatus.Unsupported => new IPv6PayloadUnavailable(IPv6PayloadFailure.Unsupported),
            IPv6ChainStatus.Invalid => new IPv6PayloadUnavailable(IPv6PayloadFailure.Invalid),
            IPv6ChainStatus.Truncated => new IPv6PayloadUnavailable(IPv6PayloadFailure.Truncated),
            _ => throw new InvalidOperationException("Inconsistent IPv6 extension parse result.")
        };
    }

    public static IPv6DecodeResult Decode(ReadOnlyMemory<byte> data) => IPv6Parser.Parse(data) switch
    {
        IPv6Packet packet => new DecodedIPv6(packet),
        IPv6ParseResult.IncompleteHeader error => error,
        IPv6ParseResult.InvalidVersion error => error,
        null => throw new InvalidOperationException("Uninitialized IPv6 parse result.")
    };
}
