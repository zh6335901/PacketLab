using System.Collections.Immutable;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.IPv6;

public union IPv6DecodeResult(DecodedIPv6, IPv6ParseResult.IncompleteHeader, IPv6ParseResult.InvalidVersion);

public union IPv6PayloadResult(UdpParseResult, IPv6FragmentPayload, IPv6NoNextHeader,
    IPv6PayloadUnavailable, UnsupportedIpProtocol);

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
        CanBuildChecksumContext = chain.Result is IPv6UpperLayer located &&
            located.ChecksumContext is IPv6ChecksumContext.KnownAddresses;
        // Consume the location result; retain one terminal payload state in the decoded tree.
        Payload = chain.Result switch
        {
            IPv6UpperLayer { Protocol: 17 } upper => UdpDecoder.Decode(upper),
            IPv6UpperLayer upper =>
                new UnsupportedIpProtocol(upper.Protocol, upper.DeclaredLength, upper.Bytes),
            IPv6FragmentPayload fragment => fragment,
            IPv6NoNextHeader end => end,
            IPv6PayloadUnavailable unavailable => unavailable,
            null => throw new InvalidOperationException("Uninitialized IPv6 extension parse result.")
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
