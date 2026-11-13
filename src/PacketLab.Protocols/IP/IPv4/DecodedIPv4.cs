using PacketLab.Protocols.IP;
using PacketLab.Protocols.Udp;
using PacketLab.Protocols.Tcp;

namespace PacketLab.Protocols.IP.IPv4;

public union IPv4DecodeResult(DecodedIPv4, IPv4ParseResult.IncompleteHeader, IPv4ParseResult.InvalidVersion,
    IPv4ParseResult.InvalidHeaderLength, IPv4ParseResult.InvalidTotalLength);

public union IPv4PayloadResult(TcpParseResult, UdpParseResult, IPv4FragmentPayload, UnsupportedIpProtocol);

public sealed record IPv4FragmentPayload(ushort Offset, bool MoreFragments, ushort Identification,
    byte Protocol, uint DeclaredLength, ReadOnlyMemory<byte> Bytes);

public sealed record DecodedIPv4
{
    public IPv4Packet Packet { get; }
    public IPv4PayloadResult Payload { get; }

    private DecodedIPv4(IPv4Packet packet)
    {
        Packet = packet;
        var header = packet.Header;
        var length = (uint)(header.TotalLength - header.HeaderLength);
        Payload = header.MoreFragments || header.FragmentOffset != 0
            ? new IPv4FragmentPayload(header.FragmentOffset, header.MoreFragments, header.Identification,
                header.Protocol, length, packet.Payload)
            : header.Protocol == 6 ? TcpDecoder.Decode(packet)
            : header.Protocol == 17 ? UdpDecoder.Decode(packet)
            : new UnsupportedIpProtocol(header.Protocol, length, packet.Payload);
    }

    public static IPv4DecodeResult Decode(ReadOnlyMemory<byte> data) => IPv4Parser.Parse(data) switch
    {
        IPv4Packet packet => new DecodedIPv4(packet),
        IPv4ParseResult.IncompleteHeader error => error,
        IPv4ParseResult.InvalidVersion error => error,
        IPv4ParseResult.InvalidHeaderLength error => error,
        IPv4ParseResult.InvalidTotalLength error => error,
        null => throw new InvalidOperationException("Uninitialized IPv4 parse result.")
    };
}
