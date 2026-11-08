using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols;

public enum LinkLayerProtocol { Unsupported, Ethernet }

public union ProtocolDecodeResult(EthernetParseResult, ProtocolDecodeResult.EthernetArp,
    ProtocolDecodeResult.EthernetIPv4, ProtocolDecodeResult.EthernetIPv6, ProtocolDecodeResult.UnsupportedLinkLayer)
{
    public sealed record EthernetArp(EthernetFrame Ethernet, ArpParseResult Arp);
    public sealed record EthernetIPv4(EthernetFrame Ethernet, IPv4ParseResult IPv4, UdpParseResult? Udp = null);
    public sealed record EthernetIPv6(EthernetFrame Ethernet, IPv6ParseResult IPv6, UdpParseResult? Udp = null);
    public sealed record UnsupportedLinkLayer(ReadOnlyMemory<byte> RemainingBytes);
}

public static class ProtocolDecoder
{
    public static ProtocolDecodeResult Decode(ReadOnlyMemory<byte> data, LinkLayerProtocol linkLayer) => linkLayer switch
    {
        LinkLayerProtocol.Ethernet => DecodeEthernet(data),
        LinkLayerProtocol.Unsupported => new ProtocolDecodeResult.UnsupportedLinkLayer(data),
        _ => throw new ArgumentOutOfRangeException(nameof(linkLayer))
    };

    private static ProtocolDecodeResult DecodeEthernet(ReadOnlyMemory<byte> data)
    {
        var result = EthernetParser.Parse(data);
        return result switch
        {
            EthernetFrame { EtherType: 0x0806 } frame => new ProtocolDecodeResult.EthernetArp(frame, ArpParser.Parse(frame.RemainingBytes)),
            EthernetFrame { EtherType: 0x0800 } frame => DecodeIPv4(frame),
            EthernetFrame { EtherType: 0x86dd } frame => DecodeIPv6(frame),
            _ => result
        };
    }

    private static ProtocolDecodeResult DecodeIPv4(EthernetFrame frame)
    {
        var result = IPv4Parser.Parse(frame.RemainingBytes);
        return new ProtocolDecodeResult.EthernetIPv4(frame, result,
            result is IPv4Packet packet ? UdpDecoder.Decode(packet) : null);
    }

    private static ProtocolDecodeResult DecodeIPv6(EthernetFrame frame)
    {
        var result = IPv6Parser.Parse(frame.RemainingBytes);
        return new ProtocolDecodeResult.EthernetIPv6(frame, result,
            result is IPv6Packet packet ? UdpDecoder.Decode(packet) : null);
    }
}
