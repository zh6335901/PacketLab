using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Protocols;

public enum LinkLayerProtocol { Unsupported, Ethernet }

public union ProtocolDecodeResult(EthernetParseResult, ProtocolDecodeResult.EthernetArp,
    ProtocolDecodeResult.EthernetIPv4, ProtocolDecodeResult.EthernetIPv6, ProtocolDecodeResult.UnsupportedLinkLayer)
{
    public sealed record EthernetArp(EthernetFrame Ethernet, ArpParseResult Arp);
    public sealed record EthernetIPv4(EthernetFrame Ethernet, IPv4ParseResult IPv4);
    public sealed record EthernetIPv6(EthernetFrame Ethernet, IPv6ParseResult IPv6);
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
            EthernetFrame { EtherType: 0x0800 } frame => new ProtocolDecodeResult.EthernetIPv4(frame, IPv4Parser.Parse(frame.RemainingBytes)),
            EthernetFrame { EtherType: 0x86dd } frame => new ProtocolDecodeResult.EthernetIPv6(frame, IPv6Parser.Parse(frame.RemainingBytes)),
            _ => result
        };
    }
}
