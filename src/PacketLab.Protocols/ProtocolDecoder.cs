using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.Arp;

namespace PacketLab.Protocols;

public enum LinkLayerProtocol { Unsupported, Ethernet }

public union ProtocolDecodeResult(EthernetParseResult, ProtocolDecodeResult.EthernetArp, ProtocolDecodeResult.UnsupportedLinkLayer)
{
    public sealed record EthernetArp(EthernetFrame Ethernet, ArpParseResult Arp);
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
        return result is EthernetFrame { EtherType: 0x0806 } frame
            ? new ProtocolDecodeResult.EthernetArp(frame, ArpParser.Parse(frame.RemainingBytes))
            : result;
    }
}
