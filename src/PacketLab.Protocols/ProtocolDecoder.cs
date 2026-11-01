using PacketLab.Protocols.Ethernet;

namespace PacketLab.Protocols;

public enum LinkLayerProtocol { Unsupported, Ethernet }

public union ProtocolDecodeResult(EthernetParseResult, ProtocolDecodeResult.UnsupportedLinkLayer)
{
    public sealed record UnsupportedLinkLayer(ReadOnlyMemory<byte> RemainingBytes);
}

public static class ProtocolDecoder
{
    public static ProtocolDecodeResult Decode(ReadOnlyMemory<byte> data, LinkLayerProtocol linkLayer) => linkLayer switch
    {
        LinkLayerProtocol.Ethernet => EthernetParser.Parse(data),
        LinkLayerProtocol.Unsupported => new ProtocolDecodeResult.UnsupportedLinkLayer(data),
        _ => throw new ArgumentOutOfRangeException(nameof(linkLayer))
    };
}
