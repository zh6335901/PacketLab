using PacketLab.Protocols.Ethernet;

namespace PacketLab.Protocols;

public enum LinkLayerProtocol { Unsupported, Ethernet }

public union ProtocolDecodeResult(EthernetDecodeResult, ProtocolDecodeResult.UnsupportedLinkLayer)
{
    public sealed record UnsupportedLinkLayer(ReadOnlyMemory<byte> RemainingBytes);
}

public static class ProtocolDecoder
{
    public static ProtocolDecodeResult Decode(ReadOnlyMemory<byte> data, LinkLayerProtocol linkLayer) => linkLayer switch
    {
        LinkLayerProtocol.Ethernet => DecodedEthernet.Decode(data),
        LinkLayerProtocol.Unsupported => new ProtocolDecodeResult.UnsupportedLinkLayer(data),
        _ => throw new ArgumentOutOfRangeException(nameof(linkLayer))
    };
}
