using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis;

public static class PcapAnalysis
{
    public static LinkLayerProtocol GetLinkLayer(PcapFileHeader header) => header.LinkType switch
    {
        1 => LinkLayerProtocol.Ethernet,
        _ => LinkLayerProtocol.Unsupported
    };

    public static ProtocolDecodeResult Decode(PcapFileHeader header, PcapPacket packet) =>
        ProtocolDecoder.Decode(packet.Data, GetLinkLayer(header));
}
