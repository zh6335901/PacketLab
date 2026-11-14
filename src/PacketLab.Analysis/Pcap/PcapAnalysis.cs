using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis.Pcap;

public static class PcapAnalysis
{
    public static LinkLayerProtocol GetLinkLayer(PcapFileHeader header) => header.LinkType switch
    {
        1 => LinkLayerProtocol.Ethernet,
        _ => LinkLayerProtocol.Unsupported
    };

    public static ProtocolDecodeResult Decode(PcapFileHeader header, PcapPacket packet) =>
        ProtocolDecoder.Decode(packet.Data, GetLinkLayer(header));
        
    internal static ulong? GetTimestampNanoseconds(PcapTimestamp timestamp)
    {
        var scale = timestamp.Precision == PcapTimestampPrecision.Microseconds ? 1000UL : 1UL;
        var fraction = timestamp.Fraction * scale;
        // PCAP preserves malformed fractions; do not use them to advance reassembly time.
        return fraction < 1_000_000_000UL ? (ulong)timestamp.Seconds * 1_000_000_000UL + fraction : null;
    }
}
