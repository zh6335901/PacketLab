using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Protocols.Udp;

internal static class UdpDecoder
{
    internal static UdpParseResult Decode(IPv4Packet packet) =>
        UdpParser.Parse(packet.Payload, (uint)(packet.Header.TotalLength - packet.Header.HeaderLength),
            false, IpChecksumAddresses.Sum(packet.Header));

    internal static UdpParseResult Decode(IPv6UpperLayer upper) =>
        UdpParser.Parse(upper.Bytes, upper.DeclaredLength, true, IpChecksumAddresses.Sum(upper.ChecksumContext));
}
