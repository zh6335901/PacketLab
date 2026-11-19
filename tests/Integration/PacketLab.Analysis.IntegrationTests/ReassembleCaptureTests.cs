using PacketLab.Analysis.Pcap;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Pcap;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.Udp;

namespace PacketLab.Analysis.IntegrationTests;

public class ReassembleCaptureTests
{
    [Test]
    [Arguments("little")]
    [Arguments("big")]
    public async Task Reference_fragments_reassemble_udp_and_tcp_with_valid_checksums(string order)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", $"ip-reassembly-{order}.pcap"));
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();
        var records = reader.ReadPackets().Select(result => result is PcapPacket packet ? packet : throw new InvalidOperationException()).ToArray();
        var first4 = IPv4(reader.Header, records[0]);
        var first6 = IPv6(reader.Header, records[1]);
        var tail4 = IPv4(reader.Header, records[2]);
        var tail6 = IPv6(reader.Header, records[3]);
        var fragment4 = first4.Payload is IPv4FragmentPayload f4 ? f4 : throw new InvalidOperationException();
        var last4 = tail4.Payload is IPv4FragmentPayload t4 ? t4 : throw new InvalidOperationException();
        var extension6 = first6.Extensions.Single(header => header.Fragment is not null);
        var last6 = tail6.Extensions.Single(header => header.Fragment is not null);
        using var analyzer = new IpReassemblyAnalyzer();

        analyzer.AddIPv4Fragment(1, records[0].Data[14..], first4, fragment4);
        analyzer.AddIPv6Fragment(2, records[1].Data[14..], first6, extension6, extension6.Fragment!);
        var complete4 = analyzer.AddIPv4Fragment(3, records[2].Data[14..], tail4, last4).Single();
        var complete6 = analyzer.AddIPv6Fragment(4, records[3].Data[14..], tail6, last6, last6.Fragment!).Single();

        var udp = complete4.Packet!.Decoding.Value is IPv4DecodeResult { Value: DecodedIPv4 { Payload.Value: UdpParseResult { Value: UdpDatagram datagram } } }
            ? datagram : throw new InvalidOperationException("Expected reassembled UDP.");
        var decoded = complete6.Packet!.Decoding.Value is IPv6DecodeResult { Value: DecodedIPv6 ip } ? ip : throw new InvalidOperationException();
        var tcp = decoded.Payload is TcpParseResult { Value: TcpSegment segment } ? segment : throw new InvalidOperationException("Expected reassembled TCP.");
        await Assert.That(udp.Checksum is UdpChecksumStatus.Match).IsTrue();
        await Assert.That(Convert.ToHexString(udp.Payload.Span)).IsEqualTo("0102030405060708090A0B0C0D0E0F10");
        await Assert.That(tcp.Checksum is TcpChecksumStatus.Match).IsTrue();
        await Assert.That(System.Text.Encoding.ASCII.GetString(tcp.Payload.Span)).IsEqualTo("Hello TCP!!!");
        await Assert.That(decoded.Extensions.Select(header => header.Type).ToArray()).IsEquivalentTo(new byte[] { 0, 60 });
    }

    private static DecodedIPv4 IPv4(PcapFileHeader header, PcapPacket packet) => PcapAnalysis.Decode(header, packet).Value switch
    {
        EthernetDecodeResult { Value: DecodedEthernet { Payload.Value: IPv4DecodeResult { Value: DecodedIPv4 ip } } } => ip,
        _ => throw new InvalidOperationException("Expected IPv4 in the reference capture.")
    };

    private static DecodedIPv6 IPv6(PcapFileHeader header, PcapPacket packet) => PcapAnalysis.Decode(header, packet).Value switch
    {
        EthernetDecodeResult { Value: DecodedEthernet { Payload.Value: IPv6DecodeResult { Value: DecodedIPv6 ip } } } => ip,
        _ => throw new InvalidOperationException("Expected IPv6 in the reference capture.")
    };
}
