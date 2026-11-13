using PacketLab.Analysis.Pcap;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Protocols.IP.Reassembly;
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
    public async Task Reference_capture_reassembles_udp_and_tcp_with_valid_checksums(string order)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", $"ip-reassembly-{order}.pcap"));
        using var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened : throw new InvalidOperationException();
        var events = new List<IpReassemblyEvent>();
        var records = new List<AnalyzedPacket>();
        while (reader.ReadNext() is AnalyzedPacket packet)
        {
            records.Add(packet);
            events.AddRange(reader.ReassemblyEvents);
        }
        events.AddRange(reader.ReassemblyEvents);
        var v4 = Decoding(events.Single(x => x.DatagramNumber == 1 && x.Status == IpReassemblyStatus.Complete));
        var udp = v4 is IPv4DecodeResult ip4 && ip4 is DecodedIPv4 d4 && d4.Payload is UdpParseResult p4 && p4 is UdpDatagram u4
            ? u4 : throw new InvalidOperationException("Expected reassembled UDP");
        await Assert.That(udp.Checksum is UdpChecksumStatus.Match).IsTrue();
        await Assert.That(Convert.ToHexString(udp.Payload.Span)).IsEqualTo("0102030405060708090A0B0C0D0E0F10");
        var v6 = Decoding(events.Single(x => x.DatagramNumber == 2 && x.Status == IpReassemblyStatus.Complete));
        var decoded = v6 is IPv6DecodeResult ip6 && ip6 is DecodedIPv6 d6 ? d6 : throw new InvalidOperationException();
        var tcp = decoded.Payload is TcpParseResult p6 && p6 is TcpSegment t6 ? t6 : throw new InvalidOperationException("Expected reassembled TCP");
        await Assert.That(tcp.Checksum is TcpChecksumStatus.Match).IsTrue();
        await Assert.That(System.Text.Encoding.ASCII.GetString(tcp.Payload.Span)).IsEqualTo("Hello TCP!!!");
        await Assert.That(decoded.Extensions.Select(x => x.Type).ToArray()).IsEquivalentTo(new byte[] { 0, 60 });
        await Assert.That(records.Count).IsEqualTo(14);
        await Assert.That(records[2].Packet.Data.Length).IsEqualTo(50);
        await Assert.That(events.Last().Reason).IsEqualTo(IpReassemblyAnalysisReason.EndOfCapture);
        await Assert.That(events.Last().RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 10 });
        await Assert.That(events.Count(x => x.Status == IpReassemblyStatus.Complete)).IsEqualTo(3);
        await Assert.That(events.Count(x => x.Status == IpReassemblyStatus.Atomic)).IsEqualTo(1);
        await Assert.That(events.Count(x => x.Status == IpReassemblyStatus.Truncated)).IsEqualTo(2);
        await Assert.That(events.Count(x => x.Status == IpReassemblyStatus.Conflict)).IsEqualTo(2);
    }

    private static ReassembledIpDecoding Decoding(IpReassemblyEvent item) => item.Packet!.Decoding;
}
