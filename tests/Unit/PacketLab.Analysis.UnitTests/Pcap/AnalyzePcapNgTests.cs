using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using static PacketLab.Testing.PcapNgSamples;

namespace PacketLab.Analysis.UnitTests.Pcap;

public class AnalyzePcapNgTests
{
    [Test]
    public async Task Unsupported_interfaces_do_not_prevent_later_ethernet_analysis()
    {
        byte[] frame = Convert.FromHexString("FFFFFFFFFFFF0200000000010806AABB");
        using var stream = new MemoryStream([.. Section(), .. Interface(link: 101), .. Interface(),
            .. Packet([1], id: 0), .. Packet(frame, id: 1, options: Text(1, "retained"))]);
        using var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened : throw new InvalidOperationException();

        var first = reader.ReadNext() is AnalyzedPcapNgPacket unsupported ? unsupported : throw new InvalidOperationException();
        var second = reader.ReadNext() is AnalyzedPcapNgPacket supported ? supported : throw new InvalidOperationException();

        await Assert.That(first.Decoding is ProtocolDecodeResult.UnsupportedLinkLayer).IsTrue();
        await Assert.That(second.Decoding is EthernetDecodeResult decoded && decoded is DecodedEthernet).IsTrue();
        await Assert.That(second.Packet.Interface.Id).IsEqualTo(1u);
        await Assert.That(second.RecordNumber).IsEqualTo(2L);
        await Assert.That(second.Packet.Comments.Single()).IsEqualTo("retained");
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(second.Packet.Data.Span.SequenceEqual(frame)).IsTrue();
    }
}
