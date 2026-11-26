using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.Arp;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzePcapNgFileTests
{
    [Test]
    public async Task Mixed_file_preserves_packet_order_and_decodes_arp_across_sections()
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "PcapNg", "mixed.pcapng"));
        var reader = PcapNgReader.Open(stream, PcapNgReaderOptions.Default) is PcapNgReader opened ? opened : throw new InvalidOperationException();

        var first = Read(reader);
        var second = Read(reader);
        var third = Read(reader);

        await Assert.That(PcapAnalysis.Decode(first) is ProtocolDecodeResult.UnsupportedLinkLayer).IsTrue();
        await Assert.That(PcapAnalysis.Decode(second) is EthernetDecodeResult ethernet && ethernet is DecodedEthernet decoded && decoded.Payload is ArpParseResult).IsTrue();
        await Assert.That(third.Interface.Section.ByteOrder).IsEqualTo(PcapByteOrder.BigEndian);
        await Assert.That(third.Data.Span.SequenceEqual(second.Data.Span)).IsTrue();
        await Assert.That(third.Timestamp!.Value.ToString()).IsEqualTo("1.234567890 s since Unix epoch");
        await Assert.That(third.Comments.Single()).IsEqualTo("capture note");
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }

    private static PcapNgPacket Read(PcapNgReader reader) => reader.ReadNext() is PcapNgPacket packet
        ? packet : throw new InvalidOperationException("Expected analyzed PCAPNG packet.");
}
