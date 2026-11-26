using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using static PacketLab.Testing.PcapNgSamples;

namespace PacketLab.Analysis.UnitTests.Pcap;

public class AnalyzePcapNgTests
{
    [Test]
    public async Task Each_packet_uses_its_own_interfaces_link_type()
    {
        byte[] frame = Convert.FromHexString("FFFFFFFFFFFF0200000000010806AABB");
        using var stream = new MemoryStream([.. Section(), .. Interface(link: 101), .. Interface(),
            .. Packet(frame, id: 0), .. Packet(frame, id: 1)]);
        var reader = PcapNgReader.Open(stream, PcapNgReaderOptions.Default) is PcapNgReader opened ? opened : throw new InvalidOperationException();
        var first = reader.ReadNext() is PcapNgPacket packet1 ? packet1 : throw new InvalidOperationException();
        var second = reader.ReadNext() is PcapNgPacket packet2 ? packet2 : throw new InvalidOperationException();

        var unsupported = PcapAnalysis.Decode(first);
        var supported = PcapAnalysis.Decode(second);

        await Assert.That(unsupported is ProtocolDecodeResult.UnsupportedLinkLayer raw && raw.RemainingBytes.Span.SequenceEqual(frame)).IsTrue();
        await Assert.That(supported is EthernetDecodeResult { Value: DecodedEthernet }).IsTrue();
    }
}
