using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;

namespace PacketLab.Analysis.UnitTests.Pcap;

public class AnalyzeCaptureTests
{
    private const string Header = "D4C3B2A1020004000000000000000000FFFF000001000000";
    private const string Records = "0100000040E20100100000003C000000FFFFFFFFFFFF0200000000010806AABB"
        + "02000000000000000300000003000000010203";

    [Test]
    public async Task Packets_can_be_decoded_after_reading_and_stream_disposal()
    {
        var stream = new MemoryStream(Convert.FromHexString(Header + Records));
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();
        var first = reader.ReadNext() is PcapPacket packet ? packet : throw new InvalidOperationException();
        _ = reader.ReadPackets().ToArray();
        stream.Dispose();

        var decoding = PcapAnalysis.Decode(reader.Header, first);

        var frame = decoding is EthernetDecodeResult { Value: DecodedEthernet value } ? value : throw new InvalidOperationException();
        await Assert.That(Convert.ToHexString(frame.Frame.RemainingBytes.Span)).IsEqualTo("AABB");
        await Assert.That(Convert.ToHexString(first.Data.Span)).IsEqualTo("FFFFFFFFFFFF0200000000010806AABB");
    }

    [Test]
    public async Task Unknown_link_type_preserves_packet_bytes_for_deferred_decoding()
    {
        var bytes = Convert.FromHexString(Header + Records);
        bytes[20] = 101;
        using var stream = new MemoryStream(bytes);
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();
        var packet = reader.ReadNext() is PcapPacket read ? read : throw new InvalidOperationException();

        var decoding = PcapAnalysis.Decode(reader.Header, packet);

        await Assert.That(decoding is ProtocolDecodeResult.UnsupportedLinkLayer unsupported &&
            unsupported.RemainingBytes.Equals(packet.Data)).IsTrue();
    }

    [Test]
    [Arguments(1, LinkLayerProtocol.Ethernet)]
    [Arguments(101, LinkLayerProtocol.Unsupported)]
    public async Task File_link_type_selects_the_link_layer(byte linkType, LinkLayerProtocol expected)
    {
        var bytes = Convert.FromHexString(Header);
        bytes[20] = linkType;
        using var stream = new MemoryStream(bytes);
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();

        var linkLayer = PcapAnalysis.GetLinkLayer(reader.Header);

        await Assert.That(linkLayer).IsEqualTo(expected);
    }

    [Test]
    [Arguments(PcapTimestampPrecision.Microseconds, 1u, 1_000_001_000UL)]
    [Arguments(PcapTimestampPrecision.Nanoseconds, 1u, 1_000_000_001UL)]
    [Arguments(PcapTimestampPrecision.Nanoseconds, 500_000_000u, 1_500_000_000UL)]
    [Arguments(PcapTimestampPrecision.Microseconds, 1_000_000u, null)]
    [Arguments(PcapTimestampPrecision.Nanoseconds, 1_000_000_000u, null)]
    public async Task Timestamp_conversion_respects_precision_and_rejects_invalid_fractions(
        PcapTimestampPrecision precision, uint fraction, ulong? expected)
    {
        var timestamp = precision == PcapTimestampPrecision.Microseconds
            ? PcapTimestamp.FromMicroseconds(1, fraction) : PcapTimestamp.FromNanoseconds(1, fraction);

        var nanoseconds = PcapAnalysis.GetTimestampNanoseconds(timestamp);

        await Assert.That(nanoseconds).IsEqualTo(expected);
    }
}
