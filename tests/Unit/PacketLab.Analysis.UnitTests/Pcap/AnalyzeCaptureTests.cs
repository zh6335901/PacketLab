using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using TUnit.Assertions.Exceptions;

namespace PacketLab.Analysis.UnitTests.Pcap;

public class AnalyzeCaptureTests
{
    private const string Header = "D4C3B2A1020004000000000000000000FFFF000001000000";
    private const string Records = "0100000040E20100100000003C000000FFFFFFFFFFFF0200000000010806AABB"
        + "02000000000000000300000003000000010203";

    [Test]
    public async Task Returned_raw_and_decoded_bytes_survive_later_reads_and_caller_disposal()
    {
        AnalyzedPacket first;
        ReadOnlyMemory<byte> decodedBytes;
        using (var stream = new MemoryStream(Convert.FromHexString(Header + Records)))
        {
            var reader = Open(stream);
            first = Read(reader);
            decodedBytes = first.Decoding is EthernetDecodeResult ethernet && ethernet is DecodedEthernet parsed
                ? parsed.Frame.RemainingBytes : throw new AssertionException("Expected decoded bytes.");
            await Assert.That(first.RecordNumber).IsEqualTo(1L);
            await Assert.That(first.Packet.Timestamp).IsEqualTo(PcapTimestamp.FromMicroseconds(1, 123456));
            await Assert.That(first.Packet.CapturedLength).IsEqualTo(16u);
            await Assert.That(first.Packet.OriginalLength).IsEqualTo(60u);
            await Assert.That(Read(reader).RecordNumber).IsEqualTo(2L);
            await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
            await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
            await Assert.That(stream.CanRead).IsTrue();
            stream.Position = 0;
            await Assert.That(stream.ReadByte()).IsEqualTo(0xd4);
        }

        await Assert.That(Convert.ToHexString(first.Packet.Data.Span)).IsEqualTo("FFFFFFFFFFFF0200000000010806AABB");
        await Assert.That(Convert.ToHexString(decodedBytes.Span)).IsEqualTo("AABB");
    }

#pragma warning disable PL0003 // Every record must remain readable with the same unsupported link type.
    [Test]
    public async Task Unknown_link_type_allows_raw_reading_deferred_decoding_and_analysis_of_every_record()
    {
        var bytes = Convert.FromHexString(Header + Records);
        bytes[20] = 101;
        using var stream = new MemoryStream(bytes);
        var raw = PcapReader.Open(stream) is PcapReader opened ? opened : throw new AssertionException("Expected a reader.");
        var packet = raw.ReadNext() is PcapPacket read ? read : throw new AssertionException("Expected a packet.");
        await Assert.That(raw.Header.LinkType).IsEqualTo((ushort)101);
        await Assert.That(raw.ReadNext() is PcapPacket).IsTrue();
        await Assert.That(raw.ReadNext() is PcapEndOfFile).IsTrue();
        var deferred = PcapAnalysis.Decode(raw.Header, packet);
        await Assert.That(deferred is ProtocolDecodeResult.UnsupportedLinkLayer unsupported &&
            unsupported.RemainingBytes.Equals(packet.Data)).IsTrue();

        stream.Position = 0;
        var reader = Open(stream);
        await Assert.That(reader.LinkLayer).IsEqualTo(LinkLayerProtocol.Unsupported);
        await Assert.That(reader.Header.LinkType).IsEqualTo((ushort)101);
        for (long number = 1; number <= 2; number++)
        {
            var analyzed = Read(reader);
            await Assert.That(analyzed.RecordNumber).IsEqualTo(number);
            await Assert.That(analyzed.Decoding is ProtocolDecodeResult.UnsupportedLinkLayer result &&
                result.RemainingBytes.Equals(analyzed.Packet.Data)).IsTrue();
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }
#pragma warning restore PL0003

    [Test]
    [Arguments(1, LinkLayerProtocol.Ethernet)]
    [Arguments(101, LinkLayerProtocol.Unsupported)]
    public async Task File_link_type_selects_the_link_layer(byte linkType, LinkLayerProtocol expected)
    {
        var bytes = Convert.FromHexString(Header);
        bytes[20] = linkType;
        using var stream = new MemoryStream(bytes);
        var reader = Open(stream);
        await Assert.That(reader.LinkLayer).IsEqualTo(expected);
    }

    [Test]
    public async Task Raw_packets_can_be_decoded_after_reading_finishes()
    {
        using var stream = new MemoryStream(Convert.FromHexString(Header + Records));
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new AssertionException("Expected a reader.");
        var packet = reader.ReadNext() is PcapPacket read ? read : throw new AssertionException("Expected a packet.");
        var savedBytes = packet.Data.ToArray();
        while (true)
        {
            var next = reader.ReadNext();
            if (next is PcapEndOfFile) break;
            if (next is not PcapPacket) throw new AssertionException("Could not consume the capture to EOF.");
        }
        await Assert.That(packet.Data.Span.SequenceEqual(savedBytes)).IsTrue();
        var decoding = PcapAnalysis.Decode(reader.Header, packet);
        await Assert.That(decoding.Value is not null).IsTrue();
    }

    [Test]
    public async Task Truncated_record_header_reports_relative_location_and_stops_reading()
    {
        var capture = Convert.FromHexString(Header + Records);
        using var stream = new MemoryStream([0xaa, 0xbb, .. capture[..64]]);
        stream.Position = 2;
        var reader = Open(stream);
        Read(reader);
        var error = reader.ReadNext() is PcapError failure ? failure : throw new AssertionException("Expected a file error.");
        await Assert.That(error.Offset).IsEqualTo(64L);
        await Assert.That(error.RecordNumber).IsEqualTo((long?)2);
        await Assert.That(error is PcapError.IncompleteRecordHeader { ReadBytes: 8 }).IsTrue();
        var stoppedAt = stream.Position;
        await Assert.That(reader.ReadNext() is PcapError repeated && repeated.Value.Equals(error.Value)).IsTrue();
        await Assert.That(stream.Position).IsEqualTo(stoppedAt);
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Truncated_packet_data_reports_relative_location_and_stops_reading()
    {
        var capture = Convert.FromHexString(Header + Records);
        using var stream = new MemoryStream([0xaa, 0xbb, .. capture[..74]]);
        stream.Position = 2;
        var reader = Open(stream);
        Read(reader);
        var error = reader.ReadNext() is PcapError failure ? failure : throw new AssertionException("Expected a file error.");
        await Assert.That(error.Offset).IsEqualTo(74L);
        await Assert.That(error.RecordNumber).IsEqualTo((long?)2);
        await Assert.That(error is PcapError.IncompletePacketData { ExpectedBytes: 3, ReadBytes: 2 }).IsTrue();
        var stoppedAt = stream.Position;
        await Assert.That(reader.ReadNext() is PcapError repeated && repeated.Value.Equals(error.Value)).IsTrue();
        await Assert.That(stream.Position).IsEqualTo(stoppedAt);
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Open_failure_preserves_caller_stream_ownership()
    {
        using var stream = new MemoryStream([0xd4]);
        var result = PcapAnalysisReader.Open(stream);
        await Assert.That(result is PcapError error && error is PcapError.IncompleteFileHeader { ReadBytes: 1 }).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Packet_limit_is_enforced_before_protocol_decoding()
    {
        using var stream = new MemoryStream(Convert.FromHexString(Header + Records));
        var result = PcapAnalysisReader.Open(stream, new PcapReaderOptions(15));
        var reader = result is PcapAnalysisReader opened ? opened : throw new AssertionException("Expected a reader.");
        var failure = reader.ReadNext();
        await Assert.That(failure is PcapError error && error is PcapError.PacketLimitExceeded
            { RecordNumber: 1, CapturedLength: 16, MaxPacketBytes: 15 }).IsTrue();
    }

    [Test]
    public async Task Open_exceptions_propagate_without_disposing_the_stream()
    {
        using var stream = new FailingStream(Convert.FromHexString(Header + Records)) { Fail = true };
        var error = await Assert.That(() => PcapAnalysisReader.Open(stream)).Throws<IOException>();
        await Assert.That(error).IsSameReferenceAs(stream.Failure);
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Read_exceptions_are_repeated_without_disposing_the_stream()
    {
        using var stream = new FailingStream(Convert.FromHexString(Header + Records));
        var reader = Open(stream);
        stream.Fail = true;
        var error = await Assert.That(() => reader.ReadNext()).Throws<IOException>();
        await Assert.That(error).IsSameReferenceAs(stream.Failure);
        stream.Fail = false;
        var repeated = await Assert.That(() => reader.ReadNext()).Throws<IOException>();
        await Assert.That(repeated).IsSameReferenceAs(error);
        await Assert.That(stream.CanRead).IsTrue();
    }

    private static PcapAnalysisReader Open(Stream stream) => PcapAnalysisReader.Open(stream) is PcapAnalysisReader reader
        ? reader : throw new AssertionException("Expected an analysis reader.");

    private static AnalyzedPacket Read(PcapAnalysisReader reader) => reader.ReadNext() is AnalyzedPacket packet
        ? packet : throw new AssertionException("Expected an analyzed packet.");

    private sealed class FailingStream(byte[] bytes) : MemoryStream(bytes)
    {
        internal IOException Failure { get; } = new("Read failed.");
        internal bool Fail { get; set; }
        public override int Read(Span<byte> buffer) => Fail ? throw Failure : base.Read(buffer);
    }
}
