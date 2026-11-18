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
        // Arrange
        var stream = new MemoryStream(Convert.FromHexString(Header + Records));
        using var reader = Open(stream);
        var first = Read(reader);
        var decodedBytes = first.Decoding is EthernetDecodeResult ethernet && ethernet is DecodedEthernet parsed
            ? parsed.Frame.RemainingBytes : throw new AssertionException("Expected decoded bytes.");
        Read(reader);
        reader.ReadNext();

        // Act
        stream.Dispose();

        // Assert
        await Assert.That(Convert.ToHexString(first.Packet.Data.Span)).IsEqualTo("FFFFFFFFFFFF0200000000010806AABB");
        await Assert.That(Convert.ToHexString(decodedBytes.Span)).IsEqualTo("AABB");
    }

    [Test]
    public async Task Reading_preserves_record_number_timestamp_and_lengths()
    {
        // Arrange
        using var stream = new MemoryStream(Convert.FromHexString(Header + Records));
        using var reader = Open(stream);

        // Act
        var first = Read(reader);

        // Assert
        await Assert.That(first.RecordNumber).IsEqualTo(1L);
        await Assert.That(first.Packet.Timestamp).IsEqualTo(PcapTimestamp.FromMicroseconds(1, 123456));
        await Assert.That(first.Packet.CapturedLength).IsEqualTo(16u);
        await Assert.That(first.Packet.OriginalLength).IsEqualTo(60u);
    }

    [Test]
    [Arguments(2)]
    [Arguments(3)]
    public async Task Reading_at_eof_preserves_caller_stream_ownership(int preceding)
    {
        // Arrange
        using var stream = new MemoryStream(Convert.FromHexString(Header + Records));
        using var reader = Open(stream);
        for (int i = 0; i < preceding; i++) reader.ReadNext();

        // Act
        var result = reader.ReadNext();

        // Assert
        await Assert.That(result is PcapEndOfFile).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Deferred_decoding_preserves_bytes_for_an_unknown_link_type()
    {
        // Arrange
        var bytes = Convert.FromHexString(Header + Records);
        bytes[20] = 101;
        using var stream = new MemoryStream(bytes);
        var raw = PcapReader.Open(stream) is PcapReader opened ? opened : throw new AssertionException("Expected a reader.");
        var packet = raw.ReadNext() is PcapPacket read ? read : throw new AssertionException("Expected a packet.");

        // Act
        var deferred = PcapAnalysis.Decode(raw.Header, packet);

        // Assert
        await Assert.That(deferred is ProtocolDecodeResult.UnsupportedLinkLayer unsupported &&
            unsupported.RemainingBytes.Equals(packet.Data)).IsTrue();
    }

    [Test]
    [Arguments(0, 1L)]
    [Arguments(1, 2L)]
    public async Task Unknown_link_type_does_not_prevent_analysis_of_a_record(int preceding, long recordNumber)
    {
        // Arrange
        var bytes = Convert.FromHexString(Header + Records);
        bytes[20] = 101;
        using var stream = new MemoryStream(bytes);
        using var reader = Open(stream);
        for (int i = 0; i < preceding; i++) Read(reader);

        // Act
        var analyzed = Read(reader);

        // Assert
        await Assert.That(analyzed.RecordNumber).IsEqualTo(recordNumber);
        await Assert.That(analyzed.Decoding is ProtocolDecodeResult.UnsupportedLinkLayer result &&
            result.RemainingBytes.Equals(analyzed.Packet.Data)).IsTrue();
    }

    [Test]
    [Arguments(1, LinkLayerProtocol.Ethernet)]
    [Arguments(101, LinkLayerProtocol.Unsupported)]
    public async Task File_link_type_selects_the_link_layer(byte linkType, LinkLayerProtocol expected)
    {
        // Arrange
        var bytes = Convert.FromHexString(Header);
        bytes[20] = linkType;
        using var stream = new MemoryStream(bytes);

        // Act
        var reader = Open(stream);

        // Assert
        await Assert.That(reader.LinkLayer).IsEqualTo(expected);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Truncated_record_header_reports_relative_location_and_stops_reading(bool repeated)
    {
        // Arrange
        var capture = Convert.FromHexString(Header + Records);
        using var stream = new MemoryStream([0xaa, 0xbb, .. capture[..64]]);
        stream.Position = 2;
        using var reader = Open(stream);
        Read(reader);
        if (repeated) reader.ReadNext();

        // Act
        var result = reader.ReadNext();

        // Assert
        var error = result is PcapError failure ? failure : throw new AssertionException("Expected a file error.");
        await Assert.That(error.Offset).IsEqualTo(64L);
        await Assert.That(error.RecordNumber).IsEqualTo((long?)2);
        await Assert.That(error is PcapError.IncompleteRecordHeader { ReadBytes: 8 }).IsTrue();
        await Assert.That(stream.Position).IsEqualTo(66L);
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Truncated_packet_data_reports_relative_location_and_stops_reading(bool repeated)
    {
        // Arrange
        var capture = Convert.FromHexString(Header + Records);
        using var stream = new MemoryStream([0xaa, 0xbb, .. capture[..74]]);
        stream.Position = 2;
        using var reader = Open(stream);
        Read(reader);
        if (repeated) reader.ReadNext();

        // Act
        var result = reader.ReadNext();

        // Assert
        var error = result is PcapError failure ? failure : throw new AssertionException("Expected a file error.");
        await Assert.That(error.Offset).IsEqualTo(74L);
        await Assert.That(error.RecordNumber).IsEqualTo((long?)2);
        await Assert.That(error is PcapError.IncompletePacketData { ExpectedBytes: 3, ReadBytes: 2 }).IsTrue();
        await Assert.That(stream.Position).IsEqualTo(76L);
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Open_failure_preserves_caller_stream_ownership()
    {
        // Arrange
        using var stream = new MemoryStream([0xd4]);

        // Act
        var result = PcapAnalysisReader.Open(stream);

        // Assert
        await Assert.That(result is PcapError error && error is PcapError.IncompleteFileHeader { ReadBytes: 1 }).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Packet_limit_is_enforced_before_protocol_decoding()
    {
        // Arrange
        using var stream = new MemoryStream(Convert.FromHexString(Header + Records));
        var result = PcapAnalysisReader.Open(stream, new PcapReaderOptions(15));
        var reader = result is PcapAnalysisReader opened ? opened : throw new AssertionException("Expected a reader.");

        // Act
        var failure = reader.ReadNext();

        // Assert
        await Assert.That(failure is PcapError error && error is PcapError.PacketLimitExceeded
        { RecordNumber: 1, CapturedLength: 16, MaxPacketBytes: 15 }).IsTrue();
    }

    [Test]
    public async Task Open_exceptions_propagate_without_disposing_the_stream()
    {
        // Arrange
        using var stream = new FailingStream(Convert.FromHexString(Header + Records)) { Fail = true };

        // Act
        Action act = () => PcapAnalysisReader.Open(stream);

        // Assert
        var error = await Assert.That(act).Throws<IOException>();
        await Assert.That(error).IsSameReferenceAs(stream.Failure);
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Read_exceptions_are_repeated_without_disposing_the_stream(bool repeated)
    {
        // Arrange
        using var stream = new FailingStream(Convert.FromHexString(Header + Records));
        using var reader = Open(stream);
        stream.Fail = true;
        if (repeated)
        {
            try { reader.ReadNext(); } catch (IOException) { }
            stream.Fail = false;
        }

        // Act
        Action act = () => reader.ReadNext();

        // Assert
        var error = await Assert.That(act).Throws<IOException>();
        await Assert.That(error).IsSameReferenceAs(stream.Failure);
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
