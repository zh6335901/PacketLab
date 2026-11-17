using FsCheck;
using FsCheck.Fluent;
using static PacketLab.Pcap.UnitTests.ReaderAssertions;

namespace PacketLab.Pcap.UnitTests;

public class ReadPacketTests
{
    [Test]
    [Arguments("little-micro", PcapTimestampPrecision.Microseconds, 123456u)]
    [Arguments("big-micro", PcapTimestampPrecision.Microseconds, 123456u)]
    [Arguments("little-nano", PcapTimestampPrecision.Nanoseconds, 123456789u)]
    [Arguments("big-nano", PcapTimestampPrecision.Nanoseconds, 123456789u)]
    public async Task Reading_supported_pcap_variants_preserves_timestamp_lengths_and_payload(
        string sample, PcapTimestampPrecision precision, uint fraction)
    {
        // Arrange
        using var stream = new MemoryStream(PcapSamples.Single(sample));
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        var result = reader.ReadNext();

        // Assert
        var packet = await result.ShouldSucceed();
        await Assert.That(packet.Timestamp.Seconds).IsEqualTo(16909060u);
        await Assert.That(packet.Timestamp.Fraction).IsEqualTo(fraction);
        await Assert.That(packet.Timestamp.Precision).IsEqualTo(precision);
        await Assert.That(packet.CapturedLength).IsEqualTo(3u);
        await Assert.That(packet.OriginalLength).IsEqualTo(5u);
        await Assert.That(packet.OriginalLengthIsLessThanCaptured).IsFalse();
        await Assert.That(Convert.ToHexString(packet.Data.Span)).IsEqualTo("DEADBE");
    }

    [Test]
    [Arguments(0, 100u, 1500000u, 3u, 5u, "DEADBE")]
    [Arguments(1, 99u, 0u, 2u, 1u, "AABB")]
    [Arguments(2, 98u, 0u, 0u, 0u, "")]
    public async Task Unaligned_records_preserve_order_and_independent_lengths(
        int preceding, uint seconds, uint fraction, uint captured, uint original, string data)
    {
        // Arrange
        using var stream = new MemoryStream(Convert.FromHexString(PcapSamples.Multiple));
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();
        for (int i = 0; i < preceding; i++) reader.ReadNext();

        // Act
        var result = reader.ReadNext();

        // Assert
        var packet = await result.ShouldSucceed();
        await Assert.That(packet.Timestamp.Seconds).IsEqualTo(seconds);
        await Assert.That(packet.Timestamp.Fraction).IsEqualTo(fraction);
        await Assert.That(packet.CapturedLength).IsEqualTo(captured);
        await Assert.That(packet.OriginalLength).IsEqualTo(original);
        await Assert.That(packet.OriginalLengthIsLessThanCaptured).IsEqualTo(original < captured);
        await Assert.That(Convert.ToHexString(packet.Data.Span)).IsEqualTo(data);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    public async Task Reading_after_the_last_record_returns_eof(int previousEofReads)
    {
        // Arrange
        using var stream = new MemoryStream(Convert.FromHexString(PcapSamples.Multiple));
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();
        for (int i = 0; i < 3 + previousEofReads; i++) reader.ReadNext();

        // Act
        var result = reader.ReadNext();

        // Assert
        await Assert.That(result is PcapEndOfFile).IsTrue();
    }

    [Test]
    public async Task Header_only_file_has_zero_packets()
    {
        // Arrange
        using var stream = new MemoryStream(Convert.FromHexString(PcapSamples.LittleMicroHeader));
        var openResult = PcapReader.Open(stream);
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        var result = reader.ReadNext();

        // Assert
        await Assert.That(result is PcapEndOfFile).IsTrue();
    }

    [Test]
    [Arguments("little-micro", "00000000", 0u)]
    [Arguments("little-micro", "3F420F00", 999999u)]
    [Arguments("little-micro", "40420F00", 1000000u)]
    [Arguments("little-nano", "FF C9 9A 3B", 999999999u)]
    [Arguments("little-nano", "00 CA 9A 3B", 1000000000u)]
    [Arguments("big-nano", "FFFFFFFF", uint.MaxValue)]
    public async Task Unsigned_timestamps_preserve_fraction_without_normalization(string sample, string fractionHex, uint fraction)
    {
        // Arrange
        // §5 specifies unsigned fields; the reader preserves them rather than imposing wall-clock ordering or normalization.
        var bytes = PcapSamples.Replace(PcapSamples.Single(sample), 24, "FFFFFFFF");
        bytes = PcapSamples.Replace(bytes, 28, fractionHex.Replace(" ", ""));
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream);
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        var packetResult = reader.ReadNext();

        // Assert
        var packet = await packetResult.ShouldSucceed();
        await Assert.That(packet.Timestamp.Seconds).IsEqualTo(uint.MaxValue);
        await Assert.That(packet.Timestamp.Fraction).IsEqualTo(fraction);
    }

    public static IEnumerable<int> RecordHeaderCuts() => Enumerable.Range(1, 15);

    [Test]
    [MethodDataSource(nameof(RecordHeaderCuts))]
    public async Task Reading_reports_truncated_record_header_instead_of_eof(int length)
    {
        // Arrange
        using var stream = new MemoryStream(Convert.FromHexString(PcapSamples.Multiple)[..(43 + length)]);
        var openResult = PcapReader.Open(stream);
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();
        reader.ReadNext();

        // Act
        var errorResult = reader.ReadNext();

        // Assert
        var error = await errorResult.ShouldFail(new PcapError.IncompleteRecordHeader(43, 2, length));
        await Location(error, 43 + length, 2);
    }

    [Test]
    public void Reading_reports_expected_and_received_lengths_when_payload_is_incomplete() =>
        Prop.ForAll((byte[][] preceding, byte[] data, ushort selector) =>
        {
            // Arrange
            byte[] last = [0xca, .. data];
            var file = Records([.. preceding, last]);
            int received = selector % last.Length;
            int start = file.Length - last.Length;
            using var stream = new MemoryStream(file[..(start + received)]);
            if (PcapReader.Open(stream) is not PcapReader reader) return false;
            foreach (var _ in preceding) reader.ReadNext();

            // Act
            var result = reader.ReadNext();

            // Assert
            return result is PcapError error && error.Offset == stream.Length
                && Equals(error.Value, new PcapError.IncompletePacketData(start, preceding.Length + 1, last.Length, received));
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public void Record_data_and_order_survive_subsequent_reads_and_disposal() =>
        Prop.ForAll((byte[][] records) =>
        {
            // Arrange
            using var stream = new MemoryStream(Records(records));
            var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();
            var packets = records.Select(_ => reader.ReadNext() is PcapPacket packet ? packet : throw new InvalidOperationException()).ToArray();
            reader.ReadNext();

            // Act
            stream.Dispose();

            // Assert
            return packets.Select((p, i) => p.Timestamp.Seconds == i && p.Data.Span.SequenceEqual(records[i])).All(equal => equal);
        }).Check(Config.QuickThrowOnFailure);

    private static byte[] Records(byte[][] payloads)
    {
        using var stream = new MemoryStream();
        using var writer = new BinaryWriter(stream);
        writer.Write(Convert.FromHexString(PcapSamples.LittleMicroHeader));
        for (int i = 0; i < payloads.Length; i++)
        {
            writer.Write((uint)i);
            writer.Write(0u);
            writer.Write((uint)payloads[i].Length);
            writer.Write((uint)payloads[i].Length);
            writer.Write(payloads[i]);
        }
        return stream.ToArray();
    }

    [Test]
    public async Task Reading_rejects_missing_payload_even_with_historical_length_metadata()
    {
        // Arrange
        using var stream = new MemoryStream(Convert.FromHexString(PcapSamples.Multiple)[..60]);
        var openResult = PcapReader.Open(stream);
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();
        reader.ReadNext();

        // Act
        var errorResult = reader.ReadNext();

        // Assert
        var error = await errorResult.ShouldFail(new PcapError.IncompletePacketData(59, 2, 2, 1));
        await Location(error, 60, 2);
    }

    [Test]
    [Arguments("03000000")]
    [Arguments("FFFFFFFF")]
    public async Task Capture_within_snaplen_preserves_large_original_length(string snaplen)
    {
        // Arrange
        var bytes = PcapSamples.Replace(PcapSamples.Single("little-micro"), 16, snaplen);
        bytes = PcapSamples.Replace(bytes, 36, "FFFFFFFF");
        using var stream = new MemoryStream(bytes);

        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        var result = reader.ReadNext();

        // Assert
        var packet = await result.ShouldSucceed();
        await Assert.That(packet.OriginalLength).IsEqualTo(uint.MaxValue);
        await Assert.That(packet.CapturedLength).IsEqualTo(3u);
    }

    [Test]
    public async Task Capture_exceeding_snaplen_is_rejected_even_with_large_original_length()
    {
        // Arrange
        var bytes = PcapSamples.Replace(PcapSamples.Single("little-micro"), 16, "02000000");
        bytes = PcapSamples.Replace(bytes, 36, "FFFFFFFF");
        using var stream = new MemoryStream(bytes);

        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        var result = reader.ReadNext();

        // Assert
        var error = await result.ShouldFail(new PcapError.CapturedLengthExceedsSnapLen(24, 1, 3, 2));
        await Location(error, 32, 1);
    }

    [Test]
    [Arguments(3)]
    [Arguments(4)]
    public async Task Payload_at_or_below_configured_limit_is_read(int limit)
    {
        // Arrange
        using var stream = new MemoryStream(PcapSamples.Single("little-micro"));
        var openResult = PcapReader.Open(stream, new CaptureReaderOptions(limit));
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        var packetResult = reader.ReadNext();

        // Assert
        var packet = await packetResult.ShouldSucceed();
        await Assert.That(Convert.ToHexString(packet.Data.Span)).IsEqualTo("DEADBE");
    }

    [Test]
    public async Task Payload_above_configured_limit_is_a_resource_error_even_with_historical_lengths()
    {
        // Arrange
        var bytes = PcapSamples.Replace(Convert.FromHexString(PcapSamples.Multiple), 36, "01000000");
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream, new CaptureReaderOptions(1));
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        var errorResult = reader.ReadNext();

        // Assert
        var error = await errorResult.ShouldFail(new PcapError.PacketLimitExceeded(24, 1, 3, 1));
        await Location(error, 32, 1);
    }

    [Test]
    [Arguments("01000001", 16777217u)]
    [Arguments("00000080", 2147483648u)]
    [Arguments("FFFFFFFF", uint.MaxValue)]
    public async Task Oversized_unsigned_lengths_are_rejected_before_large_allocation(string captured, uint expected)
    {
        // Arrange
        var bytes = PcapSamples.Replace(PcapSamples.Single("little-micro"), 16, "FFFFFFFF");
        bytes = PcapSamples.Replace(bytes, 32, captured);
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream);
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();
        var before = GC.GetAllocatedBytesForCurrentThread();

        // Act
        var errorResult = reader.ReadNext();

        // Assert
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        var error = await errorResult.ShouldFail(new PcapError.PacketLimitExceeded(24, 1, expected, 16 * 1024 * 1024));
        await Location(error, 32, 1);
        // A generous bound avoids allocator-detail assertions while detecting a payload-sized allocation.
        await Assert.That(allocated < 1024 * 1024).IsTrue();
    }

    [Test]
    public async Task Default_limit_accepts_exactly_sixteen_mebibytes()
    {
        // Arrange
        var header = PcapSamples.Replace(PcapSamples.Single("little-micro")[..40], 16, "00000001");
        header = PcapSamples.Replace(header, 32, "0000000100000001");
        var bytes = new byte[40 + 16 * 1024 * 1024];
        header.CopyTo(bytes, 0);
        bytes[40] = 0xde;
        bytes[^1] = 0xbe;
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream);
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        var packetResult = reader.ReadNext();

        // Assert
        var packet = await packetResult.ShouldSucceed();
        await Assert.That(packet.CapturedLength).IsEqualTo(16777216u);
        await Assert.That(packet.Data.Span[0]).IsEqualTo((byte)0xde);
        await Assert.That(packet.Data.Span[^1]).IsEqualTo((byte)0xbe);
    }
}
