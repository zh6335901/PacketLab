using static PacketLab.Pcap.UnitTests.ReaderAssertions;

namespace PacketLab.Pcap.UnitTests;

public class ReadPacketTests
{
    [Test]
    [Arguments("little-micro", PcapByteOrder.LittleEndian, PcapTimestampPrecision.Microseconds, 123456u)]
    [Arguments("big-micro", PcapByteOrder.BigEndian, PcapTimestampPrecision.Microseconds, 123456u)]
    [Arguments("little-nano", PcapByteOrder.LittleEndian, PcapTimestampPrecision.Nanoseconds, 123456789u)]
    [Arguments("big-nano", PcapByteOrder.BigEndian, PcapTimestampPrecision.Nanoseconds, 123456789u)]
    public async Task Reading_supported_pcap_variants_preserves_header_timestamp_lengths_and_payload(
        string sample, PcapByteOrder order, PcapTimestampPrecision precision, uint fraction)
    {
        using var stream = new MemoryStream(PcapSamples.Single(sample));
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var header = reader.Header;
        await Assert.That(header.MajorVersion).IsEqualTo((ushort)2);
        await Assert.That(header.MinorVersion).IsEqualTo((ushort)4);
        await Assert.That(header.ByteOrder).IsEqualTo(order);
        await Assert.That(header.TimestampPrecision).IsEqualTo(precision);
        await Assert.That(header.SnapLen).IsEqualTo(65535u);
        await Assert.That(header.RawLinkType).IsEqualTo(1u);
        await Assert.That(header.LinkType).IsEqualTo((ushort)1);
        await Assert.That(header.Reserved1).IsEqualTo(0u);
        await Assert.That(header.Reserved2).IsEqualTo(0u);
        var packetResult = reader.ReadNext();
        var packet = await packetResult.ShouldSucceed();
        await Assert.That(packet.Timestamp.Seconds).IsEqualTo(16909060u);
        await Assert.That(packet.Timestamp.Fraction).IsEqualTo(fraction);
        await Assert.That(packet.Timestamp.Precision).IsEqualTo(precision);
        await Assert.That(packet.CapturedLength).IsEqualTo(3u);
        await Assert.That(packet.OriginalLength).IsEqualTo(5u);
        await Assert.That(packet.OriginalLengthIsLessThanCaptured).IsFalse();
        await Assert.That(Convert.ToHexString(packet.Data.Span)).IsEqualTo("DEADBE");
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }

    [Test]
    public async Task Unaligned_records_keep_order_and_returned_data_survives_later_reads_and_stream_disposal()
    {
        var stream = new MemoryStream(Convert.FromHexString(PcapSamples.Multiple));
        PcapPacket first;
        PcapPacket second;
        using (stream)
        {
            var openResult = PcapReader.Open(stream);
            var reader = await openResult.ShouldSucceed();
            var firstResult = reader.ReadNext();
            first = await firstResult.ShouldSucceed();
            var secondResult = reader.ReadNext();
            second = await secondResult.ShouldSucceed();
            var thirdResult = reader.ReadNext();
            var third = await thirdResult.ShouldSucceed();
            await Assert.That(first.Timestamp.Seconds).IsEqualTo(100u);
            await Assert.That(first.Timestamp.Fraction).IsEqualTo(1500000u);
            await Assert.That(second.Timestamp.Seconds).IsEqualTo(99u);
            await Assert.That(second.CapturedLength).IsEqualTo(2u);
            await Assert.That(second.OriginalLength).IsEqualTo(1u);
            await Assert.That(second.OriginalLengthIsLessThanCaptured).IsTrue();
            await Assert.That(third.Timestamp.Seconds).IsEqualTo(98u);
            await Assert.That(third.CapturedLength).IsEqualTo(0u);
            await Assert.That(third.OriginalLength).IsEqualTo(0u);
            await Assert.That(third.Data.IsEmpty).IsTrue();
            await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        }
        await Assert.That(Convert.ToHexString(first.Data.Span)).IsEqualTo("DEADBE");
        await Assert.That(Convert.ToHexString(second.Data.Span)).IsEqualTo("AABB");
    }

    [Test]
    public async Task Header_only_file_has_zero_packets()
    {
        using var stream = new MemoryStream(Convert.FromHexString(PcapSamples.LittleMicroHeader));
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
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
        // §5 specifies unsigned fields; the reader preserves them rather than imposing wall-clock ordering or normalization.
        var bytes = PcapSamples.Replace(PcapSamples.Single(sample), 24, "FFFFFFFF");
        bytes = PcapSamples.Replace(bytes, 28, fractionHex.Replace(" ", ""));
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var packetResult = reader.ReadNext();
        var packet = await packetResult.ShouldSucceed();
        await Assert.That(packet.Timestamp.Seconds).IsEqualTo(uint.MaxValue);
        await Assert.That(packet.Timestamp.Fraction).IsEqualTo(fraction);
    }

    public static IEnumerable<int> RecordHeaderCuts() => Enumerable.Range(1, 15);

    [Test]
    [MethodDataSource(nameof(RecordHeaderCuts))]
    public async Task Reading_reports_truncated_record_header_instead_of_eof(int length)
    {
        using var stream = new MemoryStream(Convert.FromHexString(PcapSamples.Multiple)[..(43 + length)]);
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var firstResult = reader.ReadNext();
        await firstResult.ShouldSucceed();
        var errorResult = reader.ReadNext();
        var error = await errorResult.ShouldFail(new PcapError.IncompleteRecordHeader(43, 2, length));
        await Location(error, 43 + length, 2);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    public async Task Reading_reports_expected_and_received_lengths_when_payload_is_incomplete(int length)
    {
        using var stream = new MemoryStream(PcapSamples.Single("big-nano")[..(40 + length)]);
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var errorResult = reader.ReadNext();
        var error = await errorResult.ShouldFail(new PcapError.IncompletePacketData(40, 1, 3, length));
        await Location(error, 40 + length, 1);
    }

    [Test]
    public async Task Reading_rejects_missing_payload_even_with_historical_length_metadata()
    {
        using var stream = new MemoryStream(Convert.FromHexString(PcapSamples.Multiple)[..60]);
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var firstResult = reader.ReadNext();
        await firstResult.ShouldSucceed();
        var errorResult = reader.ReadNext();
        var error = await errorResult.ShouldFail(new PcapError.IncompletePacketData(59, 2, 2, 1));
        await Location(error, 60, 2);
    }

    [Test]
    [Arguments("02000000", false)]
    [Arguments("03000000", true)]
    [Arguments("FFFFFFFF", true)]
    public async Task Snaplen_limits_capture_size_without_limiting_original_length(string snaplen, bool valid)
    {
        // §4/5: captured length cannot exceed SnapLen; original length is retained independently.
        var bytes = PcapSamples.Replace(PcapSamples.Single("little-micro"), 16, snaplen);
        bytes = PcapSamples.Replace(bytes, 36, "FFFFFFFF");
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        if (valid)
        {
            var packetResult = reader.ReadNext();
            var packet = await packetResult.ShouldSucceed();
            await Assert.That(packet.OriginalLength).IsEqualTo(uint.MaxValue);
            await Assert.That(packet.CapturedLength).IsEqualTo(3u);
        }
        else
        {
            var errorResult = reader.ReadNext();
            var error = await errorResult.ShouldFail(new PcapError.CapturedLengthExceedsSnapLen(24, 1, 3, 2));
            await Location(error, 32, 1);
        }
    }

    [Test]
    [Arguments(3)]
    [Arguments(4)]
    public async Task Payload_at_or_below_configured_limit_is_read(int limit)
    {
        using var stream = new MemoryStream(PcapSamples.Single("little-micro"));
        var openResult = PcapReader.Open(stream, new PcapReaderOptions(limit));
        var reader = await openResult.ShouldSucceed();
        var packetResult = reader.ReadNext();
        var packet = await packetResult.ShouldSucceed();
        await Assert.That(Convert.ToHexString(packet.Data.Span)).IsEqualTo("DEADBE");
    }

    [Test]
    public async Task Payload_above_configured_limit_is_a_resource_error_even_with_historical_lengths()
    {
        var bytes = PcapSamples.Replace(Convert.FromHexString(PcapSamples.Multiple), 36, "01000000");
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream, new PcapReaderOptions(1));
        var reader = await openResult.ShouldSucceed();
        var errorResult = reader.ReadNext();
        var error = await errorResult.ShouldFail(new PcapError.PacketLimitExceeded(24, 1, 3, 1));
        await Location(error, 32, 1);
    }

    [Test]
    [Arguments("01000001", 16777217u)]
    [Arguments("00000080", 2147483648u)]
    [Arguments("FFFFFFFF", uint.MaxValue)]
    public async Task Oversized_unsigned_lengths_are_rejected_before_large_allocation(string captured, uint expected)
    {
        var bytes = PcapSamples.Replace(PcapSamples.Single("little-micro"), 16, "FFFFFFFF");
        bytes = PcapSamples.Replace(bytes, 32, captured);
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var before = GC.GetAllocatedBytesForCurrentThread();
        var errorResult = reader.ReadNext();
        var allocated = GC.GetAllocatedBytesForCurrentThread() - before;
        var error = await errorResult.ShouldFail(new PcapError.PacketLimitExceeded(24, 1, expected, 16 * 1024 * 1024));
        await Location(error, 32, 1);
        // A generous bound avoids allocator-detail assertions while detecting a payload-sized allocation.
        await Assert.That(allocated < 1024 * 1024).IsTrue();
    }

    [Test]
    public async Task Default_limit_accepts_exactly_sixteen_mebibytes()
    {
        var header = PcapSamples.Replace(PcapSamples.Single("little-micro")[..40], 16, "00000001");
        header = PcapSamples.Replace(header, 32, "0000000100000001");
        var bytes = new byte[40 + 16 * 1024 * 1024];
        header.CopyTo(bytes, 0);
        bytes[40] = 0xde;
        bytes[^1] = 0xbe;
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var packetResult = reader.ReadNext();
        var packet = await packetResult.ShouldSucceed();
        await Assert.That(packet.CapturedLength).IsEqualTo(16777216u);
        await Assert.That(packet.Data.Span[0]).IsEqualTo((byte)0xde);
        await Assert.That(packet.Data.Span[^1]).IsEqualTo((byte)0xbe);
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }
}
