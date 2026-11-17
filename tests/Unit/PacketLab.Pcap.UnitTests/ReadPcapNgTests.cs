using FsCheck;
using FsCheck.Fluent;
using System.Numerics;
using PacketLab.Testing;
using static PacketLab.Testing.PcapNgSamples;

namespace PacketLab.Pcap.UnitTests;

public class ReadPcapNgTests
{
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Reading_preserves_interface_packet_metadata_and_high_timestamp_bits(bool big)
    {
        byte[] file = [.. Section(big, options: Text(4, "dumpcap", big)),
            .. Interface(big, options: [.. Text(2, "eth0", big), .. Text(3, "wired", big), .. Option(9, [9], big),
                .. Option(14, I64(-2, big), big), .. Option(0, [], big)]),
            .. Packet([0xde, 0xad, 0xbe], big, time: 5_123456789, original: 100,
                options: [.. Text(1, "hello", big), .. Text(1, "世界", big), .. Option(2999, [1, 2], big)])];
        using var stream = new MemoryStream(file);
        var reader = Open(stream);

        var packet = Read(reader);

        await Assert.That(packet.Interface.Name).IsEqualTo("eth0");
        await Assert.That(packet.Interface.Description).IsEqualTo("wired");
        await Assert.That(packet.Interface.Section.Options[0].Text).IsEqualTo("dumpcap");
        await Assert.That(packet.Timestamp).IsEqualTo((PcapNgTimestamp?)new PcapNgTimestamp(5_123456789, 9, -2));
        await Assert.That(packet.Timestamp!.Value.ToString()).IsEqualTo("3.123456789 s since Unix epoch");
        await Assert.That(packet.CapturedLength).IsEqualTo(3u);
        await Assert.That(packet.OriginalLength).IsEqualTo(100u);
        await Assert.That(Convert.ToHexString(packet.Data.Span)).IsEqualTo("DEADBE");
        await Assert.That(string.Join("|", packet.Comments)).IsEqualTo("hello|世界");
        await Assert.That(Convert.ToHexString(packet.Options[2].Value.Span)).IsEqualTo("0102");
    }

    [Test]
    public async Task Mixed_sections_reset_interface_ids_and_preserve_capture_order()
    {
        using var stream = new MemoryStream([
            .. Section(), .. Interface(link: 101), .. Interface(options: Option(9, [0x8a])),
            .. Packet([1], id: 1, time: 1536), .. Packet([2], id: 0, time: 2),
            .. Section(true), .. Interface(true, link: 1), .. Packet([3], true, time: 1)]);
        var reader = Open(stream);

        var first = Read(reader);
        var second = Read(reader);
        var third = Read(reader);

        await Assert.That(first.Interface.Id).IsEqualTo(1u);
        await Assert.That(first.Timestamp!.Value.ToString()).IsEqualTo("1.5000000000 s since Unix epoch");
        await Assert.That(second.Interface.LinkType).IsEqualTo((ushort)101);
        await Assert.That(third.Interface.Id).IsEqualTo(0u);
        await Assert.That(third.Interface.Section.Number).IsEqualTo(1L);
        await Assert.That(third.Interface.Section.ByteOrder).IsEqualTo(PcapByteOrder.BigEndian);
        await Assert.That(new[] { first.Data.Span[0], second.Data.Span[0], third.Data.Span[0] }.SequenceEqual(new byte[] { 1, 2, 3 })).IsTrue();
        await Assert.That(reader.Sections.Count).IsEqualTo(2);
        await Assert.That(reader.Interfaces.Count).IsEqualTo(3);
    }

    [Test]
    [Arguments(0u, 5u)]
    [Arguments(3u, 3u)]
    public async Task Simple_packets_use_interface_zero_snaplen_and_have_no_timestamp(uint snap, uint captured)
    {
        byte[] payload = [1, 2, 3, 4, 5];
        using var stream = new MemoryStream([.. Section(), .. Interface(snap: snap), .. Simple(payload[..(int)captured], 5)]);
        var reader = Open(stream);

        var packet = Read(reader);

        await Assert.That(packet.Timestamp).IsNull();
        await Assert.That(packet.Kind).IsEqualTo(PcapNgPacketKind.Simple);
        await Assert.That(packet.CapturedLength).IsEqualTo(captured);
        await Assert.That(packet.OriginalLength).IsEqualTo(5u);
        await Assert.That(packet.Interface.Id).IsEqualTo(0u);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Obsolete_packet_blocks_preserve_drop_count(bool big)
    {
        var packet = Packet([1], big, type: 2);
        U16(17, big).CopyTo(packet, 10);
        using var stream = new MemoryStream([.. Section(big), .. Interface(big), .. packet]);
        var reader = Open(stream);

        var result = Read(reader);

        await Assert.That(result.Details is PcapNgPacketDetails.Obsolete { DropsCount: 17 }).IsTrue();
        await Assert.That(result.Timestamp!.Value.RawValue).IsEqualTo(1_123456UL);
    }

    [Test]
    public async Task Unknown_blocks_are_skipped_only_after_validating_their_framing()
    {
        using var stream = new MemoryStream([.. Section(), .. Block(0xbad, [1, 2, 3, 4]), .. Interface(), .. Packet([7])]);
        var reader = Open(stream);

        var packet = Read(reader);

        await Assert.That(packet.Data.Span[0]).IsEqualTo((byte)7);
    }

    [Test]
    [Arguments(0)]
    [Arguments(2)]
    public async Task Compatible_section_versions_allow_empty_captures(int minor)
    {
        using var stream = new MemoryStream(Section(length: 0, minor: (ushort)minor));
        var reader = Open(stream);

        var result = reader.ReadNext();

        await Assert.That(result is PcapEndOfFile).IsTrue();
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public void Packet_payload_and_raw_timestamp_round_trip_for_arbitrary_bytes() =>
        Prop.ForAll((byte[] data, ulong timestamp, (bool Big, byte Resolution) settings) =>
        {
            var (big, resolution) = settings;
            using var stream = new MemoryStream([.. Section(big), .. Interface(big, options: Option(9, [resolution], big)), .. Packet(data, big, time: timestamp)]);
            var reader = Open(stream);
            var packet = Read(reader);
            reader.ReadNext();
            stream.Dispose();

            return packet.Data.Span.SequenceEqual(data) && packet.Timestamp == new PcapNgTimestamp(timestamp, resolution, 0);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(6, 1234567UL, 0L, "1.234567 s since Unix epoch", 1234567000UL)]
    [Arguments(9, 1234567890UL, 0L, "1.234567890 s since Unix epoch", 1234567890UL)]
    [Arguments(0x81, 3UL, -1L, "0.5 s since Unix epoch", 500000000UL)]
    [Arguments(10, 1UL, 0L, "0.0000000001 s since Unix epoch", 0UL)]
    [Arguments(0, 4UL, 1L, "5 s since Unix epoch", 5000000000UL)]
    public async Task Timestamp_formatting_and_reassembly_conversion_use_exact_integer_arithmetic(int resolution, ulong ticks, long offset, string text, ulong nanoseconds)
    {
        var timestamp = new PcapNgTimestamp(ticks, (byte)resolution, offset);

        await Assert.That(timestamp.ToString()).IsEqualTo(text);
        await Assert.That(timestamp.GetNanoseconds()).IsEqualTo((ulong?)nanoseconds);
    }

    [Test]
    [Arguments(ulong.MaxValue, 0, long.MaxValue)]
    [Arguments(0UL, 0, -1L)]
    [Arguments(1UL, 127, -1L)]
    public async Task Timestamps_outside_reassembly_range_are_not_wrapped(ulong ticks, int resolution, long offset)
    {
        var timestamp = new PcapNgTimestamp(ticks, (byte)resolution, offset);

        await Assert.That(timestamp.GetNanoseconds()).IsNull();
        await Assert.That(timestamp.UnixTimeNumerator).IsEqualTo((BigInteger)ticks + (BigInteger)offset * timestamp.UnitsPerSecond);
    }

    [Test]
    public void Truncation_inside_any_block_is_a_located_sticky_error() =>
        Prop.ForAll((ushort selector) =>
        {
            byte[] file = [.. Section(), .. Interface(), .. Packet([1, 2, 3], options: Text(1, "note"))];
            int cut = 1 + selector % (file.Length - 1);
            if (cut is 28 or 48) return true;
            using var stream = new MemoryStream(file[..cut]);
            var opened = CaptureReader.Open(stream);
            if (opened is PcapError openError) return openError.Offset == cut;
            if (opened is not CaptureReader reader) return false;
            var result = reader.ReadNext();
            if (result is not PcapError error) return false;

            return error.Offset == cut && reader.ReadNext() is PcapError repeated && Equals(error.Value, repeated.Value);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(28, 0u, 32L)]
    [Arguments(28, 13u, 32L)]
    [Arguments(28, 0xfffffffcu, 32L)]
    [Arguments(44, 24u, 44L)]
    [Arguments(56, 1u, 56L)]
    [Arguments(68, 4u, 68L)]
    [Arguments(72, 2u, 68L)]
    public async Task Malformed_blocks_report_the_invalid_field_and_stop(int position, uint value, long expectedOffset)
    {
        byte[] file = [.. Section(), .. Interface(), .. Packet([1, 2, 3])];
        int target = position == 28 ? position + 4 : position;
        U32(value).CopyTo(file, target);
        using var stream = new MemoryStream(file);
        var reader = Open(stream);

        var result = reader.ReadNext();

        var error = result is PcapError failure ? failure : throw new InvalidOperationException("Expected a format error.");
        await Assert.That(error.Offset).IsEqualTo(expectedOffset);
        await Assert.That(error.Message.Contains("PCAPNG block at byte")).IsTrue();
        await Assert.That(reader.ReadNext() is PcapError repeated && Equals(error.Value, repeated.Value)).IsTrue();
    }

    [Test]
    [Arguments("0900020001020000")]
    [Arguments("0E00010001000000")]
    [Arguments("09000100060000000900010009000000")]
    [Arguments("0100080061626364")]
    [Arguments("0000010000000000")]
    [Arguments("0000000001000000")]
    public async Task Invalid_interface_options_are_rejected(string hex)
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(options: Convert.FromHexString(hex))]);
        var reader = Open(stream);

        var result = reader.ReadNext();

        await Assert.That(result is PcapError).IsTrue();
    }

    [Test]
    [Arguments(-2L)]
    [Arguments(3L)]
    [Arguments(long.MaxValue - 3)]
    public async Task Invalid_section_lengths_fail_at_open(long length)
    {
        using var stream = new MemoryStream(Section(length: length));

        var result = CaptureReader.Open(stream);

        await Assert.That(result is PcapError error && error.Offset == 16).IsTrue();
    }

    [Test]
    [Arguments(0L)]
    [Arguments(16L)]
    [Arguments(24L)]
    public async Task Declared_section_length_must_match_block_boundaries_and_eof(long length)
    {
        using var stream = new MemoryStream([.. Section(length: length), .. Interface()]);
        var reader = Open(stream);

        var result = reader.ReadNext();

        await Assert.That(result is PcapError).IsTrue();
    }

    [Test]
    public async Task Known_section_length_can_end_at_a_new_section_with_another_byte_order()
    {
        using var stream = new MemoryStream([.. Section(length: 20), .. Interface(), .. Section(true, length: 0)]);
        var reader = Open(stream);

        var result = reader.ReadNext();

        await Assert.That(result is PcapEndOfFile).IsTrue();
        await Assert.That(reader.Sections.Count).IsEqualTo(2);
    }

    [Test]
    public async Task An_interface_from_a_previous_section_cannot_be_referenced()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(), .. Section(true), .. Packet([1], true)]);
        var reader = Open(stream);

        var result = reader.ReadNext();

        await Assert.That(result is PcapError error && error.Message.Contains("Interface 0")).IsTrue();
    }

    [Test]
    public async Task Packet_limit_is_enforced_for_pcapng()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(), .. Packet([1, 2])]);
        var reader = CaptureReader.Open(stream, new CaptureReaderOptions(1)) is CaptureReader opened ? opened : throw new InvalidOperationException();

        var result = reader.ReadNext();

        await Assert.That(result is PcapError error && error.Message.Contains("single-packet limit 1")).IsTrue();
    }

    [Test]
    public async Task Metadata_limit_bounds_retained_sections_and_interfaces()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface()]);
        var reader = CaptureReader.Open(stream, options: new(maxMetadataBytes: 300)) is CaptureReader opened ? opened : throw new InvalidOperationException();

        var result = reader.ReadNext();

        await Assert.That(result is PcapError error && error.Message.Contains("metadata exceeds")).IsTrue();
    }

    [Test]
    public async Task Detection_supports_short_reads_without_seeking_and_keeps_stream_ownership()
    {
        using var stream = new ShortReadStream([.. Section(), .. Interface(), .. Packet([1])]);
        var reader = Open(stream);

        var packet = Read(reader);

        await Assert.That(packet.CapturedLength).IsEqualTo(1u);
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Stream_failures_are_rethrown_without_resuming_a_partial_block()
    {
        using var stream = new ShortReadStream([.. Section(), .. Interface(), .. Packet([1])]);
        var reader = Open(stream);
        stream.Fail = true;
        Action read = () => reader.ReadNext();
        var first = await Assert.That(read).Throws<IOException>();
        stream.Fail = false;

        var second = await Assert.That(read).Throws<IOException>();

        await Assert.That(second).IsSameReferenceAs(first);
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Many_empty_options_are_bounded_before_large_object_allocation()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(options: [.. Option(1, []), .. Option(1, [])])]);
        var reader = CaptureReader.Open(stream, options: new(maxOptionsPerBlock: 1)) is CaptureReader opened ? opened : throw new InvalidOperationException();

        var result = reader.ReadNext();

        await Assert.That(result is PcapError error && error.Message.Contains("per-block limit 1")).IsTrue();
    }

    [Test]
    [Arguments(8, 0u)]
    [Arguments(12, 3u)]
    public async Task Invalid_section_magic_and_version_fail_at_the_field(int offset, uint value)
    {
        var bytes = Section();
        U32(value).CopyTo(bytes, offset);
        using var stream = new MemoryStream(bytes);

        var result = CaptureReader.Open(stream);

        await Assert.That(result is PcapError error && error.Offset == offset).IsTrue();
    }

    [Test]
    public async Task Packet_data_cannot_exceed_a_nonzero_interface_snaplen()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(snap: 2), .. Packet([1, 2, 3])]);
        var reader = Open(stream);

        var result = reader.ReadNext();

        await Assert.That(result is PcapError error && error.Message.Contains("SnapLen 2")).IsTrue();
    }

    [Test]
    public async Task Simple_packets_with_extra_data_are_rejected()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(), .. Simple([1, 2, 3, 4, 5], 1)]);
        var reader = Open(stream);

        var result = reader.ReadNext();

        await Assert.That(result is PcapError error && error.Message.Contains("extra packet bytes")).IsTrue();
    }

    [Test]
    public async Task Error_offsets_are_relative_to_open_at_a_nonzero_stream_position()
    {
        using var stream = new MemoryStream([1, 2, .. Section(), .. Packet([1])]);
        stream.Position = 2;
        var reader = Open(stream);

        var result = reader.ReadNext();

        await Assert.That(result is PcapError error && error.Offset == 36 && error.RecordNumber == 1).IsTrue();
    }

    private static CaptureReader Open(Stream stream) => CaptureReader.Open(stream) is CaptureReader reader
        ? reader : throw new InvalidOperationException("Expected capture reader.");
    private static PcapNgPacket Read(CaptureReader reader) => reader.ReadNext() is PcapNgPacket packet
        ? packet : throw new InvalidOperationException("Expected PCAPNG packet.");

    private sealed class ShortReadStream(byte[] data) : MemoryStream(data)
    {
        internal bool Fail { get; set; }
        public override bool CanSeek => false;
        public override long Seek(long offset, SeekOrigin loc) => throw new NotSupportedException();
        public override int Read(Span<byte> buffer) => Fail ? throw new IOException("Read failed") : base.Read(buffer[..Math.Min(1, buffer.Length)]);
    }
}
