using FsCheck;
using FsCheck.Fluent;
using System.Buffers.Binary;
using static PacketLab.Pcap.UnitTests.ReaderAssertions;

namespace PacketLab.Pcap.UnitTests;

public class OpenPcapTests
{
    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task Historical_header_values_preserve_all_unsigned_bits(bool littleEndian)
    {
        // Act
        var matches = ReadsHeader(littleEndian, 0x01020304u, 0xA0B0C0D0u, ushort.MaxValue);

        // Assert
        await Assert.That(matches).IsTrue();
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public void Opening_preserves_historical_reserved_fields_and_link_type(bool littleEndian) =>
        Prop.ForAll((DoNotSize<uint> reserved1, DoNotSize<uint> reserved2, DoNotSize<ushort> link) =>
            {
                // Act
                var matches = ReadsHeader(littleEndian, reserved1.Item, reserved2.Item, link.Item);

                // Assert
                return matches;
            }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments("little-micro", PcapByteOrder.LittleEndian, PcapTimestampPrecision.Microseconds)]
    [Arguments("big-micro", PcapByteOrder.BigEndian, PcapTimestampPrecision.Microseconds)]
    [Arguments("little-nano", PcapByteOrder.LittleEndian, PcapTimestampPrecision.Nanoseconds)]
    [Arguments("big-nano", PcapByteOrder.BigEndian, PcapTimestampPrecision.Nanoseconds)]
    public async Task Opening_supported_pcap_variants_preserves_header_fields(
        string sample, PcapByteOrder order, PcapTimestampPrecision precision)
    {
        // Arrange
        using var stream = new MemoryStream(PcapSamples.Single(sample));

        // Act
        var result = PcapReader.Open(stream);

        // Assert
        var reader = await result.ShouldSucceed();
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
    }

    private static bool ReadsHeader(bool littleEndian, uint reserved1, uint reserved2, ushort link)
    {
        // Arrange
        var bytes = PcapSamples.Single(littleEndian ? "little-micro" : "big-micro");
        WriteWord(8, reserved1);
        WriteWord(12, reserved2);
        WriteWord(20, link);
        using var stream = new MemoryStream(bytes);

        // Act
        var result = PcapReader.Open(stream);

        // Assert
        return result is PcapReader reader && reader.Header.Reserved1 == reserved1
            && reader.Header.Reserved2 == reserved2 && reader.Header.LinkType == link && reader.Header.RawLinkType == link;
        void WriteWord(int offset, uint value)
        {
            if (littleEndian) BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(offset), value);
            else BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(offset), value);
        }
    }

    [Test]
    [Arguments("01000000", false, 0, -1)]
    [Arguments("010000F0", false, 15, -1)]
    [Arguments("01000004", true, 0, 0)]
    [Arguments("01000024", true, 2, 4)]
    [Arguments("010000F4", true, 15, 30)]
    public async Task Header_exposes_fcs_length_in_bytes_only_when_presence_bit_is_set(string link, bool present, int words, int length)
    {
        // Arrange
        // §4: P controls presence; even a nonzero raw FCS field is unspecified without P.
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single("little-micro"), 20, link));

        // Act
        var openResult = PcapReader.Open(stream);

        // Assert
        var reader = await openResult.ShouldSucceed();
        await Assert.That(reader.Header.HasFcsLength).IsEqualTo(present);
        await Assert.That((int)reader.Header.RawFcsLengthWords).IsEqualTo(words);
        await Assert.That(reader.Header.FcsLengthBytes).IsEqualTo(length < 0 ? (int?)null : length);
    }

    [Test]
    [Arguments("00000000", false)]
    [Arguments("0A0D0D0A", true)]
    public async Task Opening_distinguishes_unknown_format_from_pcapng(string magic, bool pcapng)
    {
        // Arrange
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single("little-micro"), 0, magic));

        PcapError expectedError = pcapng
            ? new PcapError.PcapNgNotSupported()
            : new PcapError.UnsupportedFormat(0);

        // Act
        var openResult = PcapReader.Open(stream);

        // Assert
        var error = await openResult.ShouldFail(expectedError);
        await Location(error, 0, null);
    }

    [Test]
    [Arguments("little-micro", "03000400", 3, 4, 4)]
    [Arguments("little-micro", "02000300", 2, 3, 6)]
    [Arguments("big-micro", "00020005", 2, 5, 6)]
    public async Task Opening_rejects_unsupported_versions_at_the_version_field(string sample, string version, int major, int minor, int offset)
    {
        // Arrange
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single(sample), 4, version));

        // Act
        var openResult = PcapReader.Open(stream);

        // Assert
        var error = await openResult.ShouldFail(new PcapError.UnsupportedVersion((ushort)major, (ushort)minor));
        await Location(error, offset, null);
    }

    [Test]
    public async Task Opening_rejects_zero_snaplen_as_structural_damage()
    {
        // Arrange
        // §4 requires nonzero SnapLen; large nonzero values alone do not allocate a packet.
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single("little-micro"), 16, "00000000"));

        // Act
        var openResult = PcapReader.Open(stream);

        // Assert
        var error = await openResult.ShouldFail(new PcapError.InvalidSnapLen());
        await Location(error, 16, null);
    }

    [Test]
    [Arguments("00000100", 0x00010000u)]
    [Arguments("00000002", 0x02000000u)]
    [Arguments("00000008", 0x08000000u)]
    public async Task Opening_rejects_nonzero_reserved3_or_r_bits(string raw, uint expected)
    {
        // Arrange
        // §4 recommends treating nonzero R/Reserved3 as errors; Reserved1/2 compatibility does not apply.
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single("little-micro"), 20, raw));

        // Act
        var openResult = PcapReader.Open(stream);

        // Assert
        var error = await openResult.ShouldFail(new PcapError.InvalidLinkTypeReservedBits(expected));
        await Location(error, 20, null);
    }

    public static IEnumerable<int> FileHeaderCuts() => Enumerable.Range(0, 24);

    [Test]
    [MethodDataSource(nameof(FileHeaderCuts))]
    public async Task Opening_reports_the_first_missing_byte_when_file_header_is_incomplete(int length)
    {
        // Arrange
        using var stream = new MemoryStream(PcapSamples.Single("little-micro")[..length]);

        // Act
        var openResult = PcapReader.Open(stream);

        // Assert
        var error = await openResult.ShouldFail(new PcapError.IncompleteFileHeader(length));
        await Location(error, length, null);
    }

    [Test]
    public async Task Open_failure_keeps_stream_owned_by_caller()
    {
        // Arrange
        using var stream = new ProbeStream([]);

        // Act
        var openResult = PcapReader.Open(stream);

        // Assert
        await openResult.ShouldFail();
        await Assert.That(stream.IsDisposed).IsFalse();
    }

    [Test]
    public async Task Opening_a_null_stream_throws()
    {
        // Act
        Action act = () => PcapReader.Open(null!);

        // Assert
        await Assert.That(act).Throws<ArgumentNullException>();
    }

    [Test]
    public async Task Opening_an_unreadable_stream_throws()
    {
        // Arrange
        using var stream = new MemoryStream();
        stream.Dispose();

        // Act
        Action act = () => PcapReader.Open(stream);

        // Assert
        await Assert.That(act).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    [Arguments(int.MaxValue)]
    public async Task Options_reject_limits_outside_the_supported_range(int limit)
    {
        // Act
        Action act = () => new PcapReaderOptions(limit);

        // Assert
        await Assert.That(act).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Options_accept_minimum_and_maximum_supported_limits(bool maximum)
    {
        // Arrange
        int limit = maximum ? Array.MaxLength : 1;

        // Act
        var options = new PcapReaderOptions(limit);

        // Assert
        await Assert.That(options.MaxPacketBytes).IsEqualTo(limit);
    }
}
