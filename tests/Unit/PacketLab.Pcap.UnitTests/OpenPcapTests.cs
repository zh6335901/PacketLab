using static PacketLab.Pcap.UnitTests.ReaderAssertions;

namespace PacketLab.Pcap.UnitTests;

public class OpenPcapTests
{
    [Test]
    [Arguments("little-micro", "04030201D0C0B0A0", "FFFF0000")]
    [Arguments("big-micro", "01020304A0B0C0D0", "0000FFFF")]
    public async Task Opening_preserves_historical_reserved_fields_and_unknown_link_type(
        string sample, string reserved, string link)
    {
        // draft-ietf-opsawg-pcap-09 §4: Reserved1/2 are ignored, unlike R/Reserved3.
        var bytes = PcapSamples.Replace(PcapSamples.Single(sample), 8, reserved);
        bytes = PcapSamples.Replace(bytes, 20, link);
        using var stream = new MemoryStream(bytes);
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        await Assert.That(reader.Header.Reserved1).IsEqualTo(0x01020304u);
        await Assert.That(reader.Header.Reserved2).IsEqualTo(0xa0b0c0d0u);
        await Assert.That(reader.Header.LinkType).IsEqualTo(ushort.MaxValue);
        await Assert.That(reader.Header.RawLinkType).IsEqualTo(65535u);
        var packetResult = reader.ReadNext();
        var packet = await packetResult.ShouldSucceed();
        await Assert.That(Convert.ToHexString(packet.Data.Span)).IsEqualTo("DEADBE");
    }

    [Test]
    [Arguments("01000000", false, 0, -1)]
    [Arguments("010000F0", false, 15, -1)]
    [Arguments("01000004", true, 0, 0)]
    [Arguments("01000024", true, 2, 4)]
    [Arguments("010000F4", true, 15, 30)]
    public async Task Header_exposes_fcs_length_in_bytes_only_when_presence_bit_is_set(string link, bool present, int words, int length)
    {
        // §4: P controls presence; even a nonzero raw FCS field is unspecified without P.
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single("little-micro"), 20, link));
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        await Assert.That(reader.Header.HasFcsLength).IsEqualTo(present);
        await Assert.That((int)reader.Header.RawFcsLengthWords).IsEqualTo(words);
        await Assert.That(reader.Header.FcsLengthBytes).IsEqualTo(length < 0 ? (int?)null : length);
        var packetResult = reader.ReadNext();
        var packet = await packetResult.ShouldSucceed();
        await Assert.That(packet.CapturedLength).IsEqualTo(3u);
    }

    [Test]
    [Arguments("00000000", false)]
    [Arguments("0A0D0D0A", true)]
    public async Task Opening_distinguishes_unknown_format_from_pcapng(string magic, bool pcapng)
    {
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single("little-micro"), 0, magic));
        var openResult = PcapReader.Open(stream);
        PcapError expectedError = pcapng
            ? new PcapError.PcapNgNotSupported()
            : new PcapError.UnsupportedFormat(0);
        var error = await openResult.ShouldFail(expectedError);
        await Location(error, 0, null);
    }

    [Test]
    [Arguments("little-micro", "03000400", 3, 4, 4)]
    [Arguments("little-micro", "02000300", 2, 3, 6)]
    [Arguments("big-micro", "00020005", 2, 5, 6)]
    public async Task Opening_rejects_unsupported_versions_at_the_version_field(string sample, string version, int major, int minor, int offset)
    {
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single(sample), 4, version));
        var openResult = PcapReader.Open(stream);
        var error = await openResult.ShouldFail(new PcapError.UnsupportedVersion((ushort)major, (ushort)minor));
        await Location(error, offset, null);
    }

    [Test]
    public async Task Opening_rejects_zero_snaplen_as_structural_damage()
    {
        // §4 requires nonzero SnapLen; large nonzero values alone do not allocate a packet.
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single("little-micro"), 16, "00000000"));
        var openResult = PcapReader.Open(stream);
        var error = await openResult.ShouldFail(new PcapError.InvalidSnapLen());
        await Location(error, 16, null);
    }

    [Test]
    [Arguments("00000100", 0x00010000u)]
    [Arguments("00000002", 0x02000000u)]
    [Arguments("00000008", 0x08000000u)]
    public async Task Opening_rejects_nonzero_reserved3_or_r_bits(string raw, uint expected)
    {
        // §4 recommends treating nonzero R/Reserved3 as errors; Reserved1/2 compatibility does not apply.
        using var stream = new MemoryStream(PcapSamples.Replace(PcapSamples.Single("little-micro"), 20, raw));
        var openResult = PcapReader.Open(stream);
        var error = await openResult.ShouldFail(new PcapError.InvalidLinkTypeReservedBits(expected));
        await Location(error, 20, null);
    }

    public static IEnumerable<int> FileHeaderCuts() => Enumerable.Range(0, 24);

    [Test]
    [MethodDataSource(nameof(FileHeaderCuts))]
    public async Task Opening_reports_the_first_missing_byte_when_file_header_is_incomplete(int length)
    {
        using var stream = new MemoryStream(PcapSamples.Single("little-micro")[..length]);
        var openResult = PcapReader.Open(stream);
        var error = await openResult.ShouldFail(new PcapError.IncompleteFileHeader(length));
        await Location(error, length, null);
    }

    [Test]
    public async Task Open_failure_keeps_stream_owned_by_caller()
    {
        var stream = new ProbeStream([]);
        using (stream)
        {
            var openResult = PcapReader.Open(stream);
            await openResult.ShouldFail();
            await Assert.That(stream.IsDisposed).IsFalse();
        }
        await Assert.That(stream.IsDisposed).IsTrue();
    }

    [Test]
    public async Task Opening_throws_when_stream_is_null_or_unreadable()
    {
        await Assert.That(() => PcapReader.Open(null!)).Throws<ArgumentNullException>();
        using var stream = new MemoryStream();
        stream.Dispose();
        await Assert.That(() => PcapReader.Open(stream)).Throws<ArgumentException>();
    }

    [Test]
    [Arguments(0)]
    [Arguments(-1)]
    [Arguments(int.MaxValue)]
    public async Task Options_reject_limits_outside_the_supported_range(int limit)
    {
        await Assert.That(() => new PcapReaderOptions(limit)).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task Options_accept_minimum_and_maximum_supported_limits()
    {
        await Assert.That(new PcapReaderOptions(1).MaxPacketBytes).IsEqualTo(1);
        await Assert.That(new PcapReaderOptions(Array.MaxLength).MaxPacketBytes).IsEqualTo(Array.MaxLength);
    }
}
