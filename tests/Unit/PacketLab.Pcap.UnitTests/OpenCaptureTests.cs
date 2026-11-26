using static PacketLab.Testing.PcapNgSamples;

namespace PacketLab.Pcap.UnitTests;

public class OpenCaptureTests
{
    [Test]
    [Arguments("little-micro")]
    [Arguments("big-micro")]
    [Arguments("little-nano")]
    [Arguments("big-nano")]
    public async Task Detection_returns_a_classic_reader_without_losing_the_first_packet(string sample)
    {
        using var stream = new ShortReadStream(PcapSamples.Single(sample));

        var result = Capture.Open(stream);

        var reader = result is PcapReader classic ? classic : throw new InvalidOperationException("Expected a PCAP reader.");
        var packet = reader.ReadNext() is PcapPacket read ? read : throw new InvalidOperationException("Expected the first packet.");
        await Assert.That(Convert.ToHexString(packet.Data.Span)).IsEqualTo("DEADBE");
        await Assert.That(packet.CapturedLength).IsEqualTo(3u);
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Detection_returns_a_pcapng_reader_with_its_own_metadata(bool big)
    {
        using var stream = new ShortReadStream([.. Section(big), .. Interface(big, options: Text(2, "eth0", big)), .. Packet([1, 2, 3], big)]);

        var result = Capture.Open(stream);

        var reader = result is PcapNgReader ng ? ng : throw new InvalidOperationException("Expected a PCAPNG reader.");
        await Assert.That(reader.Sections.Count).IsEqualTo(1);
        await Assert.That(reader.Interfaces.Count).IsEqualTo(0);
        var packet = reader.ReadNext() is PcapNgPacket read ? read : throw new InvalidOperationException("Expected the first packet.");
        await Assert.That(reader.Interfaces.Count).IsEqualTo(1);
        await Assert.That(packet.Interface.Name).IsEqualTo("eth0");
        await Assert.That(Convert.ToHexString(packet.Data.Span)).IsEqualTo("010203");
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    [Arguments(0)]
    [Arguments(3)]
    [Arguments(4)]
    [Arguments(11)]
    [Arguments(27)]
    public async Task Detection_reports_header_truncation_relative_to_the_start_of_the_capture(int length)
    {
        using var stream = new MemoryStream([0xaa, 0xbb, .. Section()[..length]]);
        stream.Position = 2;

        var result = Capture.Open(stream);

        await Assert.That(result is PcapError error && error.Offset == length).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Detection_preserves_unknown_format_errors()
    {
        using var stream = new MemoryStream(new byte[24]);

        var result = Capture.Open(stream);

        await Assert.That(result is PcapError error && error is PcapError.UnsupportedFormat { Magic: 0 }).IsTrue();
    }

    [Test]
    public async Task Pcapng_open_rejects_a_classic_header_instead_of_reading_it_as_a_section()
    {
        using var stream = new MemoryStream(PcapSamples.Single("little-micro"));

        var result = PcapNgReader.Open(stream, PcapNgReaderOptions.Default);

        await Assert.That(result is PcapError error && error.Offset == 0 && error.Message.Contains("Section Header Block")).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    private sealed class ShortReadStream(byte[] bytes) : MemoryStream(bytes)
    {
        public override bool CanSeek => false;
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }
        public override int Read(Span<byte> buffer) => base.Read(buffer[..Math.Min(1, buffer.Length)]);
    }
}
