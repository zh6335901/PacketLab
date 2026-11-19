using PacketLab.Pcap;
using static PacketLab.Testing.PcapNgSamples;

namespace PacketLab.Pcap.UnitTests;

public class EnumerateCaptureTests
{
    private static readonly byte[] PcapHeader = Convert.FromHexString("D4C3B2A1020004000000000000000000FFFF000001000000");
    private static readonly byte[] PcapRecord = Convert.FromHexString("01000000000000000100000001000000AB");

    [Test]
    public async Task Pcap_enumeration_yields_packets_without_an_eof_item_and_leaves_stream_open()
    {
        using var stream = new MemoryStream([.. PcapHeader, .. PcapRecord, .. PcapRecord]);
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();

        var packets = reader.ReadPackets().ToArray();

        await Assert.That(packets.Length).IsEqualTo(2);
        await Assert.That(packets.All(static item => item is PcapPacket)).IsTrue();
        await Assert.That(reader.ReadPackets().Any()).IsFalse();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Pcap_enumeration_yields_a_terminal_error_after_preceding_packets()
    {
        using var stream = new MemoryStream([.. PcapHeader, .. PcapRecord, 1]);
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();

        var results = reader.ReadPackets().ToArray();

        await Assert.That(results.Length).IsEqualTo(2);
        await Assert.That(results[0] is PcapPacket).IsTrue();
        await Assert.That(results[1] is PcapError { Value: PcapError.IncompleteRecordHeader }).IsTrue();
        await Assert.That(reader.ReadPackets().Single() is PcapError).IsTrue();
    }

    [Test]
    public async Task Pcapng_enumeration_consumes_trailing_metadata_without_an_eof_item()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(), .. Packet([1]), .. Section(true), .. Interface(true)]);
        var reader = PcapNgReader.Open(stream) is PcapNgReader opened ? opened : throw new InvalidOperationException();

        var result = reader.ReadPackets().Single();

        await Assert.That(result is PcapNgPacket).IsTrue();
        await Assert.That(reader.Sections.Count).IsEqualTo(2);
        await Assert.That(reader.Interfaces.Count).IsEqualTo(2);
        await Assert.That(reader.ReadPackets().Any()).IsFalse();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Pcapng_enumeration_yields_a_terminal_error_instead_of_silently_ending()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(), .. Packet([1]), 1]);
        var reader = PcapNgReader.Open(stream) is PcapNgReader opened ? opened : throw new InvalidOperationException();

        var results = reader.ReadPackets().ToArray();

        await Assert.That(results.Length).IsEqualTo(2);
        await Assert.That(results[0] is PcapNgPacket).IsTrue();
        await Assert.That(results[1] is PcapError).IsTrue();
        await Assert.That(reader.ReadPackets().Single() is PcapError).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Enumeration_propagates_io_failures(bool ng)
    {
        using var stream = new FailingStream(ng ? Section() : PcapHeader);
        var result = Capture.Open(stream);
        stream.Fail = true;
        Action enumerate = () =>
        {
            switch (result)
            {
                case PcapReader reader:
                    _ = reader.ReadPackets().ToArray();
                    break;

                case PcapNgReader reader:
                    _ = reader.ReadPackets().ToArray();
                    break;

                default:
                    throw new InvalidOperationException();
            }
        };

        var failure = await Assert.That(enumerate).Throws<IOException>();

        await Assert.That(failure).IsSameReferenceAs(stream.Failure);
        await Assert.That(stream.CanRead).IsTrue();
    }

    private sealed class FailingStream(byte[] bytes) : MemoryStream(bytes)
    {
        internal bool Fail { get; set; }
        internal IOException Failure { get; } = new("read failure");
        public override int Read(Span<byte> buffer) => Fail ? throw Failure : base.Read(buffer);
    }
}
