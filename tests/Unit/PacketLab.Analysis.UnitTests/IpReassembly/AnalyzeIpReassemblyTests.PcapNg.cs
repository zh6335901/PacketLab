using PacketLab.Testing;
using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols.IP.Reassembly;
using static PacketLab.Testing.PcapNgSamples;

namespace PacketLab.Analysis.UnitTests.IpReassembly;

public partial class AnalyzeIpReassemblyTests
{
    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Identical_fragment_ids_on_different_interfaces_reassemble_independently(int version)
    {
        byte[] first = Fragment(version, 0, true, Payload[..16]);
        byte[] tail = Fragment(version, 16, false, Payload[16..]);
        using var stream = new MemoryStream([.. Section(), .. Interface(), .. Interface(),
            .. Packet(first), .. Packet(tail, id: 1), .. Packet(tail)]);
        using var reader = OpenNg(stream);
        reader.ReadNext();
        reader.ReadNext();
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Pending);

        reader.ReadNext();

        var complete = reader.ReassemblyEvents.Single();
        await Assert.That(complete.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(complete.RecordNumbers.SequenceEqual(new long[] { 1, 3 })).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Fragments_from_different_sections_do_not_reassemble_together(int version)
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(),
            .. Packet(Fragment(version, 0, true, Payload[..16])),
            .. Section(true), .. Interface(true), .. Packet(Fragment(version, 16, false, Payload[16..]), true)]);
        using var reader = OpenNg(stream);
        reader.ReadNext();

        reader.ReadNext();

        await Assert.That(reader.ReassemblyEvents.All(item => item.Status != IpReassemblyStatus.Complete)).IsTrue();
        await Assert.That(reader.ReassemblyEvents.Any(item => item.Reason == PacketLab.Analysis.IpReassembly.IpReassemblyAnalysisReason.EndOfSection)).IsTrue();
    }

    [Test]
    public async Task Binary_interface_timestamps_advance_reassembly_expiry()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(options: Option(9, [0x81])),
            .. Packet(Fragment(4, 0, true, Payload[..16]), time: 2),
            .. Packet(Fragment(4, 16, false, Payload[16..]), time: 1000)]);
        using var reader = OpenNg(stream);
        reader.ReadNext();

        reader.ReadNext();

        await Assert.That(reader.ReassemblyEvents.Any(item => item.Status == IpReassemblyStatus.Expired)).IsTrue();
        await Assert.That(reader.ReassemblyEvents.All(item => item.Status != IpReassemblyStatus.Complete)).IsTrue();
    }
    [Test]
    public async Task Pcapng_eof_finishes_pending_fragments_once()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(), .. Packet(Fragment(4, 0, true, Payload[..16]))]);
        using var reader = OpenNg(stream);
        reader.ReadNext();

        var result = reader.ReadNext();

        await Assert.That(result is PcapEndOfFile).IsTrue();
        await Assert.That(reader.ReassemblyEvents.Single().Reason).IsEqualTo(PacketLab.Analysis.IpReassembly.IpReassemblyAnalysisReason.EndOfCapture);
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(reader.ReassemblyEvents.IsEmpty).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Pcapng_read_errors_abort_pending_fragments_once()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(), .. Packet(Fragment(4, 0, true, Payload[..16])), 1]);
        using var reader = OpenNg(stream);
        reader.ReadNext();

        var result = reader.ReadNext();

        await Assert.That(result is PcapError).IsTrue();
        await Assert.That(reader.ReassemblyEvents.Single().Reason).IsEqualTo(PacketLab.Analysis.IpReassembly.IpReassemblyAnalysisReason.Aborted);
        await Assert.That(reader.ReadNext() is PcapError).IsTrue();
        await Assert.That(reader.ReassemblyEvents.IsEmpty).IsTrue();
    }

    [Test]
    public async Task Disposing_pcapng_scenario_only_cleans_up_and_keeps_the_stream_open()
    {
        using var stream = new MemoryStream([.. Section(), .. Interface(), .. Packet(Fragment(4, 0, true, Payload[..16]))]);
        var reader = OpenNg(stream);
        reader.ReadNext();

        reader.Dispose();

        await Assert.That(reader.ReassemblyEvents.IsEmpty).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
        Action read = () => reader.ReadNext();
        await Assert.That(read).Throws<ObjectDisposedException>();
        reader.Dispose();
    }

    private static PcapNgAnalysisScenario OpenNg(Stream stream) => PcapNgAnalysisScenario.Open(stream) is PcapNgAnalysisScenario reader
        ? reader : throw new InvalidOperationException("Expected a PCAPNG analysis reader.");

}
