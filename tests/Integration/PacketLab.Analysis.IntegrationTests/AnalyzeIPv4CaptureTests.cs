using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.IPv4;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeIPv4CaptureTests
{
    [Test]
    public async Task Mixed_capture_retains_outer_headers_and_continues_after_ipv4_diagnostics()
    {
        IPv4Packet first;
        using (var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "ipv4-mixed.pcap")))
        {
            var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened
                : throw new InvalidOperationException("Expected an analysis reader.");
            var packets = new List<ProtocolDecodeResult.EthernetIPv4>();
            for (var number = 1; number <= 6; number++)
            {
                var packet = reader.ReadNext() is AnalyzedPacket analyzed ? analyzed
                    : throw new InvalidOperationException($"Expected record {number}.");
                await Assert.That(packet.RecordNumber).IsEqualTo((long)number);
                var decoded = packet.Decoding is ProtocolDecodeResult.EthernetIPv4 ip ? ip
                    : throw new InvalidOperationException("Expected IPv4 dispatch.");
                await Assert.That(decoded.Ethernet.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
                await Assert.That(decoded.Ethernet.Destination.ToString()).IsEqualTo("FF:FF:FF:FF:FF:FF");
                await Assert.That(decoded.Ethernet.EtherType).IsEqualTo((ushort)0x0800);
                await Assert.That(decoded.Ethernet.RemainingBytes.Span.SequenceEqual(packet.Packet.Data.Span[14..])).IsTrue();
                await Assert.That(packet.Packet.OriginalLength).IsEqualTo(90u);
                packets.Add(decoded);
            }
            await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
            first = packets[0].IPv4 is IPv4Packet complete ? complete
                : throw new InvalidOperationException("Expected a complete first header.");
            await Assert.That(first.IsDatagramComplete).IsTrue();
            await Assert.That(packets[1].IPv4 is IPv4ParseResult.IncompleteHeader { RequiredLength: 24, CapturedLength: 22 }).IsTrue();
            await Assert.That(packets[1].IPv4.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Unavailable);
            await Assert.That(packets[2].IPv4 is IPv4ParseResult.InvalidTotalLength { TotalLength: 19, HeaderLength: 20 }).IsTrue();
            await Assert.That(packets[3].IPv4 is IPv4Packet { ChecksumStatus: IPv4ChecksumStatus.Mismatch }).IsTrue();
            await Assert.That(packets[4].IPv4 is IPv4Packet
            {
                Header.TotalLength: 24, CapturedLength: 22, IsDatagramComplete: false, ChecksumStatus: IPv4ChecksumStatus.Match
            }).IsTrue();
            await Assert.That(packets[5].IPv4 is IPv4Packet { IsDatagramComplete: true, Payload.IsEmpty: true }).IsTrue();
        }
        await Assert.That(Convert.ToHexString(first.Header.Options.Span)).IsEqualTo("01010000");
        await Assert.That(Convert.ToHexString(first.Payload.Span)).IsEqualTo("CAFE0102");
        await Assert.That(Convert.ToHexString(first.TrailingBytes.Span)).IsEqualTo("DEADBEEF");
    }
}
