using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Arp;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeArpFileTests
{
    [Test]
    [Arguments("arp-little.pcap", PcapByteOrder.LittleEndian)]
    [Arguments("arp-big.pcap", PcapByteOrder.BigEndian)]
    public async Task Capture_byte_order_does_not_change_arp_fields(string file, PcapByteOrder byteOrder)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", file));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened
            ? opened : throw new InvalidOperationException("Expected a reader.");
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        for (ushort operation = 1; operation <= 2; operation++)
        {
            var record = reader.ReadNext() is AnalyzedPacket packet ? packet : throw new InvalidOperationException("Expected a packet.");
            var decoded = record.Decoding is ProtocolDecodeResult.EthernetArp arp ? arp : throw new InvalidOperationException("Expected ARP decoding.");
            var parsed = decoded.Arp is ArpPacket result ? result : throw new InvalidOperationException("Expected complete ARP.");
            await Assert.That(record.RecordNumber).IsEqualTo((long)operation);
            await Assert.That(decoded.Ethernet.EtherType).IsEqualTo((ushort)0x0806);
            await Assert.That(parsed.HardwareType).IsEqualTo((ushort)1);
            await Assert.That(parsed.ProtocolType).IsEqualTo((ushort)0x0800);
            await Assert.That(parsed.HardwareAddressLength).IsEqualTo((byte)6);
            await Assert.That(parsed.ProtocolAddressLength).IsEqualTo((byte)4);
            await Assert.That(parsed.Operation).IsEqualTo(operation);
            await Assert.That(Convert.ToHexString(parsed.SenderHardwareAddress.Span)).IsEqualTo(operation == 1 ? "020000000001" : "102030405060");
            await Assert.That(Convert.ToHexString(parsed.SenderProtocolAddress.Span)).IsEqualTo(operation == 1 ? "00000000" : "C0000202");
            await Assert.That(Convert.ToHexString(parsed.TargetHardwareAddress.Span)).IsEqualTo(operation == 1 ? "000000000000" : "020000000001");
            await Assert.That(Convert.ToHexString(parsed.TargetProtocolAddress.Span)).IsEqualTo(operation == 1 ? "C0000202" : "C0000201");
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }
}
