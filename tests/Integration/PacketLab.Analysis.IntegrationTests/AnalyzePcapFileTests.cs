using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using TUnit.Assertions.Exceptions;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzePcapFileTests
{
    [Test]
    [Arguments("ethernet-little.pcap", PcapByteOrder.LittleEndian)]
    [Arguments("ethernet-big.pcap", PcapByteOrder.BigEndian)]
    public async Task Analysis_preserves_metadata_bytes_and_diagnostics_across_mixed_records(string file, PcapByteOrder byteOrder)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", file));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened
            ? opened : throw new AssertionException("Expected an analysis reader.");
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        await Assert.That(reader.Header.LinkType).IsEqualTo((ushort)1);
        await Assert.That(reader.LinkLayer).IsEqualTo(LinkLayerProtocol.Ethernet);

        string[] payloads = ["FFFFFFFFFFFF0200000000010806", "010203", "00112233445566554433221105DC",
            "00112233445566554433221105DD", "0011223344556655443322118100002A0800ABCD0000"];
        uint[] originals = [60, 3, 1514, 14, 60];
        for (int index = 0; index < payloads.Length; index++)
        {
            var packet = reader.ReadNext() is AnalyzedPacket analyzed ? analyzed : throw new AssertionException("Expected an analyzed packet.");
            await Assert.That(packet.RecordNumber).IsEqualTo(index + 1L);
            await Assert.That(packet.Packet.Timestamp).IsEqualTo(PcapTimestamp.FromMicroseconds((uint)index + 1, 0));
            await Assert.That(packet.Packet.CapturedLength).IsEqualTo((uint)payloads[index].Length / 2);
            await Assert.That(packet.Packet.OriginalLength).IsEqualTo(originals[index]);
            await Assert.That(Convert.ToHexString(packet.Packet.Data.Span)).IsEqualTo(payloads[index]);
            var ethernet = packet.Decoding is EthernetParseResult result ? result : throw new AssertionException("Expected Ethernet decoding.");
            switch (index)
            {
                case 0:
                    var frame = ethernet is EthernetFrame arp ? arp : throw new AssertionException("Expected an ARP frame.");
                    await Assert.That(frame.EtherType).IsEqualTo((ushort)0x0806);
                    await Assert.That(frame.Destination.ToString()).IsEqualTo("FF:FF:FF:FF:FF:FF");
                    await Assert.That(frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
                    await Assert.That(frame.RemainingBytes.IsEmpty).IsTrue();
                    break;
                case 1:
                    var shortHeader = ethernet is EthernetParseResult.IncompleteHeader incomplete ? incomplete
                        : throw new AssertionException("Expected an incomplete header.");
                    await Assert.That(shortHeader.CapturedLength).IsEqualTo(3);
                    await Assert.That(Convert.ToHexString(shortHeader.RemainingBytes.Span)).IsEqualTo("010203");
                    break;
                case 2:
                    var length = ethernet is EthernetParseResult.Ieee8023Length unsupported ? unsupported
                        : throw new AssertionException("Expected IEEE 802.3 encapsulation.");
                    await Assert.That(length.Length).IsEqualTo((ushort)1500);
                    await Assert.That(length.Destination.ToString()).IsEqualTo("00:11:22:33:44:55");
                    await Assert.That(length.Source.ToString()).IsEqualTo("66:55:44:33:22:11");
                    await Assert.That(length.RemainingBytes.IsEmpty).IsTrue();
                    break;
                case 3:
                    var invalid = ethernet is EthernetParseResult.InvalidLengthOrType field ? field
                        : throw new AssertionException("Expected an invalid Length/Type field.");
                    await Assert.That(invalid.Value).IsEqualTo((ushort)1501);
                    await Assert.That(invalid.Destination.ToString()).IsEqualTo("00:11:22:33:44:55");
                    await Assert.That(invalid.Source.ToString()).IsEqualTo("66:55:44:33:22:11");
                    await Assert.That(invalid.RemainingBytes.IsEmpty).IsTrue();
                    break;
                case 4:
                    var tagged = ethernet is EthernetFrame vlan ? vlan : throw new AssertionException("Expected an Ethernet frame after errors.");
                    await Assert.That(tagged.EtherType).IsEqualTo((ushort)0x8100);
                    await Assert.That(tagged.Destination.ToString()).IsEqualTo("00:11:22:33:44:55");
                    await Assert.That(tagged.Source.ToString()).IsEqualTo("66:55:44:33:22:11");
                    await Assert.That(Convert.ToHexString(tagged.RemainingBytes.Span)).IsEqualTo("002A0800ABCD0000");
                    break;
            }
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }
}
