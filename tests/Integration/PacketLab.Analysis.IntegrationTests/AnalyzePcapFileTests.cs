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

        var arpPacket = ReadPacket(reader);
        await AssertMetadata(arpPacket, recordNumber: 1, seconds: 1, capturedLength: 14, originalLength: 60,
            payload: "FFFFFFFFFFFF0200000000010806");
        var frame = arpPacket.Decoding is EthernetParseResult arpResult && arpResult is EthernetFrame arp
            ? arp : throw new AssertionException("Expected an ARP frame.");
        await Assert.That(frame.EtherType).IsEqualTo((ushort)0x0806);
        await Assert.That(frame.Destination.ToString()).IsEqualTo("FF:FF:FF:FF:FF:FF");
        await Assert.That(frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(frame.RemainingBytes.IsEmpty).IsTrue();

        var shortHeaderPacket = ReadPacket(reader);
        await AssertMetadata(shortHeaderPacket, recordNumber: 2, seconds: 2, capturedLength: 3, originalLength: 3,
            payload: "010203");
        var shortHeader = shortHeaderPacket.Decoding is EthernetParseResult shortResult && shortResult is EthernetParseResult.IncompleteHeader incomplete
            ? incomplete : throw new AssertionException("Expected an incomplete header.");
        await Assert.That(shortHeader.CapturedLength).IsEqualTo(3);
        await Assert.That(Convert.ToHexString(shortHeader.RemainingBytes.Span)).IsEqualTo("010203");

        var unsupportedPacket = ReadPacket(reader);
        await AssertMetadata(unsupportedPacket, recordNumber: 3, seconds: 3, capturedLength: 14, originalLength: 1514,
            payload: "00112233445566554433221105DC");
        var length = unsupportedPacket.Decoding is EthernetParseResult lengthResult && lengthResult is EthernetParseResult.Ieee8023Length unsupported
            ? unsupported : throw new AssertionException("Expected IEEE 802.3 encapsulation.");
        await Assert.That(length.Length).IsEqualTo((ushort)1500);
        await Assert.That(length.Destination.ToString()).IsEqualTo("00:11:22:33:44:55");
        await Assert.That(length.Source.ToString()).IsEqualTo("66:55:44:33:22:11");
        await Assert.That(length.RemainingBytes.IsEmpty).IsTrue();

        var invalidPacket = ReadPacket(reader);
        await AssertMetadata(invalidPacket, recordNumber: 4, seconds: 4, capturedLength: 14, originalLength: 14,
            payload: "00112233445566554433221105DD");
        var invalid = invalidPacket.Decoding is EthernetParseResult invalidResult && invalidResult is EthernetParseResult.InvalidLengthOrType field
            ? field : throw new AssertionException("Expected an invalid Length/Type field.");
        await Assert.That(invalid.Value).IsEqualTo((ushort)1501);
        await Assert.That(invalid.Destination.ToString()).IsEqualTo("00:11:22:33:44:55");
        await Assert.That(invalid.Source.ToString()).IsEqualTo("66:55:44:33:22:11");
        await Assert.That(invalid.RemainingBytes.IsEmpty).IsTrue();

        var taggedPacket = ReadPacket(reader);
        await AssertMetadata(taggedPacket, recordNumber: 5, seconds: 5, capturedLength: 22, originalLength: 60,
            payload: "0011223344556655443322118100002A0800ABCD0000");
        var tagged = taggedPacket.Decoding is EthernetParseResult taggedResult && taggedResult is EthernetFrame vlan
            ? vlan : throw new AssertionException("Expected an Ethernet frame after errors.");
        await Assert.That(tagged.EtherType).IsEqualTo((ushort)0x8100);
        await Assert.That(tagged.Destination.ToString()).IsEqualTo("00:11:22:33:44:55");
        await Assert.That(tagged.Source.ToString()).IsEqualTo("66:55:44:33:22:11");
        await Assert.That(Convert.ToHexString(tagged.RemainingBytes.Span)).IsEqualTo("002A0800ABCD0000");

        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    private static AnalyzedPacket ReadPacket(PcapAnalysisReader reader) => reader.ReadNext() is AnalyzedPacket packet
        ? packet : throw new AssertionException("Expected an analyzed packet.");

    private static async Task AssertMetadata(AnalyzedPacket packet, long recordNumber, uint seconds,
        uint capturedLength, uint originalLength, string payload)
    {
        await Assert.That(packet.RecordNumber).IsEqualTo(recordNumber);
        await Assert.That(packet.Packet.Timestamp).IsEqualTo(PcapTimestamp.FromMicroseconds(seconds, 0));
        await Assert.That(packet.Packet.CapturedLength).IsEqualTo(capturedLength);
        await Assert.That(packet.Packet.OriginalLength).IsEqualTo(originalLength);
        await Assert.That(Convert.ToHexString(packet.Packet.Data.Span)).IsEqualTo(payload);
    }
}
