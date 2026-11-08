using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzePcapFileTests
{
    [Test]
    [Arguments("arp-little", "arp", PcapByteOrder.LittleEndian)]
    [Arguments("arp-big", "arp", PcapByteOrder.BigEndian)]
    [Arguments("ethernet-little", "ethernet", PcapByteOrder.LittleEndian)]
    [Arguments("ethernet-big", "ethernet", PcapByteOrder.BigEndian)]
    [Arguments("arp-truncated", "arp-truncated", PcapByteOrder.LittleEndian)]
    [Arguments("record-truncated", "record-truncated", PcapByteOrder.LittleEndian)]
    public async Task Analysis_matches_expected_file_records(string sample, string expectation, PcapByteOrder byteOrder)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened
            ? opened : throw new InvalidOperationException("Expected an analysis reader.");
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        var expectedRecords = ExpectedRecords(expectation);
        for (var i = 0; i < expectedRecords.Length; i++)
        {
            var packet = reader.ReadNext() is AnalyzedPacket read
                ? read : throw new InvalidOperationException($"Expected record {i + 1}.");
            await Assert.That(packet.RecordNumber).IsEqualTo((long)i + 1);
            var actual = new RecordSnapshot(packet.Packet.Timestamp, packet.Packet.CapturedLength,
                packet.Packet.OriginalLength, Hex(packet.Packet.Data), Snapshot(packet.Decoding));
            await Assert.That(actual).IsEqualTo(expectedRecords[i]);
        }
        var end = reader.ReadNext();
        if (expectation == "record-truncated")
            await Assert.That(end is PcapError error && error is PcapError.IncompletePacketData
                { DataOffset: 59, RecordNumber: 2, ExpectedBytes: 2, ReadBytes: 1 }).IsTrue();
        else
            await Assert.That(end is PcapEndOfFile).IsTrue();
    }

    private sealed record RecordSnapshot(PcapTimestamp Timestamp, uint Captured, uint Original, string Bytes, DecodedSnapshot Decoding);
    private sealed record DecodedSnapshot(string Kind, string Destination, string Source, int Value, string Bytes, ArpSnapshot? Arp = null);
    private sealed record ArpSnapshot(string Kind, int HardwareType, int ProtocolType, int HardwareLength, int ProtocolLength,
        int Operation, string SenderHardware, string SenderProtocol, string TargetHardware, string TargetProtocol,
        string RemainingBytes, int RequiredLength = 0);

    private static DecodedSnapshot Snapshot(ProtocolDecodeResult result) => result switch
    {
        EthernetParseResult ethernet => SnapshotEthernet(ethernet),
        ProtocolDecodeResult.EthernetArp arp => SnapshotEthernet(arp.Ethernet) with { Arp = SnapshotArp(arp.Arp) },
        ProtocolDecodeResult.UnsupportedLinkLayer unsupported => new("Unsupported", "", "", 0, Hex(unsupported.RemainingBytes)),
        ProtocolDecodeResult.EthernetIPv4 => throw new InvalidOperationException("Unexpected IPv4 in an Ethernet/ARP fixture."),
        ProtocolDecodeResult.EthernetIPv6 => throw new InvalidOperationException("Unexpected IPv6 in an Ethernet/ARP fixture."),
        null => throw new InvalidOperationException("Uninitialized decoding.")
    };

    private static DecodedSnapshot SnapshotEthernet(EthernetParseResult result) => result switch
    {
        EthernetFrame frame => new("Ethernet", frame.Destination.ToString(), frame.Source.ToString(), frame.EtherType, Hex(frame.RemainingBytes)),
        EthernetParseResult.IncompleteHeader incomplete => new("Incomplete", "", "", incomplete.CapturedLength, Hex(incomplete.RemainingBytes)),
        EthernetParseResult.Ieee8023Length length => new("Length", length.Destination.ToString(), length.Source.ToString(), length.Length, Hex(length.RemainingBytes)),
        EthernetParseResult.InvalidLengthOrType invalid => new("Invalid", invalid.Destination.ToString(), invalid.Source.ToString(), invalid.Value, Hex(invalid.RemainingBytes)),
        null => throw new InvalidOperationException("Uninitialized Ethernet result.")
    };

    private static ArpSnapshot SnapshotArp(ArpParseResult result) => result switch
    {
        ArpPacket arp => new("Complete", arp.HardwareType, arp.ProtocolType, arp.HardwareAddressLength, arp.ProtocolAddressLength,
            arp.Operation, Hex(arp.SenderHardwareAddress), Hex(arp.SenderProtocolAddress), Hex(arp.TargetHardwareAddress),
            Hex(arp.TargetProtocolAddress), Hex(arp.RemainingBytes)),
        ArpParseResult.IncompleteHeader incomplete => IncompleteArp(incomplete.RequiredLength, Hex(incomplete.RemainingBytes)),
        null => throw new InvalidOperationException("Uninitialized ARP result.")
    };

    private static ArpSnapshot IncompleteArp(int required, string bytes) => new("Incomplete", 0, 0, 0, 0, 0, "", "", "", "", bytes, required);
    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);
    private static RecordSnapshot Record(uint seconds, uint captured, uint original, string bytes, DecodedSnapshot decoding) =>
        new(PcapTimestamp.FromMicroseconds(seconds, 0), captured, original, bytes, decoding);

    private static RecordSnapshot[] ExpectedRecords(string sample)
    {
        const string outer = "FFFFFFFFFFFF0200000000010806";
        const string request = "000108000604000102000000000100000000000000000000C0000202";
        const string reply = "0001080006040002102030405060C0000202020000000001C0000201";
        const string nonzero = "0001080006040001020000000001C0000201102030405060C0000202";
        var requestResult = new ArpSnapshot("Complete", 1, 0x0800, 6, 4, 1, "020000000001", "00000000", "000000000000", "C0000202", "");
        var replyResult = new ArpSnapshot("Complete", 1, 0x0800, 6, 4, 2, "102030405060", "C0000202", "020000000001", "C0000201", "");
        return sample switch
        {
            "arp" => [
                Record(1, 42, 60, outer + request, new("Ethernet", "FF:FF:FF:FF:FF:FF", "02:00:00:00:00:01", 0x0806, request, requestResult)),
                Record(2, 42, 60, "0200000000011020304050600806" + reply, new("Ethernet", "02:00:00:00:00:01", "10:20:30:40:50:60", 0x0806, reply, replyResult))],
            "ethernet" => [
                Record(1, 14, 60, outer, new("Ethernet", "FF:FF:FF:FF:FF:FF", "02:00:00:00:00:01", 0x0806, "", IncompleteArp(8, ""))),
                Record(2, 3, 3, "010203", new("Incomplete", "", "", 3, "010203")),
                Record(3, 14, 1514, "00112233445566554433221105DC", new("Length", "00:11:22:33:44:55", "66:55:44:33:22:11", 1500, "")),
                Record(4, 14, 14, "00112233445566554433221105DD", new("Invalid", "00:11:22:33:44:55", "66:55:44:33:22:11", 1501, "")),
                Record(5, 22, 60, "0011223344556655443322118100002A0800ABCD0000", new("Ethernet", "00:11:22:33:44:55", "66:55:44:33:22:11", 0x8100, "002A0800ABCD0000"))],
            "arp-truncated" => [
                Record(1, 41, 60, outer + nonzero[..^2], new("Ethernet", "FF:FF:FF:FF:FF:FF", "02:00:00:00:00:01", 0x0806, nonzero[..^2], IncompleteArp(28, nonzero[..^2]))),
                Record(2, 42, 60, outer + nonzero, new("Ethernet", "FF:FF:FF:FF:FF:FF", "02:00:00:00:00:01", 0x0806, nonzero,
                    requestResult with { SenderProtocol = "C0000201", TargetHardware = "102030405060" }))],
            "record-truncated" => [new(PcapTimestamp.FromMicroseconds(100, 1500000), 3, 5, "DEADBE", new("Incomplete", "", "", 3, "DEADBE"))],
            _ => throw new ArgumentOutOfRangeException(nameof(sample))
        };
    }
}
