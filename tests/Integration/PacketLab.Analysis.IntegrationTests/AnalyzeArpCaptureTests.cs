using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Arp;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeArpCaptureTests
{
    [Test]
    [Arguments("arp-little", PcapByteOrder.LittleEndian)]
    [Arguments("arp-big", PcapByteOrder.BigEndian)]
    public Task Analysis_matches_expected_arp_file_records(string sample, PcapByteOrder byteOrder) =>
        VerifyRecords(sample, byteOrder, CompleteRecords);

    [Test]
    public Task Analysis_matches_incomplete_arp_followed_by_a_complete_packet() =>
        VerifyRecords("arp-truncated", PcapByteOrder.LittleEndian, TruncatedRecords);

    private static async Task VerifyRecords(string sample, PcapByteOrder byteOrder, RecordSnapshot[] expectedRecords)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened
            : throw new InvalidOperationException($"Expected an analysis reader for {sample}.");
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        foreach (var expected in expectedRecords)
        {
            var context = $"{sample}, record {expected.RecordNumber}";
            var packet = reader.ReadNext() is AnalyzedPacket read ? read
                : throw new InvalidOperationException($"Expected {context}.");
            var decoding = packet.Decoding is ProtocolDecodeResult.EthernetArp arp ? arp
                : throw new InvalidOperationException($"Expected ARP dispatch for {context}.");
            var actual = new RecordSnapshot(packet.RecordNumber, packet.Packet.Timestamp, packet.Packet.CapturedLength,
                packet.Packet.OriginalLength, Hex(packet.Packet.Data), decoding.Ethernet.Source.ToString(),
                decoding.Ethernet.Destination.ToString(), decoding.Ethernet.EtherType, Hex(decoding.Ethernet.RemainingBytes), Snapshot(decoding.Arp));
            await Assert.That(actual).IsEqualTo(expected).Because($"the output must match {context}");
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue().Because($"{sample} must end after the expected records");
    }

    private sealed record RecordSnapshot(long RecordNumber, PcapTimestamp Timestamp, uint CapturedLength, uint OriginalLength,
        string Bytes, string Source, string Destination, ushort EtherType, string EthernetPayload, ArpSnapshot Arp);
    private sealed record ArpSnapshot(string Kind, ushort? HardwareType = null, ushort? ProtocolType = null,
        byte? HardwareLength = null, byte? ProtocolLength = null, ushort? Operation = null,
        string? SenderHardware = null, string? SenderProtocol = null, string? TargetHardware = null, string? TargetProtocol = null,
        string RemainingBytes = "", int? RequiredLength = null, int? CapturedLength = null);

    private static ArpSnapshot Snapshot(ArpParseResult result) => result switch
    {
        ArpPacket arp => new("Complete", arp.HardwareType, arp.ProtocolType, arp.HardwareAddressLength,
            arp.ProtocolAddressLength, arp.Operation, Hex(arp.SenderHardwareAddress), Hex(arp.SenderProtocolAddress),
            Hex(arp.TargetHardwareAddress), Hex(arp.TargetProtocolAddress), Hex(arp.RemainingBytes)),
        ArpParseResult.IncompleteHeader incomplete => new("IncompleteHeader", RemainingBytes: Hex(incomplete.RemainingBytes),
            RequiredLength: incomplete.RequiredLength, CapturedLength: incomplete.CapturedLength),
        null => throw new InvalidOperationException("Uninitialized ARP parse result.")
    };

    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);

    private static readonly RecordSnapshot[] CompleteRecords =
    [
        new(1, PcapTimestamp.FromMicroseconds(1, 0), 42, 60,
            "FFFFFFFFFFFF0200000000010806000108000604000102000000000100000000000000000000C0000202",
            "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x0806, "000108000604000102000000000100000000000000000000C0000202",
            new("Complete", 1, 0x0800, 6, 4, 1, "020000000001", "00000000", "000000000000", "C0000202")),
        new(2, PcapTimestamp.FromMicroseconds(2, 0), 42, 60,
            "02000000000110203040506008060001080006040002102030405060C0000202020000000001C0000201",
            "10:20:30:40:50:60", "02:00:00:00:00:01", 0x0806, "0001080006040002102030405060C0000202020000000001C0000201",
            new("Complete", 1, 0x0800, 6, 4, 2, "102030405060", "C0000202", "020000000001", "C0000201"))
    ];

    private static readonly RecordSnapshot[] TruncatedRecords =
    [
        new(1, PcapTimestamp.FromMicroseconds(1, 0), 41, 60,
            "FFFFFFFFFFFF02000000000108060001080006040001020000000001C0000201102030405060C00002",
            "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x0806, "0001080006040001020000000001C0000201102030405060C00002",
            new("IncompleteHeader", RemainingBytes: "0001080006040001020000000001C0000201102030405060C00002",
                RequiredLength: 28, CapturedLength: 27)),
        new(2, PcapTimestamp.FromMicroseconds(2, 0), 42, 60,
            "FFFFFFFFFFFF02000000000108060001080006040001020000000001C0000201102030405060C0000202",
            "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x0806, "0001080006040001020000000001C0000201102030405060C0000202",
            new("Complete", 1, 0x0800, 6, 4, 1, "020000000001", "C0000201", "102030405060", "C0000202"))
    ];
}
