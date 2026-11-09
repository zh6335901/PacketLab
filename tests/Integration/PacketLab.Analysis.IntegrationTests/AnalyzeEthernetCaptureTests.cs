using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeEthernetCaptureTests
{
    [Test]
    [Arguments("ethernet-little", PcapByteOrder.LittleEndian)]
    [Arguments("ethernet-big", PcapByteOrder.BigEndian)]
    public async Task Analysis_matches_expected_ethernet_file_records(string sample, PcapByteOrder byteOrder)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened
            : throw new InvalidOperationException($"Expected an analysis reader for {sample}.");
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        foreach (var expected in ExpectedRecords)
        {
            var context = $"{sample}, record {expected.RecordNumber}";
            var packet = reader.ReadNext() is AnalyzedPacket read ? read
                : throw new InvalidOperationException($"Expected {context}.");
            var actual = new RecordSnapshot(packet.RecordNumber, packet.Packet.Timestamp, packet.Packet.CapturedLength,
                packet.Packet.OriginalLength, Hex(packet.Packet.Data), Snapshot(packet.Decoding));
            await Assert.That(actual).IsEqualTo(expected).Because($"the output must match {context}");
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue().Because($"{sample} must end after the expected records");
    }

    private sealed record RecordSnapshot(long RecordNumber, PcapTimestamp Timestamp, uint CapturedLength, uint OriginalLength,
        string Bytes, EthernetSnapshot Ethernet);
    private sealed record EthernetSnapshot(string Kind, string? Source = null, string? Destination = null,
        ushort? EtherType = null, ushort? Length = null, ushort? InvalidLengthOrType = null,
        int? CapturedHeaderLength = null, string RemainingBytes = "", int? RequiredArpHeaderLength = null,
        string? ArpRemainingBytes = null);

    private static EthernetSnapshot Snapshot(ProtocolDecodeResult result) => result switch
    {
        EthernetDecodeResult ethernet => SnapshotEthernet(ethernet),
        _ => throw new InvalidOperationException("Unexpected decoding in an Ethernet fixture.")
    };

    private static EthernetSnapshot SnapshotEthernet(EthernetDecodeResult result) => result switch
    {
        DecodedEthernet frame => SnapshotFrame(frame),
        EthernetParseResult.IncompleteHeader incomplete => new("IncompleteHeader",
            CapturedHeaderLength: incomplete.CapturedLength, RemainingBytes: Hex(incomplete.RemainingBytes)),
        EthernetParseResult.Ieee8023Length length => new("Ieee8023Length", length.Source.ToString(), length.Destination.ToString(),
            Length: length.Length, RemainingBytes: Hex(length.RemainingBytes)),
        EthernetParseResult.InvalidLengthOrType invalid => new("InvalidLengthOrType", invalid.Source.ToString(), invalid.Destination.ToString(),
            InvalidLengthOrType: invalid.Value, RemainingBytes: Hex(invalid.RemainingBytes)),
        null => throw new InvalidOperationException("Uninitialized Ethernet decode result.")
    };

    private static EthernetSnapshot SnapshotFrame(DecodedEthernet decoded)
    {
        var frame = decoded.Frame;
        var snapshot = new EthernetSnapshot("Frame", frame.Source.ToString(), frame.Destination.ToString(),
            EtherType: frame.EtherType, RemainingBytes: Hex(frame.RemainingBytes));
        return decoded.Payload switch
        {
            ArpParseResult arp when arp is ArpParseResult.IncompleteHeader incomplete => snapshot with
            {
                RequiredArpHeaderLength = incomplete.RequiredLength,
                ArpRemainingBytes = Hex(incomplete.RemainingBytes)
            },
            UnsupportedEtherType => snapshot,
            _ => throw new InvalidOperationException("Unexpected Ethernet payload in fixture.")
        };
    }

    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);

    private static readonly RecordSnapshot[] ExpectedRecords =
    [
        new(1, PcapTimestamp.FromMicroseconds(1, 0), 14, 60, "FFFFFFFFFFFF0200000000010806",
            new("Frame", "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", EtherType: 0x0806,
                RequiredArpHeaderLength: 8, ArpRemainingBytes: "")),
        new(2, PcapTimestamp.FromMicroseconds(2, 0), 3, 3, "010203",
            new("IncompleteHeader", CapturedHeaderLength: 3, RemainingBytes: "010203")),
        new(3, PcapTimestamp.FromMicroseconds(3, 0), 14, 1514, "00112233445566554433221105DC",
            new("Ieee8023Length", "66:55:44:33:22:11", "00:11:22:33:44:55", Length: 1500)),
        new(4, PcapTimestamp.FromMicroseconds(4, 0), 14, 14, "00112233445566554433221105DD",
            new("InvalidLengthOrType", "66:55:44:33:22:11", "00:11:22:33:44:55", InvalidLengthOrType: 1501)),
        new(5, PcapTimestamp.FromMicroseconds(5, 0), 22, 60, "0011223344556655443322118100002A0800ABCD0000",
            new("Frame", "66:55:44:33:22:11", "00:11:22:33:44:55", EtherType: 0x8100, RemainingBytes: "002A0800ABCD0000"))
    ];
}
