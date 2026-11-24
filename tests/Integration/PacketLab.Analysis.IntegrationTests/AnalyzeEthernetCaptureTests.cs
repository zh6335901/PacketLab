using PacketLab.Analysis.Pcap;
using PacketLab.Analyzers.Annotations;
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
        // Arrange
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var reader = PcapReader.Open(stream, PcapReaderOptions.Default) is PcapReader opened ? opened
            : throw new InvalidOperationException($"Expected a PCAP reader for {sample}.");
        var snapshots = new List<RecordSnapshot>();

        // Act
        for (int recordIndex = 0; recordIndex < ExpectedRecords.Length; recordIndex++)
        {
            var context = $"{sample}, record {recordIndex + 1}";
            var packet = reader.ReadNext() is PcapPacket read ? read
                : throw new InvalidOperationException($"Expected {context}.");
            var actual = new RecordSnapshot(packet.Timestamp, packet.CapturedLength,
                packet.OriginalLength, Hex(packet.Data), Snapshot(PcapAnalysis.Decode(reader.Header, packet)));
            snapshots.Add(actual);
        }
        var terminal = reader.ReadNext();

        // Assert
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        await Assert.That(snapshots.SequenceEqual(ExpectedRecords)).IsTrue();
        await Assert.That(terminal is PcapEndOfFile).IsTrue().Because($"{sample} must end after the expected records");
    }

    private sealed record RecordSnapshot(PcapTimestamp Timestamp, uint CapturedLength, uint OriginalLength,
        string Bytes, EthernetSnapshot Ethernet);
    [TransportModel]
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
        new(PcapTimestamp.FromMicroseconds(1, 0), 14, 60, "FFFFFFFFFFFF0200000000010806",
            new("Frame", "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", EtherType: 0x0806,
                RequiredArpHeaderLength: 8, ArpRemainingBytes: "")),
        new(PcapTimestamp.FromMicroseconds(2, 0), 3, 3, "010203",
            new("IncompleteHeader", CapturedHeaderLength: 3, RemainingBytes: "010203")),
        new(PcapTimestamp.FromMicroseconds(3, 0), 14, 1514, "00112233445566554433221105DC",
            new("Ieee8023Length", "66:55:44:33:22:11", "00:11:22:33:44:55", Length: 1500)),
        new(PcapTimestamp.FromMicroseconds(4, 0), 14, 14, "00112233445566554433221105DD",
            new("InvalidLengthOrType", "66:55:44:33:22:11", "00:11:22:33:44:55", InvalidLengthOrType: 1501)),
        new(PcapTimestamp.FromMicroseconds(5, 0), 22, 60, "0011223344556655443322118100002A0800ABCD0000",
            new("Frame", "66:55:44:33:22:11", "00:11:22:33:44:55", EtherType: 0x8100, RemainingBytes: "002A0800ABCD0000"))
    ];
}
