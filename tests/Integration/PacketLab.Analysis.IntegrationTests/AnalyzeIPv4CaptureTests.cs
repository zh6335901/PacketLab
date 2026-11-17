using PacketLab.Analysis.Pcap;
using PacketLab.Analyzers.Annotations;
using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeIPv4CaptureTests
{
    [Test]
    public async Task Analysis_matches_expected_ipv4_file_records()
    {
        // Arrange
        const string sample = "ipv4-mixed";
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened
            : throw new InvalidOperationException($"Expected a PCAP reader for {sample}.");
        var snapshots = new List<RecordSnapshot>();

        // Act
        for (int recordIndex = 0; recordIndex < ExpectedRecords.Length; recordIndex++)
        {
            var context = $"{sample}, record {recordIndex + 1}";
            var packet = reader.ReadNext() is PcapPacket read ? read
                : throw new InvalidOperationException($"Expected {context}.");
            var decoding = PcapAnalysis.Decode(reader.Header, packet) is EthernetDecodeResult ethernet && ethernet is DecodedEthernet frame ? frame
                : throw new InvalidOperationException($"Expected IPv4 dispatch for {context}.");
            var actual = new RecordSnapshot(packet.CapturedLength, packet.OriginalLength,
                decoding.Frame.Source.ToString(), decoding.Frame.Destination.ToString(), decoding.Frame.EtherType,
                Snapshot(decoding.Payload is IPv4DecodeResult ip ? ip : throw new InvalidOperationException()));
            snapshots.Add(actual);
        }
        var terminal = reader.ReadNext();

        // Assert
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(PcapByteOrder.LittleEndian);
        await Assert.That(snapshots.SequenceEqual(ExpectedRecords)).IsTrue();
        await Assert.That(terminal is PcapEndOfFile).IsTrue().Because($"{sample} must end after the expected records");
    }

    private sealed record RecordSnapshot(uint CapturedLength, uint OriginalLength,
        string Source, string Destination, ushort EtherType, IPv4Snapshot IPv4);
    private sealed record HeaderSnapshot(byte Version, byte Ihl, byte Dscp, byte Ecn, ushort TotalLength,
        ushort Identification, byte Flags, ushort FragmentOffset, byte Ttl, byte Protocol, ushort HeaderChecksum,
        IPv4Address Source, IPv4Address Destination, string Options);
    [TransportModel]
    private sealed record IPv4Snapshot(string Kind, IPv4ChecksumStatus ChecksumStatus, HeaderSnapshot? Header = null,
        string? Payload = null, string? TrailingBytes = null, bool? IsDatagramComplete = null,
        int? RequiredLength = null, int? CapturedLength = null, ushort? InvalidTotalLength = null,
        int? HeaderLength = null, string? RemainingBytes = null);

    private static IPv4Snapshot Snapshot(IPv4DecodeResult result) => result switch
    {
        DecodedIPv4 { Packet: var packet } => new("Packet", packet.ChecksumStatus, SnapshotHeader(packet.Header),
            Hex(packet.Payload), Hex(packet.TrailingBytes), packet.IsDatagramComplete, CapturedLength: packet.CapturedLength),
        IPv4ParseResult.IncompleteHeader incomplete => new("IncompleteHeader", IPv4ChecksumStatus.Unavailable,
            RequiredLength: incomplete.RequiredLength, CapturedLength: incomplete.CapturedLength, RemainingBytes: Hex(incomplete.RemainingBytes)),
        IPv4ParseResult.InvalidTotalLength invalid => new("InvalidTotalLength", IPv4ChecksumStatus.Unavailable,
            InvalidTotalLength: invalid.TotalLength, HeaderLength: invalid.HeaderLength, RemainingBytes: Hex(invalid.RemainingBytes)),
        _ => throw new InvalidOperationException("Unexpected IPv4 result in the mixed capture.")
    };

    private static HeaderSnapshot SnapshotHeader(IPv4Header header) => new(header.Version, header.Ihl, header.Dscp,
        header.Ecn, header.TotalLength, header.Identification, header.Flags, header.FragmentOffset, header.Ttl,
        header.Protocol, header.HeaderChecksum, header.Source, header.Destination, Hex(header.Options));

    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);

    private static readonly RecordSnapshot[] ExpectedRecords =
    [
        new(46, 90, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x0800,
            new("Packet", IPv4ChecksumStatus.Match,
                new(4, 6, 42, 3, 28, 0xbeef, 5, 291, 127, 253, 0xebee,
                    new IPv4Address(192, 0, 2, 1), new IPv4Address(198, 51, 100, 2), "01010000"),
                Payload: "CAFE0102", TrailingBytes: "DEADBEEF", IsDatagramComplete: true, CapturedLength: 32)),
        new(36, 90, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x0800,
            new("IncompleteHeader", IPv4ChecksumStatus.Unavailable, RequiredLength: 24, CapturedLength: 22,
                RemainingBytes: "46AB001CBEEFA1237FFDEBEEC0000201C63364020101")),
        new(34, 90, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x0800,
            new("InvalidTotalLength", IPv4ChecksumStatus.Unavailable, InvalidTotalLength: 19, HeaderLength: 20,
                RemainingBytes: "45AB0013BEEFA1237FFDEDF3C0000201C6336402")),
        new(38, 90, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x0800,
            new("Packet", IPv4ChecksumStatus.Mismatch,
                new(4, 5, 42, 3, 24, 0xbeef, 5, 291, 127, 253, 0xecf3,
                    new IPv4Address(192, 0, 2, 1), new IPv4Address(198, 51, 100, 2), ""),
                Payload: "CAFE0102", TrailingBytes: "", IsDatagramComplete: true, CapturedLength: 24)),
        new(36, 90, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x0800,
            new("Packet", IPv4ChecksumStatus.Match,
                new(4, 5, 42, 3, 24, 0xbeef, 5, 291, 127, 253, 0xedf3,
                    new IPv4Address(192, 0, 2, 1), new IPv4Address(198, 51, 100, 2), ""),
                Payload: "CAFE", TrailingBytes: "", IsDatagramComplete: false, CapturedLength: 22)),
        new(34, 90, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x0800,
            new("Packet", IPv4ChecksumStatus.Match,
                new(4, 5, 0, 0, 20, 0x1234, 2, 0, 64, 17, 0x3c6e,
                    new IPv4Address(192, 0, 2, 1), new IPv4Address(198, 51, 100, 2), ""),
                Payload: "", TrailingBytes: "", IsDatagramComplete: true, CapturedLength: 20))
    ];
}
