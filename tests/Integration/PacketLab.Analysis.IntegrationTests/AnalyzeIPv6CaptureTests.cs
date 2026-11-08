using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeIPv6CaptureTests
{
    [Test]
    [Arguments("ipv6-little", PcapByteOrder.LittleEndian)]
    [Arguments("ipv6-big", PcapByteOrder.BigEndian)]
    public async Task Analysis_matches_expected_ipv6_file_records(string sample, PcapByteOrder byteOrder)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened
            : throw new InvalidOperationException($"Expected an analysis reader for {sample}.");
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        foreach (var expected in ExpectedRecords)
        {
            var context = $"{sample}, record {expected.RecordNumber}";
            var analyzed = reader.ReadNext() is AnalyzedPacket read ? read
                : throw new InvalidOperationException($"Expected {context}.");
            var decoding = analyzed.Decoding is ProtocolDecodeResult.EthernetIPv6 ip ? ip
                : throw new InvalidOperationException($"Expected IPv6 dispatch for {context}.");
            var actual = new RecordSnapshot(analyzed.RecordNumber, analyzed.Packet.CapturedLength, analyzed.Packet.OriginalLength,
                decoding.Ethernet.Source.ToString(), decoding.Ethernet.Destination.ToString(), decoding.Ethernet.EtherType,
                Snapshot(decoding.IPv6));
            await Assert.That(actual).IsEqualTo(expected).Because($"the output must match {context}");
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue().Because($"{sample} must end after the expected records");
    }

    [Test]
    [Arguments("little", PcapByteOrder.LittleEndian)]
    [Arguments("big", PcapByteOrder.BigEndian)]
    public async Task Extension_chains_and_failures_survive_pcap_analysis_and_continue_to_last_record(string order, PcapByteOrder expectedOrder)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", $"ipv6-extensions-{order}.pcap"));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened
            : throw new InvalidOperationException("Expected PCAP reader.");
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(expectedOrder);
        for (var i = 0; i < ExpectedExtensionRecords.Length; i++)
        {
            var record = reader.ReadNext() is AnalyzedPacket analyzed ? analyzed
                : throw new InvalidOperationException($"Expected record {i + 1}.");
            await Assert.That(record.RecordNumber).IsEqualTo(i + 1L);
            await Assert.That(record.Packet.OriginalLength).IsEqualTo(70000u);
            var ip = record.Decoding is ProtocolDecodeResult.EthernetIPv6 decoded && decoded.IPv6 is IPv6Packet parsed
                ? parsed : throw new InvalidOperationException("Expected IPv6 packet.");
            var chain = ip.Extensions;
            var actual = new ExtensionSnapshot(chain.Status,
                string.Join(",", chain.Headers.Select(h => $"{h.Type}@{h.Offset}+{h.Length}>{h.NextHeader}:{Convert.ToHexString(h.Bytes.Span)}")),
                chain.RemainingOffset, Convert.ToHexString(chain.RemainingBytes.Span), chain.UpperLayer?.Protocol,
                chain.UpperLayer?.DeclaredLength, chain.ChecksumContext is not null,
                string.Join(",", chain.Diagnostics.Select(d => $"{d.Code}@{d.Offset}")));
            await Assert.That(actual).IsEqualTo(ExpectedExtensionRecords[i]).Because($"record {i + 1} must match independently specified wire fields");
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }

    private sealed record RecordSnapshot(long RecordNumber, uint CapturedLength, uint OriginalLength,
        string Source, string Destination, ushort EtherType, IPv6Snapshot IPv6);
    private sealed record IPv6Snapshot(string Kind, IPv6Header? Header = null, PayloadSnapshot? Payload = null,
        int? RequiredLength = null, int? CapturedLength = null, byte? InvalidVersion = null, string? RemainingBytes = null);
    private sealed record PayloadSnapshot(string Kind, string Bytes, string? TrailingBytes = null,
        uint? DeclaredLength = null, ulong? DeclaredDatagramLength = null, bool? IsDatagramComplete = null);

    private static IPv6Snapshot Snapshot(IPv6ParseResult result) => result switch
    {
        IPv6Packet packet => new("Packet", packet.Header, Snapshot(packet.Payload)),
        IPv6ParseResult.IncompleteHeader incomplete => new("IncompleteHeader", RequiredLength: incomplete.RequiredLength,
            CapturedLength: incomplete.CapturedLength, RemainingBytes: Convert.ToHexString(incomplete.RemainingBytes.Span)),
        IPv6ParseResult.InvalidVersion invalid => new("InvalidVersion", InvalidVersion: invalid.Version,
            RemainingBytes: Convert.ToHexString(invalid.RemainingBytes.Span)),
        null => throw new InvalidOperationException("Uninitialized IPv6 parse result.")
    };

    private static PayloadSnapshot Snapshot(IPv6Payload result) => result switch
    {
        IPv6Payload.KnownLength known => new("KnownLength", Convert.ToHexString(known.Bytes.Span),
            Convert.ToHexString(known.TrailingBytes.Span), known.DeclaredLength, known.DeclaredDatagramLength, known.IsDatagramComplete),
        IPv6Payload.UndeterminedLength unknown => new("UndeterminedLength", Convert.ToHexString(unknown.CapturedBytes.Span)),
        null => throw new InvalidOperationException("Uninitialized IPv6 payload result.")
    };

    private static readonly RecordSnapshot[] ExpectedRecords =
    [
        new(1, 53, 70000, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x86dd,
            new("IncompleteHeader", RequiredLength: 40, CapturedLength: 39,
                RemainingBytes: "6ABCDEF00004FD7F20010DB8000000000000000000000001FF0200000000000000000000000000")),
        new(2, 54, 70000, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x86dd,
            new("InvalidVersion", InvalidVersion: 4,
                RemainingBytes: "4ABCDEF00004FD7F20010DB8000000000000000000000001FF020000000000000000000000000002")),
        new(3, 56, 70000, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x86dd,
            new("Packet", new IPv6Header(6, 0xab, 0xcdef0, 4, 253, 127,
                    new IPv6Address(0x20010db800000000, 1), new IPv6Address(0xff02000000000000, 2)),
                new("KnownLength", "CAFE", "", DeclaredLength: 4, DeclaredDatagramLength: 44, IsDatagramComplete: false))),
        new(4, 62, 70000, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x86dd,
            new("Packet", new IPv6Header(6, 0xab, 0xcdef0, 4, 253, 127,
                    new IPv6Address(0x20010db800000000, 1), new IPv6Address(0xff02000000000000, 2)),
                new("KnownLength", "CAFE0102", "DEADBEEF", DeclaredLength: 4, DeclaredDatagramLength: 44, IsDatagramComplete: true))),
        new(5, 56, 70000, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x86dd,
            new("Packet", new IPv6Header(6, 0, 0, 0, 59, 64,
                    new IPv6Address(0x20010db800000000, 1), new IPv6Address(0xff02000000000000, 2)),
                new("KnownLength", "", "AABB", DeclaredLength: 0, DeclaredDatagramLength: 40, IsDatagramComplete: true))),
        new(6, 62, 70000, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x86dd,
            new("Packet", new IPv6Header(6, 0xab, 0xcdef0, 0, 0, 127,
                    new IPv6Address(0x20010db800000000, 1), new IPv6Address(0xff02000000000000, 2)),
                new("KnownLength", "1100C20400010000", "", DeclaredLength: 65536, DeclaredDatagramLength: 65576, IsDatagramComplete: false))),
        new(7, 58, 70000, "02:00:00:00:00:01", "FF:FF:FF:FF:FF:FF", 0x86dd,
            new("Packet", new IPv6Header(6, 0, 0, 4, 43, 64,
                    new IPv6Address(0x20010db800000000, 1), new IPv6Address(0xff02000000000000, 2)),
                new("KnownLength", "FFFFFFFF", "", DeclaredLength: 4, DeclaredDatagramLength: 44, IsDatagramComplete: true)))
    ];

    private sealed record ExtensionSnapshot(IPv6ChainStatus Status, string Headers, int RemainingOffset, string Remaining,
        byte? Protocol, uint? UpperLength, bool HasChecksumContext, string Diagnostics);

    private static readonly ExtensionSnapshot[] ExpectedExtensionRecords =
    [
        new(IPv6ChainStatus.UpperLayer,
            "0@40+8>60:3C00000000000000,60@48+8>43:2B00000000000000,43@56+8>51:3300FE0100000000,51@64+24>44:2C0400000102030405060708000000000000000000000000,44@88+8>17:1100000001234567",
            96, "CAFE", 17, 10, false, "FinalDestinationUnavailable@56,PayloadTruncated@98"),
        new(IPv6ChainStatus.ReassemblyRequired, "44@40+8>60:3C00000989ABCDEF", 48, "DEAD", null, null, false, "ReassemblyRequired@40"),
        new(IPv6ChainStatus.Truncated, "", 40, "1101", null, null, false, "HeaderTruncated@40,PayloadTruncated@42"),
        new(IPv6ChainStatus.Unsupported, "", 40, "DEAD", null, null, false, "EncryptedEsp@40"),
        new(IPv6ChainStatus.Unsupported, "", 40, "DEAD", null, null, false, "UnsupportedNextHeader@40"),
        new(IPv6ChainStatus.NoNextHeader, "", 40, "DEAD", null, null, false, ""),
        new(IPv6ChainStatus.UpperLayer, "0@40+8>17:1100C20400010000", 48, "", 17, 65528, false, "PayloadTruncated@48"),
        new(IPv6ChainStatus.Invalid, "0@40+8>17:1100000000000000", 48, "", null, null, false, "MissingJumboPayload@40"),
        new(IPv6ChainStatus.UpperLayer, "", 40, "CAFE0102", 17, 4, true, "")
    ];
}
