using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeIPv6ExtensionsTests
{
    [Test]
    [Arguments("little", PcapByteOrder.LittleEndian)]
    [Arguments("big", PcapByteOrder.BigEndian)]
    public async Task Extension_chains_and_failures_survive_pcap_analysis_and_continue_to_last_record(string order, PcapByteOrder expectedOrder)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", $"ipv6-extensions-{order}.pcap"));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened
            : throw new InvalidOperationException("Expected PCAP reader.");
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(expectedOrder);
        for (var i = 0; i < Expected.Length; i++)
        {
            var record = reader.ReadNext() is AnalyzedPacket analyzed ? analyzed
                : throw new InvalidOperationException($"Expected record {i + 1}.");
            await Assert.That(record.RecordNumber).IsEqualTo(i + 1L);
            await Assert.That(record.Packet.OriginalLength).IsEqualTo(70000u);
            var ip = record.Decoding is ProtocolDecodeResult.EthernetIPv6 decoded && decoded.IPv6 is IPv6Packet parsed
                ? parsed : throw new InvalidOperationException("Expected IPv6 packet.");
            var chain = ip.Extensions;
            var actual = new Snapshot(chain.Status,
                string.Join(",", chain.Headers.Select(h => $"{h.Type}@{h.Offset}+{h.Length}>{h.NextHeader}:{Convert.ToHexString(h.Bytes.Span)}")),
                chain.RemainingOffset, Convert.ToHexString(chain.RemainingBytes.Span), chain.UpperLayer?.Protocol,
                chain.UpperLayer?.DeclaredLength, chain.ChecksumContext is not null,
                string.Join(",", chain.Diagnostics.Select(d => $"{d.Code}@{d.Offset}")));
            await Assert.That(actual).IsEqualTo(Expected[i]).Because($"record {i + 1} must match independently specified wire fields");
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }

    private sealed record Snapshot(IPv6ChainStatus Status, string Headers, int RemainingOffset, string Remaining,
        byte? Protocol, uint? UpperLength, bool HasChecksumContext, string Diagnostics);

    private static readonly Snapshot[] Expected =
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
