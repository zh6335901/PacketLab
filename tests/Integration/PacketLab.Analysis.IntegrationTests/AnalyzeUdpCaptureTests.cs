using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Udp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeUdpCaptureTests
{
    [Test]
    [Arguments("udp-little", PcapByteOrder.LittleEndian)]
    [Arguments("udp-big", PcapByteOrder.BigEndian)]
    public async Task Analysis_preserves_udp_boundaries_and_continues_after_packet_diagnostics(string sample, PcapByteOrder byteOrder)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened : throw new InvalidOperationException();
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        foreach (var expected in Expected)
        {
            var packet = reader.ReadNext() is AnalyzedPacket analyzed ? analyzed : throw new InvalidOperationException();
            var frame = packet.Decoding is EthernetDecodeResult ethernet && ethernet is DecodedEthernet decoded
                ? decoded : throw new InvalidOperationException("Expected Ethernet frame.");
            if (frame.Payload is IPv6DecodeResult ipv6 && ipv6 is DecodedIPv6 ip6 && ip6.Payload is IPv6FragmentPayload fragment)
            {
                await Assert.That(expected.Kind).IsEqualTo("Fragment");
                await Assert.That(fragment.Fragment).IsEqualTo(new IPv6Fragment(0, true, 0x01234567, 17));
                await Assert.That(fragment.DeclaredLength).IsEqualTo(10u);
                await Assert.That(Convert.ToHexString(fragment.Bytes.Span)).IsEqualTo(expected.Remaining);
                continue;
            }
            var (version, udp) = frame.Payload switch
            {
                IPv4DecodeResult ip when ip is DecodedIPv4 decodedIp && decodedIp.Payload is UdpParseResult value => (4, value),
                IPv6DecodeResult ip when ip is DecodedIPv6 decodedIp && decodedIp.Payload is UdpParseResult value => (6, value),
                _ => throw new InvalidOperationException("Expected UDP through the Analysis entry point.")
            };
            var actual = udp switch
            {
                UdpDatagram d => new Snapshot(version, d.Header, d.EffectiveLength, d.Payload.Length,
                    d.Payload.Length > 32 ? $"{d.Payload.Span[0]:X2}..{d.Payload.Span[^1]:X2}" : Convert.ToHexString(d.Payload.Span),
                    d.DeclaredSurplusLength, Convert.ToHexString(d.SurplusArea.Span), d.IsComplete, d.IsSurplusComplete, d.Checksum),
                UdpParseResult.Unavailable u => new Snapshot(version, u.Header, null, null, null, null, null, null, null,
                    udp.Checksum, Convert.ToHexString(u.RemainingBytes.Span)),
                null => throw new InvalidOperationException()
            };
            await Assert.That(actual).IsEqualTo(expected);
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }

    #pragma warning disable PL0001 // Test snapshots intentionally flatten different result cases for comparison.
    private sealed record Snapshot(int Version, UdpHeader? Header, uint? EffectiveLength, int? PayloadLength,
        string? Payload, uint? SurplusLength, string? Surplus, bool? Complete, bool? SurplusComplete,
        UdpChecksum? Checksum, string? Remaining = null, string Kind = "Udp");
    #pragma warning restore PL0001

    private static readonly Snapshot[] Expected =
    [
        new(4, new(0, 4660, 11, 0x356e), 11, 3, "CAFE01", 2, "AABB", true, true, new(UdpChecksumStatus.Match)),
        new(6, new(0, 4660, 11, 0xc630), 11, 3, "CAFE01", 0, "", true, true, new(UdpChecksumStatus.Match)),
        new(4, new(0, 4660, 7, 1), null, null, null, null, null, null, null,
            new(UdpChecksumStatus.Unavailable, UdpUnavailableReason.InvalidLength), "0000123400070001"),
        new(6, new(0, 4660, 8, 0x9235), 8, 0, "", 4, "", true, false, new(UdpChecksumStatus.Match)),
        new(4, new(0, 4660, 11, 0x356e), 11, 2, "CAFE", 0, "", false, true, new(UdpChecksumStatus.Unavailable, UdpUnavailableReason.PayloadTruncated)),
        new(6, null, null, null, null, null, null, null, null,
            null, "FFFF800000010000CAFE", "Fragment"),
        new(6, new(0, 4660, 8, 0x9235), 8, 0, "", 0, "", true, true, new(UdpChecksumStatus.Match)),
        new(4, new(0, 4660, 8, 0), 8, 0, "", 0, "", true, true, new(UdpChecksumStatus.NotPresent)),
        new(6, new(0, 4660, 8, 0), 8, 0, "", 0, "", true, true, new(UdpChecksumStatus.ZeroNotAllowed)),
        new(6, new(0, 4660, 0, 0x923d), 8, 0, "", 0, "", true, true, new(UdpChecksumStatus.Match)),
        new(6, new(0, 4660, 8, 0x9235), 8, 0, "", 0, "", true, true, new(UdpChecksumStatus.Unavailable, UdpUnavailableReason.PseudoHeaderUnavailable)),
        new(4, new(0, 4660, 11, 0x356e), 11, 3, "CAFE00", 0, "", true, true, new(UdpChecksumStatus.Mismatch)),
        new(6, new(0, 4660, 0, 0x9244), 65536, 65528, "FF..FF", 0, "", true, true, new(UdpChecksumStatus.Match)),
        new(6, new(0, 4660, 8, 0x9235), 8, 0, "", 0, "", true, true, new(UdpChecksumStatus.Match))
    ];
}
