using PacketLab.Pcap;
using PacketLab.Protocols.Udp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeUdpCaptureTests
{
#pragma warning disable PL0003 // One reader must continue through all diagnostics to the final valid record.
    [Test]
    [Arguments("udp-little", PcapByteOrder.LittleEndian)]
    [Arguments("udp-big", PcapByteOrder.BigEndian)]
    public async Task Analysis_reads_all_records_after_packet_diagnostics_and_reaches_eof(string sample, PcapByteOrder byteOrder)
    {
        using var stream = OpenSample(sample);
        var reader = OpenReader(stream);
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        for (var number = 1; number < 14; number++)
            await Assert.That(ReadPacket(reader).RecordNumber).IsEqualTo((long)number);
        var last = ReadPacket(reader);
        await Assert.That(last.RecordNumber).IsEqualTo(14L);
        var udp = Datagram(Udp(IPv6(Ethernet(last)).Payload));
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }
#pragma warning restore PL0003

    [Test]
    [Arguments("udp-little", SampleRecord.PayloadWithSurplus, 11, 0x356e, 11u, "CAFE01", 2u, "AABB", UdpChecksumStatus.Match)]
    [Arguments("udp-big", SampleRecord.PayloadWithSurplus, 11, 0x356e, 11u, "CAFE01", 2u, "AABB", UdpChecksumStatus.Match)]
    [Arguments("udp-little", SampleRecord.AbsentIpv4Checksum, 8, 0, 8u, "", 0u, "", UdpChecksumStatus.NotPresent)]
    [Arguments("udp-big", SampleRecord.AbsentIpv4Checksum, 8, 0, 8u, "", 0u, "", UdpChecksumStatus.NotPresent)]
    [Arguments("udp-little", SampleRecord.ChangedPayload, 11, 0x356e, 11u, "CAFE00", 0u, "", UdpChecksumStatus.Mismatch)]
    [Arguments("udp-big", SampleRecord.ChangedPayload, 11, 0x356e, 11u, "CAFE00", 0u, "", UdpChecksumStatus.Mismatch)]
    public async Task Complete_ipv4_datagrams_preserve_fields_boundaries_and_checksum(string sample, SampleRecord record,
        ushort length, ushort checksum, uint effectiveLength, string payload, uint surplusLength, string surplus, UdpChecksumStatus status)
    {
        var udp = Datagram(Udp(IPv4(ReadRecord(sample, record)).Payload));
        await Assert.That(udp.Header).IsEqualTo(new UdpHeader(0, 4660, length, checksum));
        await Assert.That(udp.EffectiveLength).IsEqualTo(effectiveLength);
        await Assert.That(udp.Payload.Length).IsEqualTo(payload.Length / 2);
        await Assert.That(Hex(udp.Payload)).IsEqualTo(payload);
        await Assert.That(udp.DeclaredSurplusLength).IsEqualTo(surplusLength);
        await Assert.That(Hex(udp.SurplusArea)).IsEqualTo(surplus);
        await Assert.That(udp.IsComplete).IsTrue();
        await Assert.That(udp.IsSurplusComplete).IsTrue();
        await Assert.That(udp.Checksum.Value).IsEqualTo(status);
    }

    [Test]
    [Arguments("udp-little", SampleRecord.Ipv6Payload, 11, 0xc630, 11u, "CAFE01", 0u, "", UdpChecksumStatus.Match)]
    [Arguments("udp-big", SampleRecord.Ipv6Payload, 11, 0xc630, 11u, "CAFE01", 0u, "", UdpChecksumStatus.Match)]
    [Arguments("udp-little", SampleRecord.AtomicFragment, 8, 0x9235, 8u, "", 0u, "", UdpChecksumStatus.Match)]
    [Arguments("udp-big", SampleRecord.AtomicFragment, 8, 0x9235, 8u, "", 0u, "", UdpChecksumStatus.Match)]
    [Arguments("udp-little", SampleRecord.ZeroIpv6Checksum, 8, 0, 8u, "", 0u, "", UdpChecksumStatus.ZeroNotAllowed)]
    [Arguments("udp-big", SampleRecord.ZeroIpv6Checksum, 8, 0, 8u, "", 0u, "", UdpChecksumStatus.ZeroNotAllowed)]
    [Arguments("udp-little", SampleRecord.ZeroLength, 0, 0x923d, 8u, "", 0u, "", UdpChecksumStatus.Match)]
    [Arguments("udp-big", SampleRecord.ZeroLength, 0, 0x923d, 8u, "", 0u, "", UdpChecksumStatus.Match)]
    [Arguments("udp-little", SampleRecord.FinalValidDatagram, 8, 0x9235, 8u, "", 0u, "", UdpChecksumStatus.Match)]
    [Arguments("udp-big", SampleRecord.FinalValidDatagram, 8, 0x9235, 8u, "", 0u, "", UdpChecksumStatus.Match)]
    public async Task Complete_ipv6_datagrams_preserve_fields_boundaries_and_checksum(string sample, SampleRecord record,
        ushort length, ushort checksum, uint effectiveLength, string payload, uint surplusLength, string surplus, UdpChecksumStatus status)
    {
        var udp = Datagram(Udp(IPv6(ReadRecord(sample, record)).Payload));
        await Assert.That(udp.Header).IsEqualTo(new UdpHeader(0, 4660, length, checksum));
        await Assert.That(udp.EffectiveLength).IsEqualTo(effectiveLength);
        await Assert.That(udp.Payload.Length).IsEqualTo(payload.Length / 2);
        await Assert.That(Hex(udp.Payload)).IsEqualTo(payload);
        await Assert.That(udp.DeclaredSurplusLength).IsEqualTo(surplusLength);
        await Assert.That(Hex(udp.SurplusArea)).IsEqualTo(surplus);
        await Assert.That(udp.IsComplete).IsTrue();
        await Assert.That(udp.IsSurplusComplete).IsTrue();
        await Assert.That(udp.Checksum.Value).IsEqualTo(status);
    }

    [Test]
    [Arguments("udp-little")]
    [Arguments("udp-big")]
    public async Task Invalid_udp_length_retains_header_and_available_bytes(string sample)
    {
        var result = Udp(IPv4(ReadRecord(sample, SampleRecord.InvalidLength)).Payload);
        var error = result is UdpParseResult.InvalidLength invalid ? invalid
            : throw new InvalidOperationException("Expected an invalid UDP length.");
        await Assert.That(error.Header).IsEqualTo(new UdpHeader(0, 4660, 7, 1));
        await Assert.That(Hex(error.RemainingBytes)).IsEqualTo("0000123400070001");
        await Assert.That(result.Checksum.Value).IsEqualTo(new UdpChecksumUnavailable(UdpUnavailableReason.InvalidLength));
    }

    [Test]
    [Arguments("udp-little")]
    [Arguments("udp-big")]
    public async Task Incomplete_ip_surplus_does_not_disable_complete_udp_checksum(string sample)
    {
        var udp = Datagram(Udp(IPv6(ReadRecord(sample, SampleRecord.TruncatedSurplus)).Payload));
        await Assert.That(udp.Header).IsEqualTo(new UdpHeader(0, 4660, 8, 0x9235));
        await Assert.That(udp.EffectiveLength).IsEqualTo(8u);
        await Assert.That(udp.Payload.Length).IsEqualTo(0);
        await Assert.That(Hex(udp.Payload)).IsEqualTo("");
        await Assert.That(udp.DeclaredSurplusLength).IsEqualTo(4u);
        await Assert.That(Hex(udp.SurplusArea)).IsEqualTo("");
        await Assert.That(udp.IsComplete).IsTrue();
        await Assert.That(udp.IsSurplusComplete).IsFalse();
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
    }

    [Test]
    [Arguments("udp-little")]
    [Arguments("udp-big")]
    public async Task Truncated_payload_retains_header_and_declared_length(string sample)
    {
        var udp = Datagram(Udp(IPv4(ReadRecord(sample, SampleRecord.TruncatedPayload)).Payload));
        await Assert.That(udp.Header).IsEqualTo(new UdpHeader(0, 4660, 11, 0x356e));
        await Assert.That(udp.EffectiveLength).IsEqualTo(11u);
        await Assert.That(udp.Payload.Length).IsEqualTo(2);
        await Assert.That(Hex(udp.Payload)).IsEqualTo("CAFE");
        await Assert.That(udp.DeclaredSurplusLength).IsEqualTo(0u);
        await Assert.That(Hex(udp.SurplusArea)).IsEqualTo("");
        await Assert.That(udp.IsComplete).IsFalse();
        await Assert.That(udp.IsSurplusComplete).IsTrue();
        await Assert.That(udp.Checksum.Value).IsEqualTo(new UdpChecksumUnavailable(UdpUnavailableReason.PayloadTruncated));
    }

    [Test]
    [Arguments("udp-little")]
    [Arguments("udp-big")]
    public async Task Unknown_pseudo_header_preserves_udp_without_claiming_a_checksum_result(string sample)
    {
        var udp = Datagram(Udp(IPv6(ReadRecord(sample, SampleRecord.UnknownRoutingDestination)).Payload));
        await Assert.That(udp.Header).IsEqualTo(new UdpHeader(0, 4660, 8, 0x9235));
        await Assert.That(udp.EffectiveLength).IsEqualTo(8u);
        await Assert.That(udp.Payload.Length).IsEqualTo(0);
        await Assert.That(Hex(udp.Payload)).IsEqualTo("");
        await Assert.That(udp.DeclaredSurplusLength).IsEqualTo(0u);
        await Assert.That(Hex(udp.SurplusArea)).IsEqualTo("");
        await Assert.That(udp.IsComplete).IsTrue();
        await Assert.That(udp.IsSurplusComplete).IsTrue();
        await Assert.That(udp.Checksum.Value).IsEqualTo(new UdpChecksumUnavailable(UdpUnavailableReason.PseudoHeaderUnavailable));
    }

    [Test]
    [Arguments("udp-little")]
    [Arguments("udp-big")]
    public async Task Ipv6_fragment_preserves_fragment_metadata_and_bytes_without_decoding_udp(string sample)
    {
        var ip = IPv6(ReadRecord(sample, SampleRecord.Fragment));
        var fragment = ip.Payload is IPv6FragmentPayload payload ? payload
            : throw new InvalidOperationException("Expected an IPv6 fragment.");
        await Assert.That(fragment.Fragment).IsEqualTo(new IPv6Fragment(0, true, 0x01234567, 17));
        await Assert.That(fragment.DeclaredLength).IsEqualTo(10u);
        await Assert.That(Hex(fragment.Bytes)).IsEqualTo("FFFF800000010000CAFE");
    }

    [Test]
    [Arguments("udp-little")]
    [Arguments("udp-big")]
    public async Task Jumbogram_preserves_the_entire_payload_and_effective_udp_length(string sample)
    {
        var udp = Datagram(Udp(IPv6(ReadRecord(sample, SampleRecord.Jumbogram)).Payload));
        await Assert.That(udp.Header).IsEqualTo(new UdpHeader(0, 4660, 0, 0x9244));
        await Assert.That(udp.EffectiveLength).IsEqualTo(65536u);
        await Assert.That(udp.Payload.Length).IsEqualTo(65528);
        await Assert.That(udp.Payload.Span.ContainsAnyExcept((byte)0xff)).IsFalse();
        await Assert.That(udp.DeclaredSurplusLength).IsEqualTo(0u);
        await Assert.That(udp.SurplusArea.IsEmpty).IsTrue();
        await Assert.That(udp.IsComplete).IsTrue();
        await Assert.That(udp.IsSurplusComplete).IsTrue();
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
    }

    public enum SampleRecord
    {
        PayloadWithSurplus = 1, Ipv6Payload = 2, InvalidLength = 3, TruncatedSurplus = 4,
        TruncatedPayload = 5, Fragment = 6, AtomicFragment = 7, AbsentIpv4Checksum = 8,
        ZeroIpv6Checksum = 9, ZeroLength = 10, UnknownRoutingDestination = 11,
        ChangedPayload = 12, Jumbogram = 13, FinalValidDatagram = 14
    }

    private static FileStream OpenSample(string sample) =>
        File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
    private static PcapAnalysisReader OpenReader(Stream stream) =>
        PcapAnalysisReader.Open(stream) is PcapAnalysisReader reader ? reader : throw new InvalidOperationException("Expected a readable PCAP.");
    private static AnalyzedPacket ReadPacket(PcapAnalysisReader reader) =>
        reader.ReadNext() is AnalyzedPacket packet ? packet : throw new InvalidOperationException("Expected another analyzed packet.");
    private static DecodedEthernet ReadRecord(string sample, SampleRecord record)
    {
        using var stream = OpenSample(sample);
        var reader = OpenReader(stream);
        for (var number = 1; number < (int)record; number++) ReadPacket(reader);
        return Ethernet(ReadPacket(reader));
    }
    private static DecodedEthernet Ethernet(AnalyzedPacket packet) =>
        packet.Decoding is EthernetDecodeResult result && result is DecodedEthernet frame
            ? frame : throw new InvalidOperationException($"Expected Ethernet in record {packet.RecordNumber}.");
    private static DecodedIPv4 IPv4(DecodedEthernet frame) =>
        frame.Payload is IPv4DecodeResult result && result is DecodedIPv4 ip ? ip : throw new InvalidOperationException("Expected IPv4.");
    private static DecodedIPv6 IPv6(DecodedEthernet frame) =>
        frame.Payload is IPv6DecodeResult result && result is DecodedIPv6 ip ? ip : throw new InvalidOperationException("Expected IPv6.");
    private static UdpParseResult Udp(IPv4PayloadResult payload) =>
        payload is UdpParseResult udp ? udp : throw new InvalidOperationException("Expected UDP inside IPv4.");
    private static UdpParseResult Udp(IPv6PayloadResult payload) =>
        payload is UdpParseResult udp ? udp : throw new InvalidOperationException("Expected UDP inside IPv6.");
    private static UdpDatagram Datagram(UdpParseResult result) =>
        result is UdpDatagram udp ? udp : throw new InvalidOperationException($"Expected a UDP datagram, got {result.Value}.");
    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);
}
