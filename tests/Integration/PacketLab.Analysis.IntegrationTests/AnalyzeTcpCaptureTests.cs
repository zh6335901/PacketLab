using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.Tcp;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeTcpCaptureTests
{
#pragma warning disable PL0003 // One reader must continue through all diagnostics to the final valid record.
    [Test]
    [Arguments("tcp-little", PcapByteOrder.LittleEndian)]
    [Arguments("tcp-big", PcapByteOrder.BigEndian)]
    public async Task Analysis_reads_all_records_after_packet_diagnostics_and_reaches_eof(string sample, PcapByteOrder order)
    {
        using var stream = OpenSample(sample);
        var reader = OpenReader(stream);
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(order);
        var packets = new AnalyzedPacket[16];
        for (var i = 0; i < packets.Length; i++)
        {
            var packet = ReadPacket(reader);
            packets[i] = packet;
            await Assert.That(packet.RecordNumber).IsEqualTo(i + 1L);
            await Assert.That(packet.Packet.OriginalLength).IsEqualTo(70000u);
            await Assert.That(Ethernet(packet).Frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        var last = Segment(Tcp(IPv6(Ethernet(packets[^1])).Payload));
        await Assert.That(last.IsComplete).IsTrue();
        await Assert.That(last.Checksum.Value).IsEqualTo(TcpChecksumStatus.Match);
        await Assert.That(Hex(last.Payload)).IsEqualTo("CAFE01");
    }
#pragma warning restore PL0003

    [Test]
    [Arguments("tcp-little", SampleRecord.MaximumHeader, 60, 63u, "CAFE01", TcpChecksumStatus.Match)]
    [Arguments("tcp-big", SampleRecord.MaximumHeader, 60, 63u, "CAFE01", TcpChecksumStatus.Match)]
    [Arguments("tcp-little", SampleRecord.InvalidOption, 24, 27u, "CAFE01", TcpChecksumStatus.Match)]
    [Arguments("tcp-big", SampleRecord.InvalidOption, 24, 27u, "CAFE01", TcpChecksumStatus.Match)]
    [Arguments("tcp-little", SampleRecord.SourceRoute, 20, 23u, "CAFE01", TcpChecksumStatus.Match)]
    [Arguments("tcp-big", SampleRecord.SourceRoute, 20, 23u, "CAFE01", TcpChecksumStatus.Match)]
    [Arguments("tcp-little", SampleRecord.ChangedPayload, 20, 23u, "CAFE00", TcpChecksumStatus.Mismatch)]
    [Arguments("tcp-big", SampleRecord.ChangedPayload, 20, 23u, "CAFE00", TcpChecksumStatus.Mismatch)]
    [Arguments("tcp-little", SampleRecord.ZeroChecksum, 20, 22u, "358A", TcpChecksumStatus.Match)]
    [Arguments("tcp-big", SampleRecord.ZeroChecksum, 20, 22u, "358A", TcpChecksumStatus.Match)]
    public async Task Ipv4_tcp_preserves_fields_boundaries_and_checksum(string sample, SampleRecord record,
        int headerLength, uint declaredLength, string payload, TcpChecksumStatus checksum)
    {
        var tcp = Segment(Tcp(IPv4(ReadRecord(sample, record)).Payload));
        await Assert.That(tcp.Header.SourcePort).IsEqualTo((ushort)43981);
        await Assert.That(tcp.Header.DestinationPort).IsEqualTo((ushort)65244);
        await Assert.That(tcp.Header.HeaderLength).IsEqualTo(headerLength);
        await Assert.That(tcp.DeclaredLength).IsEqualTo(declaredLength);
        await Assert.That(Hex(tcp.Payload)).IsEqualTo(payload);
        await Assert.That(tcp.Checksum.Value).IsEqualTo(checksum);
    }

    [Test]
    [Arguments("tcp-little", SampleRecord.ExtensionChain)]
    [Arguments("tcp-big", SampleRecord.ExtensionChain)]
    [Arguments("tcp-little", SampleRecord.AtomicFragment)]
    [Arguments("tcp-big", SampleRecord.AtomicFragment)]
    [Arguments("tcp-little", SampleRecord.FinalValidSegment)]
    [Arguments("tcp-big", SampleRecord.FinalValidSegment)]
    public async Task Ipv6_located_tcp_preserves_fields_boundaries_and_checksum(string sample, SampleRecord record)
    {
        var tcp = Segment(Tcp(IPv6(ReadRecord(sample, record)).Payload));
        await Assert.That(tcp.Header.SourcePort).IsEqualTo((ushort)43981);
        await Assert.That(tcp.Header.DestinationPort).IsEqualTo((ushort)65244);
        await Assert.That(tcp.Header.HeaderLength).IsEqualTo(20);
        await Assert.That(tcp.DeclaredLength).IsEqualTo(23u);
        await Assert.That(Hex(tcp.Payload)).IsEqualTo("CAFE01");
        await Assert.That(tcp.Checksum.Value).IsEqualTo(TcpChecksumStatus.Match);
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Maximum_tcp_header_retains_options_and_excludes_ip_trailing_bytes(string sample)
    {
        var ip = IPv4(ReadRecord(sample, SampleRecord.MaximumHeader));
        var tcp = Segment(Tcp(ip.Payload));
        await Assert.That(ip.Packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
        await Assert.That(Hex(ip.Packet.TrailingBytes)).IsEqualTo("DEADBEEF");
        await Assert.That(tcp.Options.Items.Length).IsEqualTo(8);
        await Assert.That(tcp.Options.Padding.Length).IsEqualTo(5);
        await Assert.That(tcp.Header.SequenceNumber).IsEqualTo(0x81234567u);
        await Assert.That(tcp.Header.AcknowledgmentNumber).IsEqualTo(0xfedcba98u);
        await Assert.That(tcp.Header.Flags).IsEqualTo((TcpFlags)0x1db);
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Ipv6_extensions_locate_tcp_and_keep_trailing_bytes_separate(string sample)
    {
        var ip = IPv6(ReadRecord(sample, SampleRecord.ExtensionChain));
        await Assert.That(ip.RemainingOffset).IsEqualTo(56);
        await Assert.That(ip.Extensions.Length).IsEqualTo(2);
        await Assert.That(ip.Capture is IPv6Payload.KnownLength known && Hex(known.TrailingBytes) == "DEAD").IsTrue();
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Invalid_data_offset_is_retained_inside_ipv4(string sample)
    {
        var tcp = Tcp(IPv4(ReadRecord(sample, SampleRecord.InvalidDataOffset)).Payload);
        await Assert.That(tcp is TcpParseResult.InvalidDataOffset { Header.DataOffset: 4, DeclaredLength: 23 }).IsTrue();
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Fixed_header_truncation_is_retained_inside_ipv6(string sample)
    {
        var tcp = Tcp(IPv6(ReadRecord(sample, SampleRecord.TruncatedHeader)).Payload);
        await Assert.That(tcp is TcpParseResult.HeaderTruncated { DeclaredLength: 23, RemainingBytes.Length: 18 }).IsTrue();
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Options_truncation_retains_the_declared_header_length(string sample)
    {
        var tcp = Tcp(IPv4(ReadRecord(sample, SampleRecord.TruncatedOptions)).Payload);
        await Assert.That(tcp is TcpParseResult.OptionsTruncated
            { Header.HeaderLength: 60, DeclaredLength: 63, RemainingBytes.Length: 22 }).IsTrue();
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Payload_truncation_preserves_tcp_fields_without_claiming_a_checksum_result(string sample)
    {
        var tcp = Segment(Tcp(IPv6(ReadRecord(sample, SampleRecord.TruncatedPayload)).Payload));
        await Assert.That(tcp.Header.SourcePort).IsEqualTo((ushort)43981);
        await Assert.That(tcp.Header.DestinationPort).IsEqualTo((ushort)65244);
        await Assert.That(tcp.Header.HeaderLength).IsEqualTo(20);
        await Assert.That(tcp.DeclaredLength).IsEqualTo(23u);
        await Assert.That(Hex(tcp.Payload)).IsEqualTo("CAFE");
        await Assert.That(tcp.Checksum.Value).IsEqualTo(new TcpChecksumUnavailable(TcpUnavailableReason.PayloadTruncated));
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Malformed_option_has_a_structured_boundary_diagnostic(string sample)
    {
        var tcp = Segment(Tcp(IPv4(ReadRecord(sample, SampleRecord.InvalidOption)).Payload));
        await Assert.That(tcp.Options.Items.Single().Value.Value)
            .IsEqualTo(new TcpOptionValue.Invalid(TcpOptionFailure.ExceedsHeader, 5, 4));
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Unknown_routing_destination_preserves_tcp_without_claiming_a_checksum_result(string sample)
    {
        var tcp = Segment(Tcp(IPv6(ReadRecord(sample, SampleRecord.UnknownRoutingDestination)).Payload));
        await Assert.That(tcp.Header.SourcePort).IsEqualTo((ushort)43981);
        await Assert.That(tcp.Header.DestinationPort).IsEqualTo((ushort)65244);
        await Assert.That(tcp.Header.HeaderLength).IsEqualTo(20);
        await Assert.That(tcp.DeclaredLength).IsEqualTo(23u);
        await Assert.That(Hex(tcp.Payload)).IsEqualTo("CAFE01");
        await Assert.That(tcp.Checksum.Value).IsEqualTo(new TcpChecksumUnavailable(TcpUnavailableReason.PseudoHeaderUnavailable));
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Ipv4_fragment_stops_before_tcp_decoding(string sample)
    {
        var ip = IPv4(ReadRecord(sample, SampleRecord.Ipv4Fragment));
        await Assert.That(ip.Payload is IPv4FragmentPayload { Protocol: 6, MoreFragments: true }).IsTrue();
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Ipv6_fragment_stops_before_tcp_decoding(string sample)
    {
        var ip = IPv6(ReadRecord(sample, SampleRecord.Ipv6Fragment));
        await Assert.That(ip.Payload is IPv6FragmentPayload { Fragment: { NextHeader: 6, MoreFragments: true } }).IsTrue();
    }

    [Test]
    [Arguments("tcp-little")]
    [Arguments("tcp-big")]
    public async Task Invalid_extension_chain_stops_before_tcp_decoding(string sample)
    {
        var ip = IPv6(ReadRecord(sample, SampleRecord.InvalidExtensionChain));
        await Assert.That(ip.Payload is IPv6PayloadUnavailable { Reason: IPv6PayloadFailure.Invalid }).IsTrue();
    }

    public enum SampleRecord
    {
        MaximumHeader = 1, ExtensionChain = 2, InvalidDataOffset = 3, TruncatedHeader = 4,
        TruncatedOptions = 5, TruncatedPayload = 6, InvalidOption = 7, UnknownRoutingDestination = 8,
        SourceRoute = 9, AtomicFragment = 10, Ipv4Fragment = 11, Ipv6Fragment = 12,
        InvalidExtensionChain = 13, ChangedPayload = 14, ZeroChecksum = 15, FinalValidSegment = 16
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
    private static TcpParseResult Tcp(IPv4PayloadResult payload) =>
        payload is TcpParseResult tcp ? tcp : throw new InvalidOperationException("Expected TCP inside IPv4.");
    private static TcpParseResult Tcp(IPv6PayloadResult payload) =>
        payload is TcpParseResult tcp ? tcp : throw new InvalidOperationException("Expected TCP inside IPv6.");
    private static TcpSegment Segment(TcpParseResult result) =>
        result is TcpSegment tcp ? tcp : throw new InvalidOperationException($"Expected a TCP segment, got {result.Value}.");
    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);
}
