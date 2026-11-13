using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Protocols.UnitTests.IP.IPv6;

public class ParseIPv6PacketTests
{
    private const string Addresses = "20010DB8000000000000000000000001FF020000000000000000000000000002";
    private const string Header = "6ABCDEF00004FD00" + Addresses;

    [Test]
    public async Task Fixed_header_preserves_distinct_bit_fields_network_order_addresses_and_unknown_next_header()
    {
        var packet = Parse("6ABCDEF00102FD00" + Addresses);
        await Assert.That(packet.Header).IsEqualTo(new IPv6Header(6, 0xab, 0xcdef0, 258, 253, 0,
            new IPv6Address(0x20010db800000000, 1), new IPv6Address(0xff02000000000000, 2)));
        await Assert.That(packet.Header.Source.ToString()).IsEqualTo("2001:db8::1");
        await Assert.That(packet.Header.Destination.ToString()).IsEqualTo("ff02::2");
        await Assert.That(Known(packet).IsDatagramComplete).IsFalse();
    }

    [Test]
    [Arguments("6000000000003BFF", 0, 0u, 255)]
    [Arguments("6FFFFFFF00003B01", 255, 0xfffffu, 1)]
    [Arguments("6018000000003B80", 1, 0x80000u, 128)]
    public async Task Bit_field_edges_do_not_bleed_into_adjacent_fields(string prefix, byte trafficClass, uint flowLabel, byte hopLimit)
    {
        var header = Parse(prefix + Addresses).Header;
        await Assert.That(header.Version).IsEqualTo((byte)6);
        await Assert.That(header.TrafficClass).IsEqualTo(trafficClass);
        await Assert.That(header.FlowLabel).IsEqualTo(flowLabel);
        await Assert.That(header.HopLimit).IsEqualTo(hopLimit);
    }

    public static IEnumerable<int> ShortLengths() => Enumerable.Range(0, 40);

    [Test]
    [MethodDataSource(nameof(ShortLengths))]
    public async Task Short_headers_report_actual_bytes_and_required_length(int length)
    {
        var bytes = Convert.FromHexString(Header)[..length];
        var result = IPv6Parser.Parse(bytes);
        var incomplete = result is IPv6ParseResult.IncompleteHeader parsed ? parsed
            : throw new InvalidOperationException("Expected an incomplete header.");
        await Assert.That(incomplete.RequiredLength).IsEqualTo(40);
        await Assert.That(incomplete.CapturedLength).IsEqualTo(length);
        await Assert.That(incomplete.RemainingBytes.Span.SequenceEqual(bytes)).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(7)]
    public async Task Complete_header_with_wrong_version_is_distinct_from_truncation(byte version)
    {
        var bytes = Convert.FromHexString(Header + "CAFE");
        bytes[0] = (byte)((version << 4) | 0xa);
        var result = IPv6Parser.Parse(bytes);
        var invalid = result is IPv6ParseResult.InvalidVersion parsed ? parsed
            : throw new InvalidOperationException("Expected an invalid version.");
        await Assert.That(invalid.Version).IsEqualTo(version);
        await Assert.That(invalid.RemainingBytes.Span.SequenceEqual(bytes)).IsTrue();
        await Assert.That(IPv6Parser.Parse(bytes.AsMemory(0, 39)) is IPv6ParseResult.IncompleteHeader).IsTrue();
    }

    [Test]
    [Arguments(40, "", "", false)]
    [Arguments(42, "CAFE", "", false)]
    [Arguments(44, "CAFE0102", "", true)]
    [Arguments(48, "CAFE0102", "DEADBEEF", true)]
    public async Task Declared_length_bounds_payload_and_preserves_trailing_bytes(int length, string payloadHex, string trailingHex, bool complete)
    {
        var bytes = Convert.FromHexString(Header + "CAFE0102DEADBEEF");
        var packet = IPv6Parser.Parse(bytes.AsMemory(0, length)) is IPv6Packet parsed ? parsed
            : throw new InvalidOperationException("Expected a complete header.");
        await Assert.That(packet.Header).IsEqualTo(Parse(Header).Header);
        var payload = Known(packet);
        await Assert.That(payload.DeclaredLength).IsEqualTo((ushort)4);
        await Assert.That(payload.DeclaredDatagramLength).IsEqualTo(44);
        await Assert.That(payload.IsDatagramComplete).IsEqualTo(complete);
        await Assert.That(Convert.ToHexString(payload.Bytes.Span)).IsEqualTo(payloadHex);
        await Assert.That(Convert.ToHexString(payload.TrailingBytes.Span)).IsEqualTo(trailingHex);
        await Assert.That(payload.Bytes.Equals(bytes.AsMemory(40, payloadHex.Length / 2))).IsTrue();
        await Assert.That(payload.TrailingBytes.Equals(bytes.AsMemory(Math.Min(length, 44), trailingHex.Length / 2))).IsTrue();
    }

    [Test]
    public async Task Maximum_payload_length_does_not_overflow_datagram_length_or_require_captured_payload()
    {
        var payload = Known(Parse("60000000FFFF1101" + Addresses));
        await Assert.That(payload.DeclaredDatagramLength).IsEqualTo(65575);
        await Assert.That(payload.DeclaredLength).IsEqualTo(ushort.MaxValue);
        await Assert.That(payload.Bytes.IsEmpty).IsTrue();
        await Assert.That(payload.IsDatagramComplete).IsFalse();
    }

    [Test]
    [Arguments(0)]
    [Arguments(43)]
    [Arguments(44)]
    [Arguments(50)]
    [Arguments(51)]
    [Arguments(60)]
    public async Task Invalid_extension_headers_preserve_fixed_header_and_payload(byte nextHeader)
    {
        var packet = Parse("600000000004" + nextHeader.ToString("X2") + "40" + Addresses + "FFFFFFFF");
        await Assert.That(packet.Header.NextHeader).IsEqualTo(nextHeader);
        var payload = Known(packet);
        await Assert.That(payload.IsDatagramComplete).IsTrue();
        await Assert.That(Convert.ToHexString(payload.Bytes.Span)).IsEqualTo("FFFFFFFF");
    }

    [Test]
    [Arguments(59)]
    [Arguments(253)]
    public async Task Zero_length_without_hop_by_hop_keeps_remaining_capture_as_trailing_bytes(byte nextHeader)
    {
        var packet = Parse("600000000000" + nextHeader.ToString("X2") + "40" + Addresses + "DEADBEEF");
        var payload = Known(packet);
        await Assert.That(payload.DeclaredLength).IsEqualTo((ushort)0);
        await Assert.That(payload.DeclaredDatagramLength).IsEqualTo(40);
        await Assert.That(payload.IsDatagramComplete).IsTrue();
        await Assert.That(payload.Bytes.IsEmpty).IsTrue();
        await Assert.That(Convert.ToHexString(payload.TrailingBytes.Span)).IsEqualTo("DEADBEEF");
    }

    [Test]
    [Arguments("")]
    [Arguments("FFFFFFFF")]
    public async Task Zero_length_with_hop_by_hop_preserves_capture_without_asserting_length_or_completeness(string remaining)
    {
        var bytes = Convert.FromHexString("6ABCDEF00000007F" + Addresses + remaining);
        var packet = IPv6Parser.Parse(bytes) is IPv6Packet parsed ? parsed
            : throw new InvalidOperationException("Expected a complete header.");
        await Assert.That(packet.Header).IsEqualTo(new IPv6Header(6, 0xab, 0xcdef0, 0, 0, 127,
            new IPv6Address(0x20010db800000000, 1), new IPv6Address(0xff02000000000000, 2)));
        var payload = packet.Payload is IPv6Payload.UndeterminedLength unknown ? unknown
            : throw new InvalidOperationException("Expected undetermined payload length.");
        await Assert.That(Convert.ToHexString(payload.CapturedBytes.Span)).IsEqualTo(remaining);
        await Assert.That(payload.CapturedBytes.Equals(bytes.AsMemory(40))).IsTrue();
    }

    [Test]
    [Arguments("20010DB8000000010002000300040005", "2001:db8:0:1:2:3:4:5")]
    [Arguments("20010000000000010000000000010001", "2001::1:0:0:1:1")]
    [Arguments("20010000000000010000000000000001", "2001:0:0:1::1")]
    [Arguments("00000000000000000000000000000000", "::")]
    [Arguments("00000000000000000000000000000001", "::1")]
    [Arguments("20010DB8000000000000000000000000", "2001:db8::")]
    [Arguments("20010DB8ABCD123456789ABCDEF00001", "2001:db8:abcd:1234:5678:9abc:def0:1")]
    [Arguments("00000000000000000000FFFFC0000201", "::ffff:192.0.2.1")]
    public async Task Addresses_use_canonical_rfc5952_text(string source, string expected)
    {
        var packet = Parse("6000000000003B40" + source + Addresses[32..]);
        await Assert.That(packet.Header.Source.ToString()).IsEqualTo(expected);
    }

    private static IPv6Packet Parse(string hex) => IPv6Parser.Parse(Convert.FromHexString(hex)) is IPv6Packet packet
        ? packet : throw new InvalidOperationException("Expected an IPv6 packet.");

    private static IPv6Payload.KnownLength Known(IPv6Packet packet) => packet.Payload is IPv6Payload.KnownLength payload
        ? payload : throw new InvalidOperationException("Expected a known payload length.");
}
