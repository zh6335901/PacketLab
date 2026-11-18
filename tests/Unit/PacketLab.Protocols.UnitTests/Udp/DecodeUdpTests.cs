using System.Buffers.Binary;
using FsCheck.Fluent;
using FsCheck;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.IP;
using PacketLab.Protocols.Udp;
using PacketLab.Protocols.UnitTests.IP.IPv6;

namespace PacketLab.Protocols.UnitTests.Udp;

public class DecodeUdpTests
{
    [Test]
    [Arguments(false, "0000123400070001", 8)]
    [Arguments(true, "0000123400010001", 8)]
    [Arguments(false, "0000123400000001", 8)]
    public async Task Invalid_udp_lengths_are_rejected(bool ipv6, string bytes, ushort declared)
    {
        // Act
        var result = Decode(ipv6, bytes, declared);

        // Assert
        var error = result is UdpParseResult.InvalidLength failure ? failure
            : throw new InvalidOperationException("Expected InvalidLength.");
        await Assert.That(error.RemainingBytes.Length).IsEqualTo((int)declared);
        await Assert.That(result.Checksum.Value).IsEqualTo(new UdpChecksumUnavailable(UdpUnavailableReason.InvalidLength));
    }

    [Test]
    [Arguments(false, "0000123400080001", 7)]
    [Arguments(true, "0000123400080001", 7)]
    [Arguments(true, "0000123400000001", 0)]
    public async Task Short_ip_declarations_do_not_borrow_trailing_capture(bool ipv6, string bytes, ushort declared)
    {
        // Act
        var result = Decode(ipv6, bytes, declared);

        // Assert
        var error = result is UdpParseResult.IpLengthTooShort failure ? failure
            : throw new InvalidOperationException("Expected IpLengthTooShort.");
        await Assert.That(error.RemainingBytes.Length).IsEqualTo((int)declared);
        await Assert.That(result.Checksum.Value).IsEqualTo(new UdpChecksumUnavailable(UdpUnavailableReason.IpLengthTooShort));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Udp_lengths_exceeding_ip_payload_do_not_borrow_trailing_capture(bool ipv6) =>
        Prop.ForAll((byte[] data, ushort selector) =>
        {
            // Arrange
            byte[] payload = [0xca, .. data];
            var length = (ushort)(8 + payload.Length);
            var wire = "00001234" + length.ToString("X4") + "0001" + Hex(payload);
            var declared = (ushort)(8 + selector % payload.Length);

            // Act
            var result = Decode(ipv6, wire, declared);

            // Assert
            return result is UdpParseResult.LengthExceedsIpPayload error && Hex(error.RemainingBytes) == wire[..(2 * declared)]
                && result.Checksum.Value is UdpChecksumUnavailable { Reason: UdpUnavailableReason.LengthExceedsIpPayload };
        }).Check(Config.QuickThrowOnFailure);

    public static IEnumerable<(bool Ipv6, int Length)> HeaderPrefixes() =>
        from ipv6 in new[] { false, true }
        from length in Enumerable.Range(0, 8)
        select (ipv6, length);

    [Test]
    [MethodDataSource(nameof(HeaderPrefixes))]
    public async Task Every_incomplete_header_prefix_reports_header_truncation(bool ipv6, int captured)
    {
        // Arrange
        var bytes = ipv6 ? "00001234000BC630CAFE01" : "00001234000B356ECAFE01";

        // Act
        var result = Decode(ipv6, bytes[..(captured * 2)], 11);

        // Assert
        var error = result is UdpParseResult.HeaderTruncated failure ? failure
            : throw new InvalidOperationException($"Expected header truncation with {captured} bytes.");
        await Assert.That(error.RemainingBytes.Length).IsEqualTo(captured);
        await Assert.That(result.Checksum.Value).IsEqualTo(new UdpChecksumUnavailable(UdpUnavailableReason.HeaderTruncated));
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Incomplete_payload_preserves_udp_header_and_received_prefix(bool ipv6) =>
        Prop.ForAll((byte[] data, ushort selector) =>
        {
            // Arrange
            byte[] payload = [0xca, .. data];
            var length = (ushort)(8 + payload.Length);
            int cut = selector % payload.Length;
            var wire = "00001234" + length.ToString("X4") + "0001" + Hex(payload[..cut]);

            // Act
            var udp = Datagram(Decode(ipv6, wire, length));

            // Assert
            return udp.Header == new UdpHeader(0, 0x1234, length, 1) && !udp.IsComplete
                && udp.Payload.Span.SequenceEqual(payload.AsSpan(0, cut))
                && udp.Checksum.Value is UdpChecksumUnavailable { Reason: UdpUnavailableReason.PayloadTruncated };
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Ip_surplus_and_capture_trailing_bytes_are_distinct_and_excluded_from_udp_checksum(bool ipv6) =>
        Prop.ForAll((byte[] surplus, byte[] tail) =>
        {
            // Act
            var result = Frame(ipv6, ValidUdp(ipv6) + Hex(surplus) + Hex(tail), (ushort)(11 + surplus.Length));

            // Assert
            var udp = Datagram(Udp(result));
            var trailing = ipv6 ? KnownTrailingBytes(IPv6(result)) : IPv4(result).Packet.TrailingBytes;
            return Hex(udp.Payload) == "CAFE01" && udp.SurplusArea.Span.SequenceEqual(surplus)
                && udp.DeclaredSurplusLength == surplus.Length && udp.IsSurplusComplete && trailing.Span.SequenceEqual(tail)
                && udp.Checksum.Value is UdpChecksumStatus.Match;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Incomplete_ip_surplus_does_not_disable_complete_udp_checksum(bool ipv6) =>
        Prop.ForAll((byte[] surplus, byte missing) =>
        {
            // Arrange
            int declaredSurplus = surplus.Length + 1 + missing;

            // Act
            var result = Frame(ipv6, ValidUdp(ipv6) + Hex(surplus), (ushort)(11 + declaredSurplus));

            // Assert
            var udp = Datagram(Udp(result));
            return udp.IsComplete && !udp.IsSurplusComplete && udp.DeclaredSurplusLength == declaredSurplus
                && udp.SurplusArea.Span.SequenceEqual(surplus) && udp.Checksum.Value is UdpChecksumStatus.Match
                && (ipv6 ? IPv6(result).Diagnostics.Single().Code == IPv6DiagnosticCode.PayloadTruncated
                    : !IPv4(result).Packet.IsDatagramComplete);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments("000012340000923D", "", 17, 8u)]
    [Arguments("000012340000C63BCAFE01", "1100000000000000", 60, 11u)]
    public async Task Zero_length_without_jumbo_uses_receiver_rule(string udpBytes, string extensions, byte next, uint effective)
    {
        // Act
        var udp = Datagram(Udp(Frame(true, extensions + udpBytes, next: next)));

        // Assert
        await Assert.That(udp.Header.Length).IsEqualTo((ushort)0);
        await Assert.That(udp.EffectiveLength).IsEqualTo(effective);
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
    }

    [Test]
    public async Task Maximum_jumbo_declaration_is_not_replaced_by_capture_length()
    {
        // Act
        var udp = Datagram(Udp(Frame(true, "1100C204FFFFFFFF0000123400000001CAFE", 0, 0)));

        // Assert
        await Assert.That(udp.EffectiveLength).IsEqualTo(uint.MaxValue - 8);
        await Assert.That(udp.IsComplete).IsFalse();
        await Assert.That(udp.Checksum.Value).IsEqualTo(new UdpChecksumUnavailable(UdpUnavailableReason.PayloadTruncated));
        await Assert.That(Hex(udp.Payload)).IsEqualTo("CAFE");
    }

    [Test]
    public async Task Jumbo_ip_can_carry_short_udp_with_incomplete_surplus()
    {
        // Act
        var udp = Datagram(Udp(Frame(true, "1100C204000100000000123400089235", 0, 0)));

        // Assert
        await Assert.That(udp.EffectiveLength).IsEqualTo(8u);
        await Assert.That(udp.DeclaredSurplusLength).IsEqualTo(65520u);
        await Assert.That(udp.IsComplete).IsTrue();
        await Assert.That(udp.IsSurplusComplete).IsFalse();
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
    }

    [Test]
    [Arguments(false, "0000123400080173", "", 8u)]
    [Arguments(true, "0000123400089235", "", 8u)]
    [Arguments(false, "00001234000B356ECAFE01", "CAFE01", 11u)]
    [Arguments(true, "00001234000BC630CAFE01", "CAFE01", 11u)]
    [Arguments(false, "00001234000AFFFF016F", "016F", 10u)]
    [Arguments(true, "00001234000AFFFF9231", "9231", 10u)]
    public async Task Fixed_vectors_verify_pseudo_headers_odd_payload_and_wire_negative_zero(
        bool ipv6, string bytes, string payload, uint effectiveLength)
    {
        // Act
        var udp = Datagram(Decode(ipv6, bytes));

        // Assert
        await Assert.That(udp.Header.SourcePort).IsEqualTo((ushort)0);
        await Assert.That(udp.Header.DestinationPort).IsEqualTo((ushort)0x1234);
        await Assert.That(udp.EffectiveLength).IsEqualTo(effectiveLength);
        await Assert.That(Hex(udp.Payload)).IsEqualTo(payload);
        await Assert.That(udp.IsComplete).IsTrue();
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Changing_a_payload_or_checksum_bit_invalidates_udp(bool ipv6) =>
        Prop.ForAll((byte selector, byte bit) =>
        {
            // Arrange
            var wire = Convert.FromHexString(ValidUdp(ipv6));
            int offset = 6 + selector % (wire.Length - 6);
            wire[offset] ^= (byte)(1 << (bit % 8));

            // Act
            var result = Decode(ipv6, Hex(wire));

            // Assert
            return Datagram(result).Checksum.Value is UdpChecksumStatus.Mismatch;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(false, UdpChecksumStatus.NotPresent)]
    [Arguments(true, UdpChecksumStatus.ZeroNotAllowed)]
    public async Task Zero_checksum_has_network_specific_semantics(bool ipv6, UdpChecksumStatus expected)
    {
        // Act
        var result = Decode(ipv6, "FFFF800000080000");

        // Assert
        await Assert.That(Datagram(result).Checksum.Value).IsEqualTo(expected);
    }

    [Test]
    [Arguments("", 17)]
    [Arguments("1100000000000000", 60)]
    [Arguments("3C000000000000001100000000000000", 0)]
    [Arguments("1104FE000102030405060708000000000000000000000000", 51)]
    [Arguments("1100000001234567", 44)]
    [Arguments("1100FE0000000000", 43)]
    public async Task Ipv6_extension_bytes_never_enter_udp_checksum(string extensions, byte next)
    {
        // Act
        var result = Frame(true, extensions + "00001234000BC630CAFE01", next: next);

        // Assert
        var udp = Datagram(Udp(result));
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
        await Assert.That(Hex(udp.Payload)).IsEqualTo("CAFE01");
    }

    [Test]
    public void Generated_ipv6_extensions_preserve_the_transport_checksum() =>
        Prop.ForAll((byte mask, byte[] lengths) =>
        {
            // Arrange
            var chain = ExtensionHeaders.Create(mask, lengths, 17);

            // Act
            var transport = Datagram(Udp(Frame(true, Hex(chain.Bytes) + ValidUdp(true), next: chain.First)));

            // Assert
            return Hex(transport.Payload) == "CAFE01" && transport.Checksum.Value is UdpChecksumStatus.Match;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments("01010000")]
    [Arguments("01019E02")]
    [Arguments("83030400")]
    [Arguments("94040000")]
    [Arguments("830704C633640200")]
    [Arguments("890704C633640200")]
    [Arguments("8307080102030400")]
    public async Task Ipv4_options_use_known_final_destination_and_ignore_unrelated_options(string options)
    {
        // Act
        var udp = Datagram(Udp(Frame(false, "0000123400080173", options: options)));

        // Assert
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
    }

    [Test]
    public async Task Active_source_route_uses_last_route_address_instead_of_current_destination()
    {
        // Act
        // Current destination remains 198.51.100.2; final route destination is 198.51.100.3.
        var udp = Datagram(Udp(Frame(false, "0000123400080172", options: "830B04C0000209C633640300")));

        // Assert
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
    }

    [Test]
    [Arguments("0101019E")]
    [Arguments("9E080000")]
    [Arguments("9E000000")]
    [Arguments("9E010000")]
    [Arguments("830703C633640200")]
    [Arguments("830705C633640200")]
    [Arguments("83070CC633640200")]
    [Arguments("830604C633640200")]
    [Arguments("83000400")]
    [Arguments("83080400")]
    [Arguments("830704C6336402890704C63364020000")]
    public async Task Ambiguous_or_malformed_source_routes_disable_checksum(string options)
    {
        // Act
        var udp = Datagram(Udp(Frame(false, "0000123400080173", options: options)));

        // Assert
        await Assert.That(udp.Checksum.Value).IsEqualTo(new UdpChecksumUnavailable(UdpUnavailableReason.PseudoHeaderUnavailable));
    }

    [Test]
    [Arguments("1100FE0100000000", 43)]
    [Arguments("1102C91020010DB800000000000000000000000900000000", 60)]
    public async Task Uncertain_ipv6_addresses_preserve_udp_but_disable_checksum(string extensions, byte next)
    {
        // Act
        var udp = Datagram(Udp(Frame(true, extensions + "0000123400089235", next: next)));

        // Assert
        await Assert.That(udp.IsComplete).IsTrue();
        await Assert.That(udp.Checksum.Value).IsEqualTo(new UdpChecksumUnavailable(UdpUnavailableReason.PseudoHeaderUnavailable));
    }

    [Test]
    public async Task Checksum_includes_every_ipv6_address_word()
    {
        // Act
        var result = ProtocolDecoder.Decode(Convert.FromHexString("FFFFFFFFFFFF02000000000186DD"
            + "60000000000B1140"
            + "20010DB8123456789ABCDEF011112222"
            + "20010DB887654321FEDCBA9833334444"
            + "00001234000BB532CAFE01"), LinkLayerProtocol.Ethernet);

        // Assert
        await Assert.That(Datagram(Udp(result)).Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
    }

    [Test]
    [Arguments(65536, 0x9244, 65528)]
    [Arguments(131073, 0x9341, 131065)]
    [Arguments(200008, 0x84FA, 200000)]
    public async Task Jumbo_checksum_uses_real_32_bit_udp_length_and_does_not_overflow(int length, ushort checksum, int payloadLength)
    {
        // Arrange
        var bytes = new byte[length + 8];
        Convert.FromHexString("1100C204").CopyTo(bytes, 0);
        BinaryPrimitives.WriteUInt32BigEndian(bytes.AsSpan(4), (uint)bytes.Length);
        Convert.FromHexString("000012340000").CopyTo(bytes, 8);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(14), checksum);
        bytes.AsSpan(16).Fill(0xff);

        // Act
        var udp = Datagram(Udp(Frame(true, Convert.ToHexString(bytes) + "DEAD", 0, 0)));

        // Assert
        await Assert.That(udp.EffectiveLength).IsEqualTo((uint)length);
        await Assert.That(udp.Payload.Length).IsEqualTo(payloadLength);
        await Assert.That(udp.IsComplete).IsTrue();
        await Assert.That(udp.DeclaredSurplusLength).IsEqualTo(0u);
        await Assert.That(udp.SurplusArea.IsEmpty).IsTrue();
        await Assert.That(udp.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task High_port_bits_are_preserved_in_network_byte_order(bool ipv6)
    {
        // Act
        var header = Datagram(Decode(ipv6, "ABCDFEDC00080000")).Header;

        // Assert
        await Assert.That(header).IsEqualTo(new UdpHeader(0xabcd, 0xfedc, 8, 0));
    }

    [Test]
    [Arguments(58)]
    [Arguments(50)]
    [Arguments(59)]
    [Arguments(253)]
    public async Task Unsupported_ipv4_protocols_do_not_dispatch_udp(byte protocol)
    {
        // Act
        var decoded = Frame(false, "0000123400080173", next: protocol);

        // Assert
        await Assert.That(IPv4(decoded).Payload is UnsupportedIpProtocol other && other.Protocol == protocol).IsTrue();
    }

    [Test]
    public async Task Located_non_udp_ipv6_protocol_is_preserved()
    {
        // Act
        var decoded = Frame(true, "0000123400089235", next: 58);

        // Assert
        await Assert.That(IPv6(decoded).Payload is UnsupportedIpProtocol { Protocol: 58 }).IsTrue();
    }

    [Test]
    public async Task No_next_header_does_not_dispatch_udp()
    {
        // Act
        var decoded = Frame(true, "0000123400089235", next: 59);

        // Assert
        await Assert.That(IPv6(decoded).Payload is IPv6NoNextHeader).IsTrue();
    }

    [Test]
    [Arguments(50)]
    [Arguments(253)]
    public async Task Unlocatable_ipv6_chains_do_not_dispatch_udp(byte next)
    {
        // Act
        var decoded = Frame(true, "0000123400089235", next: next);

        // Assert
        await Assert.That(IPv6(decoded).Payload is IPv6PayloadUnavailable { Reason: IPv6PayloadFailure.Unsupported }).IsTrue();
    }

    [Test]
    [Arguments("1100000000000000")]
    [Arguments("1100C2040000FFFF")]
    [Arguments("2C00C204000100001100000001234567")]
    public async Task Invalid_jumbo_combinations_do_not_guess_udp_position(string bytes)
    {
        // Act
        var decoded = Frame(true, bytes + "000012340000923D", 0, 0);

        // Assert
        await Assert.That(IPv6(decoded).Payload is IPv6PayloadUnavailable { Reason: IPv6PayloadFailure.Invalid }).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Ipv4_udp_fragments_preserve_protocol_and_bytes(bool first) =>
        Prop.ForAll((DoNotSize<ushort> index, bool more, byte[] bytes) =>
        {
            // Arrange
            ushort offset = first ? (ushort)0 : (ushort)(1 + index.Item % 0x1FFF);
            more |= first;
            var field = (ushort)(offset | (more ? 0x2000 : 0));

            // Act
            var frame = Ethernet(Frame(false, Hex(bytes), fragment: field));

            // Assert
            return frame.Payload is IPv4DecodeResult ip && ip is DecodedIPv4 decoded
                && decoded.Payload is IPv4FragmentPayload fragment && fragment.Protocol == 17
                && fragment.Offset == offset && fragment.MoreFragments == more
                && fragment.DeclaredLength == bytes.Length && fragment.Bytes.Span.SequenceEqual(bytes);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Ipv6_non_atomic_udp_fragments_preserve_protocol_and_bytes(bool first) =>
        Prop.ForAll((DoNotSize<ushort> index, bool more, byte[] bytes) =>
        {
            // Arrange
            ushort offset = first ? (ushort)0 : (ushort)(1 + index.Item % 0x1FFF);
            more |= first;
            var field = (ushort)(offset << 3 | (more ? 1 : 0));

            // Act
            var frame = Ethernet(Frame(true, "1100" + field.ToString("X4") + "01234567" + Hex(bytes), next: 44));

            // Assert
            return frame.Payload is IPv6DecodeResult ip && ip is DecodedIPv6 decoded
                && decoded.Payload is IPv6FragmentPayload fragment && fragment.Fragment.NextHeader == 17
                && fragment.Fragment.Offset == offset && fragment.Fragment.MoreFragments == more
                && fragment.DeclaredLength == bytes.Length && fragment.Bytes.Span.SequenceEqual(bytes);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(0x8100)]
    [Arguments(0x88B5)]
    public async Task Unsupported_ether_types_preserve_the_opaque_payload(ushort etherType)
    {
        // Arrange
        const string payload = "4500001C0000000040110000C0000201C63364020000123400080173";
        var bytes = Convert.FromHexString($"FFFFFFFFFFFF020000000001{etherType:X4}{payload}");

        // Act
        var result = ProtocolDecoder.Decode(bytes, LinkLayerProtocol.Ethernet);

        // Assert
        var unsupported = Ethernet(result).Payload is UnsupportedEtherType other ? other : throw new InvalidOperationException();
        await Assert.That(unsupported.EtherType).IsEqualTo(etherType);
        await Assert.That(Hex(unsupported.Bytes)).IsEqualTo(payload);
    }

    [Test]
    public async Task Ieee8023_length_encapsulation_does_not_expose_udp()
    {
        // Act
        var result = ProtocolDecoder.Decode(Convert.FromHexString("FFFFFFFFFFFF02000000000105DC"
            + "4500001C0000000040110000C0000201C63364020000123400080173"), LinkLayerProtocol.Ethernet);

        // Assert
        await Assert.That(result is EthernetDecodeResult ethernet && ethernet is EthernetParseResult.Ieee8023Length).IsTrue();
    }

    private static UdpParseResult Decode(bool ipv6, string bytes, ushort? declared = null) => Udp(Frame(ipv6, bytes, declared));

    private static UdpDatagram Datagram(UdpParseResult result) => result is UdpDatagram udp ? udp : throw new InvalidOperationException($"Expected UDP datagram, got {result.Value}.");

    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);

    private static DecodedEthernet Ethernet(ProtocolDecodeResult result) =>
        result is EthernetDecodeResult ethernet && ethernet is DecodedEthernet frame ? frame : throw new InvalidOperationException();

    private static DecodedIPv4 IPv4(ProtocolDecodeResult result) =>
        Ethernet(result).Payload is IPv4DecodeResult ip && ip is DecodedIPv4 decoded ? decoded : throw new InvalidOperationException();

    private static DecodedIPv6 IPv6(ProtocolDecodeResult result) =>
        Ethernet(result).Payload is IPv6DecodeResult ip && ip is DecodedIPv6 decoded ? decoded : throw new InvalidOperationException();

    private static UdpParseResult Udp(ProtocolDecodeResult result) => Ethernet(result).Payload switch
    {
        IPv4DecodeResult ip when ip is DecodedIPv4 decoded && decoded.Payload is UdpParseResult udp => udp,
        IPv6DecodeResult ip when ip is DecodedIPv6 decoded && decoded.Payload is UdpParseResult udp => udp,
        _ => throw new InvalidOperationException("Expected UDP dispatch.")
    };

    private static ProtocolDecodeResult Frame(bool ipv6, string payload, ushort? declared = null, byte next = 17,
        ushort fragment = 0, string options = "")
    {
        var bytes = Convert.FromHexString(payload);
        var header = ipv6
            ? Convert.FromHexString("600000000000114020010DB800000000000000000000000120010DB8000000000000000000000002")
            : Convert.FromHexString("450000000000000040110000C0000201C6336402" + options);
        if (ipv6)
        {
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(4), declared ?? checked((ushort)bytes.Length));
            header[6] = next;
        }
        else
        {
            header[0] = (byte)(0x40 | header.Length / 4);
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), (ushort)(header.Length + (declared ?? bytes.Length)));
            BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(6), fragment);
            header[9] = next;
        }
        var ethernet = Convert.FromHexString("FFFFFFFFFFFF020000000001" + (ipv6 ? "86DD" : "0800"));
        return ProtocolDecoder.Decode((byte[])[.. ethernet, .. header, .. bytes], LinkLayerProtocol.Ethernet);
    }

    private static string ValidUdp(bool ipv6) => ipv6 ? "00001234000BC630CAFE01" : "00001234000B356ECAFE01";

    private static ReadOnlyMemory<byte> KnownTrailingBytes(DecodedIPv6 packet) =>
        packet.Capture is IPv6Payload.KnownLength known ? known.TrailingBytes
            : throw new InvalidOperationException("Expected known IPv6 length.");
}
