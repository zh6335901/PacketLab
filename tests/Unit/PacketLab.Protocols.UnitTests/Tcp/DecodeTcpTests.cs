using System.Buffers.Binary;
using FsCheck.Fluent;
using FsCheck;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.UnitTests.IP.IPv6;

namespace PacketLab.Protocols.UnitTests.Tcp;

public class DecodeTcpTests
{
    private const string V4 = "ABCDFEDC81234567FEDCBA985BDB89AB698ACDEFCAFE01";

    private const string V6 = "ABCDFEDC81234567FEDCBA985BDB89ABFA4CCDEFCAFE01";

#pragma warning disable PL0003 // Every fixed-header prefix checks the same truncation contract.
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Every_incomplete_fixed_header_prefix_reports_header_truncation(bool ipv6)
    {
        var wire = WithOptions("020405B401030307080A123456789ABCDEF00000") + "CAFE01";
        for (var captured = 0; captured < 20; captured++)
        {
            var result = Decode(ipv6, wire[..(captured * 2)], 43);
            await Assert.That(result is TcpParseResult.HeaderTruncated error && error.RemainingBytes.Length == captured)
                .IsTrue().Because($"only {captured} fixed header bytes were captured");
            await Assert.That(result.Checksum.Value).IsEqualTo(new TcpChecksumUnavailable(TcpUnavailableReason.HeaderTruncated));
        }
    }
#pragma warning restore PL0003

#pragma warning disable PL0003 // Every options prefix checks the same fixed-header preservation contract.
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Every_incomplete_options_prefix_preserves_the_fixed_header(bool ipv6)
    {
        var wire = WithOptions("020405B401030307080A123456789ABCDEF00000") + "CAFE01";
        for (var captured = 20; captured < 40; captured++)
        {
            var result = Decode(ipv6, wire[..(captured * 2)], 43);
            await Assert.That(result is TcpParseResult.OptionsTruncated error && error.Header.HeaderLength == 40
                && error.Options.RawBytes.Length == captured - 20 && error.RemainingBytes.Length == captured)
                .IsTrue().Because($"only {captured - 20} option bytes were captured");
            await Assert.That(result.Checksum.Value).IsEqualTo(new TcpChecksumUnavailable(TcpUnavailableReason.HeaderTruncated));
        }
    }
#pragma warning restore PL0003

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Options_truncation_preserves_the_fixed_header_and_option_prefix(bool ipv6) =>
        Prop.ForAll((byte words, ushort selector) =>
        {
            int length = 4 * (1 + words % 10);
            var wire = WithOptions(string.Concat(Enumerable.Repeat("01", length)));
            int cut = 20 + selector % length;
            var full = Segment(Decode(ipv6, wire));
            var result = Decode(ipv6, wire[..(2 * cut)], (ushort)(20 + length));
            return result is TcpParseResult.OptionsTruncated error && error.Header == full.Header
                && error.RemainingBytes.Length == cut && error.Options.RawBytes.Span.SequenceEqual(full.Options.RawBytes.Span[..(cut - 20)])
                && result.Checksum.Value is TcpChecksumUnavailable { Reason: TcpUnavailableReason.HeaderTruncated };
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Incomplete_payload_preserves_declared_length_and_captured_bytes(bool ipv6) =>
        Prop.ForAll((byte words, byte[] data, ushort selector) =>
        {
            byte[] payload = [0xca, .. data];
            var header = WithOptions(new string('0', 8 * (words % 11)));
            int cut = selector % payload.Length;
            var segment = Segment(Decode(ipv6, header + Hex(payload[..cut]), (ushort)(header.Length / 2 + payload.Length)));
            return !segment.IsComplete && segment.DeclaredPayloadLength == payload.Length
                && segment.Payload.Span.SequenceEqual(payload.AsSpan(0, cut))
                && segment.Checksum.Value is TcpChecksumUnavailable { Reason: TcpUnavailableReason.PayloadTruncated };
        }).Check(Config.QuickThrowOnFailure);

#pragma warning disable PL0003 // Every short IP length checks the same capture boundary contract.
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Short_ip_declarations_do_not_borrow_trailing_capture(bool ipv6)
    {
        for (ushort declared = 0; declared < 20; declared++)
            await Assert.That(Decode(ipv6, V4, declared) is TcpParseResult.IpLengthTooShort error
                && error.RemainingBytes.Length == declared).IsTrue().Because($"IP declares only {declared} bytes");
    }
#pragma warning restore PL0003

#pragma warning disable PL0003 // Every invalid data offset checks the same rejection contract.
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Data_offsets_below_five_do_not_guess_a_payload(bool ipv6)
    {
        for (byte offset = 0; offset < 5; offset++)
        {
            var wire = Convert.FromHexString(V4);
            wire[12] = (byte)(offset << 4);
            var result = Decode(ipv6, Hex(wire));
            await Assert.That(result is TcpParseResult.InvalidDataOffset error && error.Header.DataOffset == offset).IsTrue();
            await Assert.That(result.Checksum.Value).IsEqualTo(new TcpChecksumUnavailable(TcpUnavailableReason.InvalidDataOffset));
        }
    }
#pragma warning restore PL0003

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Header_exceeding_ip_declaration_does_not_borrow_trailing_capture(bool ipv6) =>
        Prop.ForAll((byte words, byte selector, byte[] tail) =>
        {
            int optionsLength = 4 * (1 + words % 10);
            var header = WithOptions(new string('0', 2 * optionsLength));
            var result = Decode(ipv6, header + Hex(tail), (ushort)(20 + selector % optionsLength));
            return result is TcpParseResult.HeaderExceedsSegment error && error.Header.HeaderLength == 20 + optionsLength
                && result.Checksum.Value is TcpChecksumUnavailable { Reason: TcpUnavailableReason.HeaderExceedsSegment };
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task Maximum_jumbo_declaration_is_not_replaced_by_captured_length()
    {
        var segment = Segment(Tcp(Frame(true, "0600C204FFFFFFFF" + V6, 0, 0)));
        await Assert.That(segment.DeclaredLength).IsEqualTo(uint.MaxValue - 8);
        await Assert.That(segment.Checksum.Value).IsEqualTo(new TcpChecksumUnavailable(TcpUnavailableReason.PayloadTruncated));
    }

    [Test]
    public async Task Maximum_header_preserves_common_options_unknown_values_and_eol_padding()
    {
        const string options = "020405B403030E0402080A81234567FEDCBA98050A1234567887654321FE04CAFE01000000000000";
        var segment = Segment(Decode(false, WithOptions(options) + "AB"));
        await Assert.That(segment.Header.HeaderLength).IsEqualTo(60);
        await Assert.That(Hex(segment.Options.RawBytes)).IsEqualTo(options);
        await Assert.That(Hex(segment.Payload)).IsEqualTo("AB");
        var items = segment.Options.Items;
        await Assert.That(items.Length).IsEqualTo(8);
        await Assert.That(items[0].Value.Value).IsEqualTo(new TcpOptionValue.MaximumSegmentSize(1460));
        await Assert.That(items[1].Value.Value).IsEqualTo(new TcpOptionValue.WindowScale(14));
        await Assert.That(items[2].Value is TcpOptionValue.SackPermitted).IsTrue();
        await Assert.That(items[3].Value.Value).IsEqualTo(new TcpOptionValue.Timestamp(0x81234567, 0xfedcba98));
        var sack = items[4].Value is TcpOptionValue.Sack s ? s : throw new InvalidOperationException();
        await Assert.That(sack.Blocks.Single()).IsEqualTo(new TcpSackBlock(0x12345678, 0x87654321));
        await Assert.That(items[5].Value is TcpOptionValue.Unknown).IsTrue();
        await Assert.That(Hex(items[5].Bytes)).IsEqualTo("FE04CAFE");
        await Assert.That(items[5].Offset).IsEqualTo(49);
        await Assert.That(items[6].Value is TcpOptionValue.NoOperation).IsTrue();
        await Assert.That(items[7].Value is TcpOptionValue.End).IsTrue();
        await Assert.That(segment.Options.Padding.Length).IsEqualTo(5);
        await Assert.That(segment.Options.HasNonZeroPadding).IsFalse();
    }

    [Test]
    public void Bytes_after_eol_are_retained_as_padding() =>
        Prop.ForAll((byte[] data) =>
        {
            var padding = data.Take(39).ToArray();
            int nops = 3 - padding.Length % 4;
            var options = string.Concat(Enumerable.Repeat("01", nops)) + "00" + Hex(padding);
            var parsed = Segment(Decode(false, WithOptions(options))).Options;
            return parsed.Padding.Span.SequenceEqual(padding) && parsed.HasNonZeroPadding == padding.Any(b => b != 0);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments("010101FE", TcpOptionFailure.ExceedsHeader)]
    [Arguments("FE05AABB", TcpOptionFailure.ExceedsHeader)]
    [Arguments("FE000000", TcpOptionFailure.InvalidLength)]
    [Arguments("FE010000", TcpOptionFailure.InvalidLength)]
    [Arguments("02030000", TcpOptionFailure.InvalidLength)]
    [Arguments("03040000", TcpOptionFailure.InvalidLength)]
    [Arguments("04040000", TcpOptionFailure.InvalidLength)]
    [Arguments("05020000", TcpOptionFailure.InvalidLength)]
    [Arguments("050B00000000000000000000", TcpOptionFailure.InvalidLength)]
    [Arguments("08040000", TcpOptionFailure.InvalidLength)]
    public async Task Invalid_option_lengths_preserve_raw_bytes_and_payload(string options, TcpOptionFailure reason)
    {
        var segment = Segment(Decode(false, WithOptions(options) + "CAFE"));
        await Assert.That(segment.Options.Items.Any(o => o.Value is TcpOptionValue.Invalid invalid && invalid.Reason == reason)).IsTrue();
        await Assert.That(Hex(segment.Options.RawBytes)).IsEqualTo(options);
        await Assert.That(Hex(segment.Payload)).IsEqualTo("CAFE");
    }

    [Test]
    public async Task Options_capture_failure_is_distinct_from_declared_header_overrun()
    {
        var result = Decode(false, WithOptions("FE040102")[..44], 24);
        var shortOptions = result is TcpParseResult.OptionsTruncated o ? o : throw new InvalidOperationException();
        await Assert.That(shortOptions.Options.Items.Single().Value.Value)
            .IsEqualTo(new TcpOptionValue.Invalid(TcpOptionFailure.CaptureTruncated, 4, 2));
    }

    [Test]
    public async Task Out_of_range_window_scale_preserves_the_wire_value()
    {
        var segment = Segment(Decode(false, WithOptions("0303FF00")));
        await Assert.That(segment.Options.Items[0].Value is TcpOptionValue.WindowScale { ShiftCount: 255, IsInRange: false }).IsTrue();
    }

    [Test]
    public async Task Sack_can_contain_multiple_blocks_and_fill_the_option_area_without_eol()
    {
        var segment = Segment(Decode(false, WithOptions("01010522123456788765432100000000FFFFFFFF8000000090000000000000010000000201010101")));
        var sack = segment.Options.Items[2].Value is TcpOptionValue.Sack s ? s : throw new InvalidOperationException();
        await Assert.That(sack.Blocks.Length).IsEqualTo(4);
        await Assert.That(sack.Blocks[1]).IsEqualTo(new TcpSackBlock(0, uint.MaxValue));
        await Assert.That(sack.Blocks[2]).IsEqualTo(new TcpSackBlock(0x80000000, 0x90000000));
        await Assert.That(sack.Blocks[3]).IsEqualTo(new TcpSackBlock(1, 2));
        await Assert.That(segment.Options.Padding.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments(false, V4, "CAFE01")]
    [Arguments(true, V6, "CAFE01")]
    [Arguments(false, "ABCDFEDC81234567FEDCBA985BDB89AB358CCDEF", "")]
    [Arguments(true, "ABCDFEDC81234567FEDCBA985BDB89ABC64ECDEF", "")]
    [Arguments(false, "ABCDFEDC81234567FEDCBA985BDB89AB6987CDEFCAFE0102", "CAFE0102")]
    [Arguments(true, "ABCDFEDC81234567FEDCBA985BDB89ABFA49CDEFCAFE0102", "CAFE0102")]
    [Arguments(false, "ABCDFEDC81234567FEDCBA985BDB89AB0000CDEF358A", "358A")]
    [Arguments(true, "ABCDFEDC81234567FEDCBA985BDB89AB0000CDEFC64C", "C64C")]
    public async Task Independent_vectors_cover_fields_odd_lengths_and_valid_zero_checksum(bool ipv6, string wire, string payload)
    {
        var segment = Segment(Decode(ipv6, wire));
        await Assert.That(segment.Header).IsEqualTo(new TcpHeader(0xabcd, 0xfedc, 0x81234567, 0xfedcba98,
            5, 5, TcpFlags.AE | TcpFlags.CWR | TcpFlags.ECE | TcpFlags.ACK | TcpFlags.PSH | TcpFlags.SYN | TcpFlags.FIN,
            0x89ab, Convert.ToUInt16(wire.Substring(32, 4), 16), 0xcdef));
        await Assert.That(Hex(segment.Payload)).IsEqualTo(payload);
        await Assert.That(segment.DeclaredLength).IsEqualTo((uint)(wire.Length / 2));
        await Assert.That(segment.IsComplete).IsTrue();
        await Assert.That(segment.Options.RawBytes.IsEmpty).IsTrue();
        await Assert.That(segment.Checksum.Value).IsEqualTo(TcpChecksumStatus.Match);
    }

#pragma warning disable PL0003 // Every byte mutation checks the same checksum sensitivity contract.
    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Changed_fields_and_payload_fail_checksum(bool ipv6)
    {
        var wire = Convert.FromHexString(ipv6 ? V6 : V4);
        for (var offset = 0; offset < wire.Length; offset++)
        {
            var changed = (byte[])wire.Clone();
            changed[offset] ^= 1;
            await Assert.That(Segment(Decode(ipv6, Hex(changed))).Checksum.Value)
                .IsEqualTo(TcpChecksumStatus.Mismatch).Because($"changing the low bit at byte {offset} must invalidate the checksum");
        }
    }
#pragma warning restore PL0003

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Single_bit_changes_in_the_tcp_segment_fail_checksum(bool ipv6) =>
        Prop.ForAll((byte position, byte bit) =>
        {
            var bytes = Convert.FromHexString(ipv6 ? V6 : V4);
            int offset = position % bytes.Length;
            bytes[offset] ^= (byte)(1 << (bit % (offset == 12 ? 4 : 8)));
            return Segment(Decode(ipv6, Hex(bytes))).Checksum.Value is TcpChecksumStatus.Mismatch;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Clearing_a_required_nonzero_checksum_does_not_mean_checksum_absent(bool ipv6)
    {
        var wire = Convert.FromHexString(ipv6 ? V6 : V4);
        wire[16] = wire[17] = 0;
        await Assert.That(Segment(Decode(ipv6, Hex(wire))).Checksum.Value).IsEqualTo(TcpChecksumStatus.Mismatch);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Ip_trailing_bytes_are_excluded_from_tcp_payload_and_checksum(bool ipv6) =>
        Prop.ForAll((byte[] tail) =>
        {
            var segment = Segment(Decode(ipv6, (ipv6 ? V6 : V4) + Hex(tail), 23));
            return Hex(segment.Payload) == "CAFE01" && segment.Checksum.Value is TcpChecksumStatus.Match;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments("0600000000000000", 0)]
    [Arguments("0600000000000000", 60)]
    [Arguments("0600FE0000000000", 43)]
    [Arguments("06020000010203040506070800000000", 51)]
    [Arguments("0600000001234567", 44)]
    [Arguments("3C000000000000002B000000000000003300FE00000000002C0200000102030405060708000000000600000001234567", 0)]
    public async Task Ipv6_checksum_excludes_extensions_and_uses_final_protocol_and_length(string extensions, byte next)
    {
        var segment = Segment(Tcp(Frame(true, extensions + V6, next: next)));
        await Assert.That(Hex(segment.Payload)).IsEqualTo("CAFE01");
        await Assert.That(segment.Checksum.Value).IsEqualTo(TcpChecksumStatus.Match);
    }

    [Test]
    public void Generated_ipv6_extensions_preserve_the_transport_checksum() =>
        Prop.ForAll((byte mask, byte[] lengths) =>
        {
            var chain = ExtensionHeaders.Create(mask, lengths, 6);
            var transport = Segment(Tcp(Frame(true, Hex(chain.Bytes) + V6, next: chain.First)));
            return Hex(transport.Payload) == "CAFE01" && transport.Checksum.Value is TcpChecksumStatus.Match;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments("01010000", V4)]
    [Arguments("9E040000", V4)]
    [Arguments("83030400", V4)]
    [Arguments("8307080102030400", V4)]
    [Arguments("830B04C0000209C633640300", "ABCDFEDC81234567FEDCBA985BDB89AB6989CDEFCAFE01")]
    [Arguments("890B04C0000209C633640300", "ABCDFEDC81234567FEDCBA985BDB89AB6989CDEFCAFE01")]
    public async Task Ipv4_options_use_reliable_final_destination(string options, string wire)
    {
        await Assert.That(Segment(Tcp(Frame(false, wire, options: options))).Checksum.Value).IsEqualTo(TcpChecksumStatus.Match);
    }

    [Test]
    [Arguments("830705C633640200")]
    [Arguments("83070CC633640200")]
    [Arguments("830604C633640200")]
    [Arguments("830704C6336402890704C63364020000")]
    [Arguments("9E080000")]
    public async Task Uncertain_ipv4_route_disables_checksum_but_keeps_tcp(string options)
    {
        await Assert.That(Segment(Tcp(Frame(false, V4, options: options))).Checksum.Value)
            .IsEqualTo(new TcpChecksumUnavailable(TcpUnavailableReason.PseudoHeaderUnavailable));
    }

    [Test]
    [Arguments("0600FE0100000000", 43)]
    [Arguments("0602C91020010DB800000000000000000000000900000000", 60)]
    public async Task Uncertain_ipv6_addresses_disable_checksum_but_keep_tcp(string extensions, byte next)
    {
        var tcp = Segment(Tcp(Frame(true, extensions + V6, next: next)));
        await Assert.That(tcp.IsComplete).IsTrue();
        await Assert.That(tcp.Checksum.Value).IsEqualTo(new TcpChecksumUnavailable(TcpUnavailableReason.PseudoHeaderUnavailable));
    }

#pragma warning disable PL0003 // Every address byte mutation checks the same pseudo-header checksum contract.
    [Test]
    public async Task Every_ipv6_address_word_contributes_to_checksum()
    {
        var frame = Convert.FromHexString("FFFFFFFFFFFF02000000000186DD6000000000170640"
            + "20010DB8123456789ABCDEF01111222220010DB887654321FEDCBA9833334444"
            + "ABCDFEDC81234567FEDCBA985BDB89ABE94ECDEFCAFE01");
        await Assert.That(Segment(Tcp(ProtocolDecoder.Decode(frame, LinkLayerProtocol.Ethernet))).Checksum.Value).IsEqualTo(TcpChecksumStatus.Match);
        for (var i = 22; i < 54; i++)
        {
            frame[i] ^= 1;
            await Assert.That(Segment(Tcp(ProtocolDecoder.Decode(frame, LinkLayerProtocol.Ethernet))).Checksum.Value).IsEqualTo(TcpChecksumStatus.Mismatch);
            frame[i] ^= 1;
        }
    }
#pragma warning restore PL0003

    [Test]
    [Arguments(65536, 0xc661)]
    [Arguments(131073, 0xc75e)]
    [Arguments(200008, 0xb917)]
    public async Task Jumbo_checksum_uses_full_32_bit_segment_length(int length, ushort checksum)
    {
        var wire = new byte[length + 8];
        Convert.FromHexString("0600C204").CopyTo(wire, 0);
        BinaryPrimitives.WriteUInt32BigEndian(wire.AsSpan(4), (uint)wire.Length);
        Convert.FromHexString(V6[..40]).CopyTo(wire, 8);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(24), checksum);
        wire.AsSpan(28).Fill(0xff);
        var segment = Segment(Tcp(Frame(true, Hex(wire) + "DEAD", 0, 0)));
        await Assert.That(segment.DeclaredLength).IsEqualTo((uint)length);
        await Assert.That(segment.Payload.Length).IsEqualTo(length - 20);
        await Assert.That(segment.Checksum.Value).IsEqualTo(TcpChecksumStatus.Match);
    }

    [Test]
    [Arguments(0x100, TcpFlags.AE)]
    [Arguments(0x80, TcpFlags.CWR)]
    [Arguments(0x40, TcpFlags.ECE)]
    [Arguments(0x20, TcpFlags.URG)]
    [Arguments(0x10, TcpFlags.ACK)]
    [Arguments(0x08, TcpFlags.PSH)]
    [Arguments(0x04, TcpFlags.RST)]
    [Arguments(0x02, TcpFlags.SYN)]
    [Arguments(0x01, TcpFlags.FIN)]
    public async Task Flag_bits_are_independent_of_reserved_and_offset(ushort bits, TcpFlags expected)
    {
        var wire = Convert.FromHexString(V4);
        BinaryPrimitives.WriteUInt16BigEndian(wire.AsSpan(12), (ushort)(0x5e00 | bits));
        var header = Segment(Decode(false, Hex(wire))).Header;
        await Assert.That(header.Flags).IsEqualTo(expected);
        await Assert.That(header.Reserved).IsEqualTo((byte)7);
        await Assert.That(header.DataOffset).IsEqualTo((byte)5);
    }

    [Test]
    public void Flag_combinations_are_independent_of_reserved_bits_and_header_size() =>
        Prop.ForAll((DoNotSize<ushort> bits, byte reserved, byte words) =>
        {
            int flags = bits.Item & 0x1FF;
            int offset = 5 + words % 11;
            var bytes = Convert.FromHexString(WithOptions(new string('0', 8 * (offset - 5))));
            BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(12),
                (ushort)((offset << 12) | ((reserved & 7) << 9) | flags));
            var header = Segment(Decode(false, Hex(bytes))).Header;
            return header.DataOffset == offset && header.Reserved == (reserved & 7) && header.Flags == (TcpFlags)flags;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(17)]
    [Arguments(58)]
    [Arguments(50)]
    [Arguments(59)]
    [Arguments(253)]
    public async Task Other_ipv4_protocols_never_dispatch_tcp(byte next)
    {
        var frame = Ethernet(Frame(false, V4, next: next));
        var ip = frame.Payload is IPv4DecodeResult result && result is DecodedIPv4 decoded
            ? decoded : throw new InvalidOperationException("Expected IPv4.");
        await Assert.That(ip.Payload is TcpParseResult).IsFalse();
    }

    [Test]
    [Arguments(17)]
    [Arguments(58)]
    [Arguments(50)]
    [Arguments(59)]
    [Arguments(253)]
    public async Task Other_ipv6_protocols_never_dispatch_tcp(byte next)
    {
        var frame = Ethernet(Frame(true, V6, next: next));
        var ip = frame.Payload is IPv6DecodeResult result && result is DecodedIPv6 decoded
            ? decoded : throw new InvalidOperationException("Expected IPv6.");
        await Assert.That(ip.Payload is TcpParseResult).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Ipv4_tcp_fragments_preserve_protocol_and_bytes(bool first) =>
        Prop.ForAll((DoNotSize<ushort> index, bool more, byte[] bytes) =>
        {
            ushort offset = first ? (ushort)0 : (ushort)(1 + index.Item % 0x1FFF);
            more |= first;
            var field = (ushort)(offset | (more ? 0x2000 : 0));
            var frame = Ethernet(Frame(false, Hex(bytes), fragment: field));
            return frame.Payload is IPv4DecodeResult ip && ip is DecodedIPv4 decoded
                && decoded.Payload is IPv4FragmentPayload fragment && fragment.Protocol == 6
                && fragment.Offset == offset && fragment.MoreFragments == more
                && fragment.DeclaredLength == bytes.Length && fragment.Bytes.Span.SequenceEqual(bytes);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public void Ipv6_non_atomic_tcp_fragments_preserve_protocol_and_bytes(bool first) =>
        Prop.ForAll((DoNotSize<ushort> index, bool more, byte[] bytes) =>
        {
            ushort offset = first ? (ushort)0 : (ushort)(1 + index.Item % 0x1FFF);
            more |= first;
            var field = (ushort)(offset << 3 | (more ? 1 : 0));
            var frame = Ethernet(Frame(true, "0600" + field.ToString("X4") + "01234567" + Hex(bytes), next: 44));
            return frame.Payload is IPv6DecodeResult ip && ip is DecodedIPv6 decoded
                && decoded.Payload is IPv6FragmentPayload fragment && fragment.Fragment.NextHeader == 6
                && fragment.Fragment.Offset == offset && fragment.Fragment.MoreFragments == more
                && fragment.DeclaredLength == bytes.Length && fragment.Bytes.Span.SequenceEqual(bytes);
        }).Check(Config.QuickThrowOnFailure);

    private static string WithOptions(string options)
    {
        var bytes = Convert.FromHexString(V4[..40] + options);
        bytes[12] = (byte)(bytes.Length / 4 << 4);
        return Hex(bytes);
    }

    private static TcpParseResult Decode(bool ipv6, string bytes, ushort? declared = null) => Tcp(Frame(ipv6, bytes, declared));

    private static TcpSegment Segment(TcpParseResult result) => result is TcpSegment tcp ? tcp : throw new InvalidOperationException($"Expected TCP segment, got {result.Value}.");

    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);

    private static DecodedEthernet Ethernet(ProtocolDecodeResult result) =>
        result is EthernetDecodeResult ethernet && ethernet is DecodedEthernet frame ? frame : throw new InvalidOperationException();

    private static TcpParseResult Tcp(ProtocolDecodeResult result) => Ethernet(result).Payload switch
    {
        IPv4DecodeResult ip when ip is DecodedIPv4 decoded && decoded.Payload is TcpParseResult tcp => tcp,
        IPv6DecodeResult ip when ip is DecodedIPv6 decoded && decoded.Payload is TcpParseResult tcp => tcp,
        _ => throw new InvalidOperationException("Expected TCP dispatch.")
    };

    private static ProtocolDecodeResult Frame(bool ipv6, string payload, ushort? declared = null, byte next = 6,
        ushort fragment = 0, string options = "")
    {
        var bytes = Convert.FromHexString(payload);
        var header = ipv6
            ? Convert.FromHexString("600000000000064020010DB800000000000000000000000120010DB8000000000000000000000002")
            : Convert.FromHexString("450000000000000040060000C0000201C6336402" + options);
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
}
