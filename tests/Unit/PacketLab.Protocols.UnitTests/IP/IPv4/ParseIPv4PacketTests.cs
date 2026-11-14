using FsCheck;
using FsCheck.Fluent;
using System.Buffers.Binary;
using PacketLab.Protocols.IP.IPv4;

namespace PacketLab.Protocols.UnitTests.IP.IPv4;

public class ParseIPv4PacketTests
{
    private const string Datagram = "45AB0018BEEF21237FFD6DF4C0000201C6336402CAFE0102";
    private const string WithOptions = "46AB001CBEEFA1237FFDEBEEC0000201C633640201010000CAFE0102";

    [Test]
    public async Task Header_fields_preserve_network_order_bit_fields_and_unknown_protocol()
    {
        var packet = Parse(Datagram);
        var header = packet.Header;
        await Assert.That(header.Version).IsEqualTo((byte)4);
        await Assert.That(header.Ihl).IsEqualTo((byte)5);
        await Assert.That(header.HeaderLength).IsEqualTo(20);
        await Assert.That(header.Dscp).IsEqualTo((byte)42);
        await Assert.That(header.Ecn).IsEqualTo((byte)3);
        await Assert.That(header.TotalLength).IsEqualTo((ushort)24);
        await Assert.That(header.Identification).IsEqualTo((ushort)0xbeef);
        await Assert.That(header.Flags).IsEqualTo((byte)1);
        await Assert.That(header.ReservedFlag).IsFalse();
        await Assert.That(header.DontFragment).IsFalse();
        await Assert.That(header.MoreFragments).IsTrue();
        await Assert.That(header.FragmentOffset).IsEqualTo((ushort)0x123);
        await Assert.That(header.FragmentOffsetBytes).IsEqualTo(2328);
        await Assert.That(header.Ttl).IsEqualTo((byte)127);
        await Assert.That(header.Protocol).IsEqualTo((byte)253);
        await Assert.That(header.HeaderChecksum).IsEqualTo((ushort)0x6df4);
        await Assert.That(header.Source.ToString()).IsEqualTo("192.0.2.1");
        await Assert.That(header.Destination.ToString()).IsEqualTo("198.51.100.2");
        await Assert.That(header.Options.IsEmpty).IsTrue();
        await Assert.That(packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
        await Assert.That(Convert.ToHexString(packet.Payload.Span)).IsEqualTo("CAFE0102");
    }

    [Test]
    public async Task Options_and_padding_are_preserved_and_payload_starts_after_them()
    {
        var packet = Parse(WithOptions);
        await Assert.That(packet.Header.ReservedFlag).IsTrue();
        await Assert.That(packet.Header.Ihl).IsEqualTo((byte)6);
        await Assert.That(packet.Header.HeaderLength).IsEqualTo(24);
        await Assert.That(Convert.ToHexString(packet.Header.Options.Span)).IsEqualTo("01010000");
        await Assert.That(Convert.ToHexString(packet.Payload.Span)).IsEqualTo("CAFE0102");
        await Assert.That(packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
    }

    [Test]
    public async Task Fragment_offset_preserves_the_high_bit_of_its_13_bit_value()
    {
        var packet = Parse("45AB0018BEEF31237FFD5DF4C0000201C6336402CAFE0102");
        await Assert.That(packet.Header.FragmentOffset).IsEqualTo((ushort)0x1123);
        await Assert.That(packet.Header.FragmentOffsetBytes).IsEqualTo(35096);
    }

    [Test]
    public async Task Maximum_header_accepts_all_option_bytes_and_empty_payload()
    {
        const string options = "0102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F202122232425262728";
        var packet = Parse("4F00003C123440004011A0A0C0000201C6336402" + options);
        await Assert.That(packet.Header.HeaderLength).IsEqualTo(60);
        await Assert.That(Convert.ToHexString(packet.Header.Options.Span)).IsEqualTo(options);
        await Assert.That(packet.Payload.IsEmpty).IsTrue();
        await Assert.That(packet.IsDatagramComplete).IsTrue();
        await Assert.That(packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
        await Assert.That(packet.Header.DontFragment).IsTrue();
        await Assert.That(packet.Header.MoreFragments).IsFalse();
        await Assert.That(packet.Header.ReservedFlag).IsFalse();
    }

    public static IEnumerable<int> ShortLengths() => Enumerable.Range(0, 24);

    [Test]
    [MethodDataSource(nameof(ShortLengths))]
    public async Task Incomplete_headers_report_required_and_captured_lengths_without_checksum_verdict(int length)
    {
        var bytes = Convert.FromHexString(WithOptions)[..length];
        var result = IPv4Parser.Parse(bytes);
        var incomplete = result is IPv4ParseResult.IncompleteHeader parsed ? parsed
            : throw new InvalidOperationException("Expected an incomplete header.");
        await Assert.That(incomplete.RequiredLength).IsEqualTo(length < 20 ? 20 : 24);
        await Assert.That(incomplete.CapturedLength).IsEqualTo(length);
        await Assert.That(incomplete.RemainingBytes.Span.SequenceEqual(bytes)).IsTrue();
        await Assert.That(result.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Unavailable);
    }

    [Test]
    [Arguments("65AB0018BEEFA1237FFDEDF3C0000201C6336402", "version")]
    [Arguments("35AB0018BEEFA1237FFDEDF3C0000201C6336402", "version-below")]
    [Arguments("44AB0018BEEFA1237FFDEDF3C0000201C6336402", "ihl")]
    [Arguments("45AB0013BEEFA1237FFDEDF3C0000201C6336402", "total")]
    [Arguments("46AB0014BEEFA1237FFDEDF3C0000201C6336402", "options-total")]
    public async Task Invalid_declarations_are_distinct_from_capture_truncation(string hex, string kind)
    {
        var bytes = Convert.FromHexString(hex);
        var result = IPv4Parser.Parse(bytes);
        ReadOnlyMemory<byte> retained = (kind, result.Value) switch
        {
            ("version", IPv4ParseResult.InvalidVersion { Version: 6 } invalid) => invalid.RemainingBytes,
            ("version-below", IPv4ParseResult.InvalidVersion { Version: 3 } invalid) => invalid.RemainingBytes,
            ("ihl", IPv4ParseResult.InvalidHeaderLength { Ihl: 4 } invalid) => invalid.RemainingBytes,
            ("total", IPv4ParseResult.InvalidTotalLength { TotalLength: 19, HeaderLength: 20 } invalid) => invalid.RemainingBytes,
            ("options-total", IPv4ParseResult.InvalidTotalLength { TotalLength: 20, HeaderLength: 24 } invalid) => invalid.RemainingBytes,
            _ => throw new InvalidOperationException("Expected a specific invalid declaration.")
        };
        await Assert.That(retained.Span.SequenceEqual(bytes)).IsTrue();
        await Assert.That(result.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Unavailable);
    }

    [Test]
    public void Total_length_bounds_payload_and_keeps_trailing_bytes_separate() =>
        Prop.ForAll((byte[] options, byte[] payload, (byte[] Tail, DoNotSize<ushort> Cut) capture) =>
        {
            var header = ValidHeader(options, payload.Length);
            int cut = capture.Cut.Item % (payload.Length + 1);
            return HasSlices(header, payload.Length, payload[..cut], [])
                && HasSlices(header, payload.Length, payload, [])
                && HasSlices(header, payload.Length, payload, capture.Tail);
        }).Check(Config.QuickThrowOnFailure);

    private static bool HasSlices(byte[] header, int declared, byte[] captured, byte[] tail)
    {
        byte[] wire = [.. header, .. captured, .. tail];
        return IPv4Parser.Parse(wire) is IPv4Packet packet && packet.CapturedLength == wire.Length
            && packet.Header.TotalLength == header.Length + declared
            && packet.IsDatagramComplete == (captured.Length == declared)
            && packet.Payload.Span.SequenceEqual(captured) && packet.TrailingBytes.Span.SequenceEqual(tail)
            && packet.ChecksumStatus == IPv4ChecksumStatus.Match;
    }

    [Test]
    public void Truncating_any_header_preserves_the_captured_prefix() =>
        Prop.ForAll((byte[] options, DoNotSize<ushort> selector) =>
        {
            var header = ValidHeader(options, 0);
            int captured = selector.Item % header.Length;
            return IPv4Parser.Parse(header.AsMemory(0, captured)) is IPv4ParseResult.IncompleteHeader error
                && error.RequiredLength == (captured < 20 ? 20 : header.Length)
                && error.CapturedLength == captured && error.RemainingBytes.Span.SequenceEqual(header.AsSpan(0, captured))
                && ((IPv4ParseResult)error).ChecksumStatus == IPv4ChecksumStatus.Unavailable;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task Header_only_datagram_keeps_all_extra_bytes_out_of_payload()
    {
        var packet = Parse("450000141234400040113C6EC0000201C6336402AABB");
        await Assert.That(packet.Payload.IsEmpty).IsTrue();
        await Assert.That(Convert.ToHexString(packet.TrailingBytes.Span)).IsEqualTo("AABB");
        await Assert.That(packet.IsDatagramComplete).IsTrue();
        await Assert.That(packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
    }

    [Test]
    public void Checksum_covers_header_options_and_padding_but_not_payload_or_trailing_bytes() =>
        Prop.ForAll((byte[] options, DoNotSize<ushort> position, byte bit) =>
        {
            var header = ValidHeader(options, 1);
            byte[] wire = [.. header, 0xca, 0xfe];
            int offset = 4 + position.Item % (header.Length - 4);
            wire[offset] ^= (byte)(1 << (bit % 8));
            var changed = IPv4Parser.Parse(wire);
            wire[offset] ^= (byte)(1 << (bit % 8));
            wire[header.Length] ^= 1;
            var changedPayload = IPv4Parser.Parse(wire);
            wire[header.Length] ^= 1;
            wire[^1] ^= 0x80;
            return changed.ChecksumStatus == IPv4ChecksumStatus.Mismatch && changedPayload.ChecksumStatus == IPv4ChecksumStatus.Match
                && IPv4Parser.Parse(wire) is IPv4Packet { Header.Source: { Octet0: 192, Octet3: 1 },
                    ChecksumStatus: IPv4ChecksumStatus.Match };
        }).Check(Config.QuickThrowOnFailure);

    private static byte[] ValidHeader(byte[] options, int payloadLength)
    {
        int length = 20 + Math.Min(10, options.Length / 4) * 4;
        byte[] header = [.. Convert.FromHexString(Datagram)[..20], .. options[..(length - 20)]];
        header[0] = (byte)(0x40 | length / 4);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(2), (ushort)(length + payloadLength));
        header[10] = header[11] = 0;
        int sum = Enumerable.Range(0, length / 2).Sum(i => BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(2 * i)));
        while (sum > ushort.MaxValue) sum = (sum & ushort.MaxValue) + (sum >> 16);
        BinaryPrimitives.WriteUInt16BigEndian(header.AsSpan(10), (ushort)~sum);
        return header;
    }

    [Test]
    public async Task Maximum_declared_length_does_not_require_captured_payload()
    {
        var packet = Parse("4500FFFF1234400040113C82C0000201C6336402");
        await Assert.That(packet.Header.TotalLength).IsEqualTo(ushort.MaxValue);
        await Assert.That(packet.CapturedLength).IsEqualTo(20);
        await Assert.That(packet.IsDatagramComplete).IsFalse();
        await Assert.That(packet.Payload.IsEmpty).IsTrue();
        await Assert.That(packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
    }

    private static IPv4Packet Parse(string hex) => IPv4Parser.Parse(Convert.FromHexString(hex)) is IPv4Packet packet
        ? packet : throw new InvalidOperationException("Expected an IPv4 packet.");
}
