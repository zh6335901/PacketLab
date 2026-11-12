using System.Buffers.Binary;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Protocols.UnitTests.IPv6;

public class ParseIPv6ExtensionsTests
{
    [Test]
    [Arguments(6)]
    [Arguments(17)]
    [Arguments(58)]
    public async Task Direct_upper_layer_has_exact_range_and_pseudo_header(byte protocol)
    {
        var packet = Parse(protocol, "CAFE0102DEAD", 4);
        var upper = Upper(packet.Extensions);
        await Assert.That(upper.Protocol).IsEqualTo(protocol);
        await Assert.That(upper.Offset).IsEqualTo(40);
        await Assert.That(upper.DeclaredLength).IsEqualTo(4u);
        await Assert.That(Hex(upper.Bytes)).IsEqualTo("CAFE0102");
        await Assert.That(packet.Extensions.Headers.IsEmpty).IsTrue();
        await Assert.That(upper.ChecksumContext.Value).IsEqualTo(new IPv6ChecksumContext.KnownAddresses(
            new(0x20010db800000000, 1), new(0xff02000000000000, 2)));
        await Assert.That(Hex(Known(packet).TrailingBytes)).IsEqualTo("DEAD");
    }

    [Test]
    [Arguments(0, "11010000000000000000000000000000", 16)]
    [Arguments(60, "11010000000000000000000000000000", 16)]
    [Arguments(43, "1101FE00000000000000000000000000", 16)]
    [Arguments(51, "110400000102030405060708000000000000000000000000", 24)]
    [Arguments(44, "11FF000001020304", 8)]
    public async Task Header_specific_length_encoding_locates_transport(byte type, string extension, int length)
    {
        var packet = Parse(type, extension + "CAFE");
        var item = packet.Extensions.Headers.Single();
        await Assert.That(item.Type).IsEqualTo(type);
        await Assert.That(item.NextHeader).IsEqualTo((byte)17);
        await Assert.That(item.Offset).IsEqualTo(40);
        await Assert.That(item.Length).IsEqualTo(length);
        await Assert.That(Hex(item.Bytes)).IsEqualTo(extension);
        await Assert.That(Upper(packet.Extensions).Offset).IsEqualTo(40 + length);
        await Assert.That(Hex(Upper(packet.Extensions).Bytes)).IsEqualTo("CAFE");
        await Assert.That(Upper(packet.Extensions).DeclaredLength).IsEqualTo(2u);
        await Assert.That(HasKnownContext(packet.Extensions)).IsTrue();
    }

    [Test]
    public async Task Mixed_chain_retains_order_raw_slices_and_true_upper_length()
    {
        var packet = Parse(0, "3C00000000000000" + "2B010000000000000000000000000000"
            + "3300FE0000000000" + "2C0400000102030405060708000000000000000000000000"
            + "0600000001234567" + "CAFE0102");
        var chain = packet.Extensions;
        await Assert.That(string.Join(",", chain.Headers.Select(h => h.Type))).IsEqualTo("0,60,43,51,44");
        await Assert.That(string.Join(",", chain.Headers.Select(h => h.Offset))).IsEqualTo("40,48,64,72,96");
        await Assert.That(Upper(chain).Offset).IsEqualTo(104);
        await Assert.That(Upper(chain).Protocol).IsEqualTo((byte)6);
        await Assert.That(Upper(chain).DeclaredLength).IsEqualTo(4u);
        await Assert.That(Hex(Upper(chain).Bytes)).IsEqualTo("CAFE0102");
        await Assert.That(HasKnownContext(chain)).IsTrue();
        await Assert.That(chain.Diagnostics.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments(0, false)]
    [Arguments(1, false)]
    [Arguments(0, true)]
    [Arguments(8191, true)]
    public async Task Fragment_fields_distinguish_atomic_first_and_later_fragments(ushort offset, bool more)
    {
        var fragment = new byte[10];
        fragment[0] = 60;
        BinaryPrimitives.WriteUInt16BigEndian(fragment.AsSpan(2), (ushort)((offset << 3) | (more ? 1 : 0)));
        BinaryPrimitives.WriteUInt32BigEndian(fragment.AsSpan(4), 0x89abcdef);
        fragment[8] = 0xde; fragment[9] = 0xad;
        var packet = Parse(44, Convert.ToHexString(fragment));
        var actual = packet.Extensions.Headers[0].Fragment!;
        await Assert.That(actual).IsEqualTo(new IPv6Fragment(offset, more, 0x89abcdef, 60));
        await Assert.That(actual.OffsetBytes).IsEqualTo(offset * 8);
        await Assert.That(actual.IsAtomic).IsEqualTo(offset == 0 && !more);
        await Assert.That(actual.IsAtomic
            ? packet.Extensions.Result is IPv6PayloadUnavailable { Reason: IPv6PayloadFailure.Invalid }
            : packet.Extensions.Result is IPv6FragmentPayload { DeclaredLength: 2 } result && result.Fragment == actual).IsTrue();
        await Assert.That(packet.Extensions.RemainingOffset).IsEqualTo(48);
        await Assert.That(Hex(packet.Extensions.RemainingBytes)).IsEqualTo("DEAD");
    }

    [Test]
    [Arguments(0, true)]
    [Arguments(1, false)]
    public async Task Routing_segments_control_final_destination_reliability(byte segments, bool available)
    {
        var chain = Parse(43, "1100FE" + segments.ToString("X2") + "00000000CAFE").Extensions;
        await Assert.That(Upper(chain).Protocol).IsEqualTo((byte)17);
        await Assert.That(available
            ? Upper(chain).ChecksumContext is IPv6ChecksumContext.KnownAddresses
            : Upper(chain).ChecksumContext is IPv6ChecksumContext.Unavailable).IsTrue();
        await Assert.That(chain.Diagnostics.Any(d => d.Code == IPv6DiagnosticCode.FinalDestinationUnavailable)).IsEqualTo(!available);
    }

    [Test]
    [Arguments(50, IPv6DiagnosticCode.EncryptedEsp)]
    [Arguments(253, IPv6DiagnosticCode.UnsupportedNextHeader)]
    [Arguments(135, IPv6DiagnosticCode.UnsupportedNextHeader)]
    public async Task Unsupported_chain_preserves_prefix_and_remainder(byte type, IPv6DiagnosticCode code)
    {
        var chain = Parse(60, type.ToString("X2") + "00000000000000CAFE").Extensions;
        await Assert.That(chain.Result is IPv6PayloadUnavailable { Reason: IPv6PayloadFailure.Unsupported }).IsTrue();
        await Assert.That(chain.Headers.Length).IsEqualTo(1);
        await Assert.That(chain.Diagnostics.Single().Code).IsEqualTo(code);
        await Assert.That(chain.Diagnostics.Single().Offset).IsEqualTo(48);
        await Assert.That(chain.RemainingOffset).IsEqualTo(48);
        await Assert.That(Hex(chain.RemainingBytes)).IsEqualTo("CAFE");
    }

    [Test]
    public async Task No_next_header_ignores_but_preserves_remaining_payload()
    {
        var chain = Parse(60, "3B00000000000000CAFE").Extensions;
        await Assert.That(chain.Result is IPv6NoNextHeader).IsTrue();
        await Assert.That(Hex(chain.RemainingBytes)).IsEqualTo("CAFE");
    }

    [Test]
    [Arguments(60, "1101", 16, IPv6DiagnosticCode.HeaderTruncated)]
    [Arguments(60, "11", 16, IPv6DiagnosticCode.HeaderTruncated)]
    [Arguments(60, "11010000000000000000000000000000", 8, IPv6DiagnosticCode.HeaderExceedsPayload)]
    [Arguments(44, "11000000000000", 8, IPv6DiagnosticCode.HeaderTruncated)]
    [Arguments(51, "1104", 24, IPv6DiagnosticCode.HeaderTruncated)]
    [Arguments(51, "1100", 8, IPv6DiagnosticCode.InvalidHeaderLength)]
    [Arguments(51, "1101", 12, IPv6DiagnosticCode.InvalidHeaderLength)]
    [Arguments(60, "1100010500000000", 8, IPv6DiagnosticCode.InvalidOptions)]
    public async Task Invalid_and_short_headers_report_precise_failure_without_transport(byte type, string bytes, ushort declared, IPv6DiagnosticCode code)
    {
        var packet = Parse(type, bytes, declared);
        await Assert.That(packet.Extensions.Diagnostics[0].Code).IsEqualTo(code);
        await Assert.That(packet.Extensions.Diagnostics[0].Offset).IsEqualTo(code == IPv6DiagnosticCode.InvalidOptions ? 42 : 40);
        await Assert.That(packet.Extensions.Result is IPv6PayloadUnavailable failure && failure.Reason ==
            (code == IPv6DiagnosticCode.HeaderTruncated ? IPv6PayloadFailure.Truncated : IPv6PayloadFailure.Invalid)).IsTrue();
        await Assert.That(Known(packet).Bytes.Length).IsEqualTo(Math.Min(declared, bytes.Length / 2));
    }

    [Test]
    public async Task Incomplete_upper_payload_retains_pseudo_header_context_and_capture_diagnostic()
    {
        var packet = Parse(60, "1100000000000000CAFE", 12);
        await Assert.That(Upper(packet.Extensions).DeclaredLength).IsEqualTo(4u);
        await Assert.That(Upper(packet.Extensions).IsComplete).IsFalse();
        await Assert.That(Hex(Upper(packet.Extensions).Bytes)).IsEqualTo("CAFE");
        await Assert.That(HasKnownContext(packet.Extensions)).IsTrue();
        await Assert.That(packet.Extensions.Diagnostics.Single().Code).IsEqualTo(IPv6DiagnosticCode.PayloadTruncated);
    }

    [Test]
    [Arguments("1100C20400010000", 65536u)]
    [Arguments("1100C204FFFFFFFF", uint.MaxValue)]
    public async Task Jumbo_length_uses_unsigned_wire_value_even_when_capture_is_short(string bytes, uint expected)
    {
        var packet = Parse(0, bytes, 0);
        await Assert.That(Known(packet).DeclaredLength).IsEqualTo(expected);
        await Assert.That(Known(packet).DeclaredDatagramLength).IsEqualTo(40UL + expected);
        await Assert.That(Known(packet).IsDatagramComplete).IsFalse();
        await Assert.That(Upper(packet.Extensions).DeclaredLength).IsEqualTo(expected - 8);
        await Assert.That(Upper(packet.Extensions).Offset).IsEqualTo(48);
        await Assert.That(HasKnownContext(packet.Extensions)).IsTrue();
        await Assert.That(packet.Extensions.Diagnostics.Single().Code).IsEqualTo(IPv6DiagnosticCode.PayloadTruncated);
    }

    [Test]
    public async Task Complete_jumbo_excludes_trailing_capture_and_supplies_upper_length()
    {
        var bytes = new byte[65539];
        Convert.FromHexString("1100C20400010000").CopyTo(bytes, 0);
        bytes[65535] = 0xab; bytes[65536] = 0xcd;
        var packet = Parse(0, Convert.ToHexString(bytes), 0);
        await Assert.That(Known(packet).IsDatagramComplete).IsTrue();
        await Assert.That(Known(packet).TrailingBytes.Length).IsEqualTo(3);
        await Assert.That(Known(packet).TrailingBytes.Span[0]).IsEqualTo((byte)0xcd);
        await Assert.That(Upper(packet.Extensions).Bytes.Length).IsEqualTo(65528);
        await Assert.That(Upper(packet.Extensions).Bytes.Span[^1]).IsEqualTo((byte)0xab);
        await Assert.That(Upper(packet.Extensions).DeclaredLength).IsEqualTo(65528u);
        await Assert.That(packet.Extensions.Diagnostics.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments("1100000000000000", IPv6DiagnosticCode.MissingJumboPayload)]
    [Arguments("1100C2040000FFFF", IPv6DiagnosticCode.InvalidJumboPayload)]
    [Arguments("1100C20301000000", IPv6DiagnosticCode.InvalidJumboPayload)]
    [Arguments("110100C2040001000000000000000000", IPv6DiagnosticCode.InvalidJumboPayload)]
    [Arguments("1101C204000100000000C20400020000", IPv6DiagnosticCode.InvalidJumboPayload)]
    [Arguments("1100C20500010000", IPv6DiagnosticCode.InvalidOptions)]
    [Arguments("1100C2040001", IPv6DiagnosticCode.HeaderTruncated)]
    [Arguments("", IPv6DiagnosticCode.HeaderTruncated)]
    public async Task Invalid_jumbo_never_infers_length_from_capture(string bytes, IPv6DiagnosticCode code)
    {
        var packet = Parse(0, bytes, 0);
        var payload = packet.Payload is IPv6Payload.UndeterminedLength unknown ? unknown
            : throw new InvalidOperationException("Expected unknown length.");
        await Assert.That(Hex(payload.CapturedBytes)).IsEqualTo(bytes);
        await Assert.That(packet.Extensions.Diagnostics[0].Code).IsEqualTo(code);
        await Assert.That(packet.Extensions.Result is IPv6PayloadUnavailable failure && failure.Reason ==
            (code == IPv6DiagnosticCode.HeaderTruncated ? IPv6PayloadFailure.Truncated : IPv6PayloadFailure.Invalid)).IsTrue();
    }

    [Test]
    [Arguments(0)]
    [Arguments(60)]
    public async Task Jumbo_option_with_nonzero_fixed_length_is_invalid(byte type)
    {
        var packet = Parse(type, "1100C20400010000");
        await Assert.That(Known(packet).DeclaredLength).IsEqualTo(8u);
        await Assert.That(packet.Extensions.Diagnostics.Single().Code).IsEqualTo(IPv6DiagnosticCode.InvalidJumboPayload);
        await Assert.That(packet.Extensions.Result is IPv6PayloadUnavailable { Reason: IPv6PayloadFailure.Invalid }).IsTrue();
    }

    [Test]
    [Arguments(0, "2C00C204000100001100000001020304", 0, IPv6DiagnosticCode.JumboFragment)]
    [Arguments(44, "2C000000010203041100000005060708", 16, IPv6DiagnosticCode.DuplicateFragment)]
    [Arguments(60, "00000000000000001100000000000000", 16, IPv6DiagnosticCode.InvalidHopByHopPosition)]
    public async Task Illegal_header_combinations_retain_headers_but_disable_upper_layer(byte type, string bytes, ushort length, IPv6DiagnosticCode code)
    {
        var chain = Parse(type, bytes, length).Extensions;
        await Assert.That(chain.Headers.Length).IsEqualTo(2);
        await Assert.That(chain.Diagnostics[0].Code).IsEqualTo(code);
        await Assert.That(chain.Result is IPv6PayloadUnavailable { Reason: IPv6PayloadFailure.Invalid }).IsTrue();
    }

    [Test]
    public async Task Home_address_option_does_not_supply_potentially_wrong_source_to_checksum()
    {
        var chain = Parse(60, "1102C91020010DB800000000000000000000000900000000CAFE").Extensions;
        await Assert.That(Upper(chain).Offset).IsEqualTo(64);
        await Assert.That(Upper(chain).ChecksumContext is IPv6ChecksumContext.Unavailable).IsTrue();
        await Assert.That(chain.Diagnostics.Single().Code).IsEqualTo(IPv6DiagnosticCode.SourceAddressUnavailable);
    }

#pragma warning disable PL0003 // Every capture prefix checks the same extension-chain bounds contract.
    [Test]
    public async Task Every_capture_prefix_is_bounded_and_never_throws()
    {
        var source = Convert.FromHexString("3C000000000000002B000000000000003300FE00000000002C04000001020304050607080000000000000000000000000600000001234567CAFE0102");
        for (var captured = 0; captured <= source.Length; captured++)
        {
            var packet = Parse(0, Convert.ToHexString(source.AsSpan(0, captured)), (ushort)source.Length);
            await Assert.That(packet.Extensions.RemainingOffset + packet.Extensions.RemainingBytes.Length).IsEqualTo(40 + captured);
            await Assert.That(packet.Extensions.Headers.All(h => h.Offset + h.Length <= 40 + captured)).IsTrue();
        }
    }
#pragma warning restore PL0003

    private static IPv6Packet Parse(byte next, string payload, ushort? length = null)
    {
        var bytes = Convert.FromHexString("60000000" + (length ?? (ushort)(payload.Length / 2)).ToString("X4")
            + next.ToString("X2") + "40" + "20010DB8000000000000000000000001FF020000000000000000000000000002" + payload);
        return IPv6Parser.Parse(bytes) is IPv6Packet packet ? packet : throw new InvalidOperationException("Expected IPv6.");
    }

    private static IPv6UpperLayer Upper(IPv6ExtensionChain chain) => chain.Result is IPv6UpperLayer upper
        ? upper : throw new InvalidOperationException("Expected a located upper layer.");
    private static bool HasKnownContext(IPv6ExtensionChain chain) => chain.Result is IPv6UpperLayer upper &&
        upper.ChecksumContext is IPv6ChecksumContext.KnownAddresses;

    private static string Hex(ReadOnlyMemory<byte> bytes) => Convert.ToHexString(bytes.Span);
    private static IPv6Payload.KnownLength Known(IPv6Packet packet) => packet.Payload is IPv6Payload.KnownLength known
        ? known : throw new InvalidOperationException("Expected known length.");
}
