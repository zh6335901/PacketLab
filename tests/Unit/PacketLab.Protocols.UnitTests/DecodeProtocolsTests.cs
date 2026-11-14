using FsCheck;
using FsCheck.Fluent;
using PacketLab.Protocols.IP;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.UnitTests;

public class DecodeProtocolsTests
{

    [Test]
    public async Task Incomplete_ethernet_and_unsupported_link_layer_do_not_dispatch_payload()
    {
        var frame = Convert.FromHexString("FFFFFFFFFFFF02000000000186DD");
        var shortHeader = ProtocolDecoder.Decode(frame.AsMemory(0, 13), LinkLayerProtocol.Ethernet);
        await Assert.That(shortHeader is EthernetDecodeResult ethernet && ethernet is EthernetParseResult.IncompleteHeader).IsTrue();
        var unsupported = ProtocolDecoder.Decode(frame, LinkLayerProtocol.Unsupported);
        await Assert.That(unsupported is ProtocolDecodeResult.UnsupportedLinkLayer).IsTrue();
    }



    [Test]
    public async Task Ipv4_dispatch_preserves_each_layer_and_places_udp_failure_inside_ip_payload()
    {
        const string bytes = "450000141234400040113C6EC0000201C6336402";
        var frame = Decode("0800", bytes) is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        await Assert.That(frame.Frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(Convert.ToHexString(frame.Frame.RemainingBytes.Span)).IsEqualTo(bytes);
        var ip = frame.Payload is IPv4DecodeResult result && result is DecodedIPv4 decoded ? decoded : throw new InvalidOperationException();
        await Assert.That(ip.Packet.Header.Source.ToString()).IsEqualTo("192.0.2.1");
        await Assert.That(ip.Payload is UdpParseResult udp && udp is UdpParseResult.IpLengthTooShort).IsTrue();
    }

    [Test]
    public async Task Ipv4_header_failure_keeps_ethernet_without_constructing_decoded_ip()
    {
        var frame = Decode("0800", "AABB") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        await Assert.That(frame.Payload is IPv4DecodeResult ip && ip is IPv4ParseResult.IncompleteHeader { CapturedLength: 2 }).IsTrue();
        await Assert.That(frame.Frame.EtherType).IsEqualTo((ushort)0x0800);
    }

    [Test]
    public async Task Ipv6_header_failure_keeps_ethernet_without_constructing_decoded_ip()
    {
        var frame = Decode("86DD", "AABB") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        await Assert.That(frame.Payload is IPv6DecodeResult ip && ip is IPv6ParseResult.IncompleteHeader { CapturedLength: 2 }).IsTrue();
        await Assert.That(frame.Frame.EtherType).IsEqualTo((ushort)0x86DD);
    }

    [Test]
    public async Task Complete_arp_dispatch_preserves_outer_frame_and_packet()
    {
        const string payload = "0001080006040001020000000001C0000201000000000000C0000202";
        var frame = Decode("0806", payload) is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        await Assert.That(frame.Frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(Convert.ToHexString(frame.Frame.RemainingBytes.Span)).IsEqualTo(payload);
        var arp = frame.Payload is ArpParseResult result ? result : throw new InvalidOperationException();
        await Assert.That(arp is ArpPacket).IsTrue();
    }

    [Test]
    public async Task Truncated_arp_dispatch_preserves_outer_frame_and_diagnostic()
    {
        const string payload = "AABB";
        var frame = Decode("0806", payload) is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        await Assert.That(frame.Frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(Convert.ToHexString(frame.Frame.RemainingBytes.Span)).IsEqualTo(payload);
        var arp = frame.Payload is ArpParseResult result ? result : throw new InvalidOperationException();
        await Assert.That(arp is ArpParseResult.IncompleteHeader { RequiredLength: 8, CapturedLength: 2 }).IsTrue();
    }

    [Test]
    [Arguments("450000141234400040113C6EC0000201C6336402")]
    [Arguments("0001080006040001020000000001C0000201000000000000C0000202")]
    [Arguments("6000000000003B4020010DB8000000000000000000000001FF020000000000000000000000000002")]
    public async Task Recognizable_payloads_follow_the_outer_field(string bait) =>
        await Assert.That(MatchesRepresentativeFields(bait)).IsTrue();

    [Test]
    public void Outer_field_selects_decoder_regardless_of_payload() =>
        Prop.ForAll((DoNotSize<ushort> field, byte[] payload) =>
        {
            var bytes = Convert.ToHexString(payload);
            return MatchesRepresentativeFields(bytes) && DispatchMatches(field.Item, bytes);
        }).Check(Config.QuickThrowOnFailure);

    private static bool MatchesRepresentativeFields(string bytes) =>
        DispatchMatches(0x0800, bytes) && DispatchMatches(0x0806, bytes) && DispatchMatches(0x86DD, bytes)
        && DispatchMatches(1500, bytes) && DispatchMatches(1501, bytes) && DispatchMatches(1536, bytes)
        && DispatchMatches(0x8100, bytes) && DispatchMatches(0x88B5, bytes);

    private static bool DispatchMatches(ushort field, string bytes)
    {
        var result = Decode(field.ToString("X4"), bytes);
        return field switch
        {
            <= 1500 => result is EthernetParseResult.Ieee8023Length length && length.Length == field,
            <= 1535 => result is EthernetParseResult.InvalidLengthOrType invalid && invalid.Value == field,
            0x0800 => result is DecodedEthernet v4 && v4.Payload is IPv4DecodeResult,
            0x0806 => result is DecodedEthernet arp && arp.Payload is ArpParseResult,
            0x86dd => result is DecodedEthernet v6 && v6.Payload is IPv6DecodeResult,
            _ => result is DecodedEthernet frame && frame.Payload is UnsupportedEtherType other
                && other.EtherType == field && Convert.ToHexString(other.Bytes.Span) == bytes
        };
    }

    [Test]
    [Arguments("450000141234400040013C7EC0000201C6336402", 1)]
    [Arguments("450000141234400040FD3B82C0000201C6336402", 253)]
    public async Task Unsupported_ipv4_has_an_explicit_protocol_branch(string bytes, byte protocol)
    {
        var ip = DecodedIPv4.Decode(Convert.FromHexString(bytes)) is DecodedIPv4 decoded ? decoded : throw new InvalidOperationException();
        await Assert.That(ip.Payload is UnsupportedIpProtocol { DeclaredLength: 0 } other && other.Protocol == protocol).IsTrue();
    }

    [Test]
    [Arguments("2001", 6, 1, true)]
    [Arguments("1FFF", 6, 0x1FFF, false)]
    [Arguments("1FFF", 17, 0x1FFF, false)]
    public async Task Ipv4_fragments_preserve_metadata_and_bytes_before_reassembly(
        string fragmentField, byte protocol, ushort offset, bool moreFragments)
    {
        var packet = Convert.FromHexString($"450000161234{fragmentField}40{protocol:X2}0000C0000201C6336402CAFE");
        var ip = DecodedIPv4.Decode(packet) is DecodedIPv4 decoded
            ? decoded : throw new InvalidOperationException();
        var fragment = ip.Payload is IPv4FragmentPayload value ? value : throw new InvalidOperationException();
        await Assert.That(fragment.Protocol).IsEqualTo(protocol);
        await Assert.That(fragment.Offset).IsEqualTo(offset);
        await Assert.That(fragment.MoreFragments).IsEqualTo(moreFragments);
        await Assert.That(fragment.Identification).IsEqualTo((ushort)0x1234);
        await Assert.That(fragment.DeclaredLength).IsEqualTo(2u);
        await Assert.That(Convert.ToHexString(fragment.Bytes.Span)).IsEqualTo("CAFE");
    }

    [Test]
    public async Task Ipv4_invalid_version_stays_in_the_header_error_branch()
    {
        var frame = Decode("0800", "350000140000000040110000C0000201C6336402") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        var ip = frame.Payload is IPv4DecodeResult result ? result : throw new InvalidOperationException();
        await Assert.That(ip is IPv4ParseResult.InvalidVersion { Version: 3 }).IsTrue();
    }

    [Test]
    public async Task Ipv4_invalid_ihl_stays_in_the_header_error_branch()
    {
        var frame = Decode("0800", "440000140000000040110000C0000201C6336402") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        var ip = frame.Payload is IPv4DecodeResult result ? result : throw new InvalidOperationException();
        await Assert.That(ip is IPv4ParseResult.InvalidHeaderLength { Ihl: 4 }).IsTrue();
    }

    [Test]
    public async Task Ipv4_invalid_total_length_stays_in_the_header_error_branch()
    {
        var frame = Decode("0800", "450000130000000040110000C0000201C6336402") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        var ip = frame.Payload is IPv4DecodeResult result ? result : throw new InvalidOperationException();
        await Assert.That(ip is IPv4ParseResult.InvalidTotalLength { TotalLength: 19, HeaderLength: 20 }).IsTrue();
    }

    [Test]
    public async Task Ipv4_truncated_options_stay_in_the_header_error_branch()
    {
        var frame = Decode("0800", "460000180000000040110000C0000201C6336402") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        var ip = frame.Payload is IPv4DecodeResult result ? result : throw new InvalidOperationException();
        await Assert.That(ip is IPv4ParseResult.IncompleteHeader { RequiredLength: 24, CapturedLength: 20 }).IsTrue();
    }

    [Test]
    public async Task Ipv6_invalid_version_stays_in_the_header_error_branch()
    {
        var bytes = new byte[40];
        bytes[0] = 0x40;
        var result = DecodedIPv6.Decode(bytes);
        await Assert.That(result is IPv6ParseResult.InvalidVersion { Version: 4 }).IsTrue();
    }

    private static EthernetDecodeResult Decode(string type, string payload) =>
        DecodedEthernet.Decode(Convert.FromHexString("FFFFFFFFFFFF020000000001" + type + payload));
}
