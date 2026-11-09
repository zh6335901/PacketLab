using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.UnitTests;

public class DecodeProtocolsTests
{
    [Test]
    [Arguments("0800")]
    [Arguments("0806")]
    [Arguments("8100")]
    [Arguments("05DC")]
    [Arguments("05DD")]
    [Arguments("88B5")]
    public async Task Other_outer_types_do_not_dispatch_ipv6(string type)
    {
        var result = Decode(type, "6000000000003B4020010DB8000000000000000000000001FF020000000000000000000000000002");
        await Assert.That(result is DecodedEthernet frame && frame.Payload is IPv6DecodeResult).IsFalse();
    }

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
    [Arguments("0800")]
    [Arguments("86DD")]
    [Arguments("8100")]
    [Arguments("05DC")]
    [Arguments("05DD")]
    public async Task Other_outer_types_do_not_dispatch_arp(string type)
    {
        var result = Decode(type, "0001080006040001020000000001C0000201000000000000C0000202");
        await Assert.That(result is DecodedEthernet frame && frame.Payload is ArpParseResult).IsFalse();
    }

    [Test]
    [Arguments("0806")]
    [Arguments("86DD")]
    [Arguments("8100")]
    [Arguments("05DC")]
    [Arguments("05DD")]
    public async Task Other_outer_types_do_not_dispatch_ipv4(string type)
    {
        var result = Decode(type, "450000141234400040113C6EC0000201C6336402");
        await Assert.That(result is DecodedEthernet frame && frame.Payload is IPv4DecodeResult).IsFalse();
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
    [Arguments("0800")]
    [Arguments("86DD")]
    public async Task Ip_header_failure_keeps_ethernet_without_constructing_decoded_ip(string type)
    {
        var frame = Decode(type, "AABB") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        var isIncomplete = frame.Payload switch
        {
            IPv4DecodeResult ip => ip is IPv4ParseResult.IncompleteHeader { CapturedLength: 2 },
            IPv6DecodeResult ip => ip is IPv6ParseResult.IncompleteHeader { CapturedLength: 2 },
            _ => false
        };
        await Assert.That(isIncomplete).IsTrue();
        await Assert.That(frame.Frame.EtherType).IsEqualTo(Convert.ToUInt16(type, 16));
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task Arp_dispatch_preserves_outer_frame_and_inner_result(bool complete)
    {
        var payload = complete ? "0001080006040001020000000001C0000201000000000000C0000202" : "AABB";
        var frame = Decode("0806", payload) is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        await Assert.That(frame.Frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(Convert.ToHexString(frame.Frame.RemainingBytes.Span)).IsEqualTo(payload);
        var arp = frame.Payload is ArpParseResult result ? result : throw new InvalidOperationException();
        if (complete)
            await Assert.That(arp is ArpPacket).IsTrue();
        else
            await Assert.That(arp is ArpParseResult.IncompleteHeader { RequiredLength: 8, CapturedLength: 2 }).IsTrue();
    }

    [Test]
    public async Task Unknown_ether_type_has_an_explicit_payload_branch_with_original_bytes()
    {
        var frame = Decode("88B5", "CAFE") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        var payload = frame.Payload is UnsupportedEtherType unsupported ? unsupported : throw new InvalidOperationException();
        await Assert.That(payload.EtherType).IsEqualTo((ushort)0x88b5);
        await Assert.That(Convert.ToHexString(payload.Bytes.Span)).IsEqualTo("CAFE");
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
    public async Task Non_udp_ipv4_fragment_stops_at_reassembly_instead_of_protocol_dispatch()
    {
        var ip = DecodedIPv4.Decode(Convert.FromHexString("450000161234200140060000C0000201C6336402CAFE")) is DecodedIPv4 decoded
            ? decoded : throw new InvalidOperationException();
        var fragment = ip.Payload is IPv4FragmentPayload value ? value : throw new InvalidOperationException();
        await Assert.That(fragment.Protocol).IsEqualTo((byte)6);
        await Assert.That(fragment.Offset).IsEqualTo((ushort)1);
        await Assert.That(fragment.MoreFragments).IsTrue();
        await Assert.That(fragment.Identification).IsEqualTo((ushort)0x1234);
        await Assert.That(fragment.DeclaredLength).IsEqualTo(2u);
        await Assert.That(Convert.ToHexString(fragment.Bytes.Span)).IsEqualTo("CAFE");
    }

    [Test]
    [Arguments("350000140000000040110000C0000201C6336402", "InvalidVersion")]
    [Arguments("440000140000000040110000C0000201C6336402", "InvalidHeaderLength")]
    [Arguments("450000130000000040110000C0000201C6336402", "InvalidTotalLength")]
    [Arguments("460000180000000040110000C0000201C6336402", "IncompleteHeader")]
    public async Task Ipv4_header_errors_keep_their_specific_branch(string bytes, string expected)
    {
        var frame = Decode("0800", bytes) is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();
        var ip = frame.Payload is IPv4DecodeResult result ? result : throw new InvalidOperationException();
        var kind = ip switch
        {
            IPv4ParseResult.InvalidVersion { Version: 3 } => "InvalidVersion",
            IPv4ParseResult.InvalidHeaderLength { Ihl: 4 } => "InvalidHeaderLength",
            IPv4ParseResult.InvalidTotalLength { TotalLength: 19, HeaderLength: 20 } => "InvalidTotalLength",
            IPv4ParseResult.IncompleteHeader { RequiredLength: 24, CapturedLength: 20 } => "IncompleteHeader",
            _ => throw new InvalidOperationException("Wrong network failure branch.")
        };
        await Assert.That(kind).IsEqualTo(expected);
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
