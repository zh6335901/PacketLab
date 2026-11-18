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
    public async Task Incomplete_ethernet_does_not_dispatch_payload()
    {
        // Arrange
        var frame = Convert.FromHexString("FFFFFFFFFFFF02000000000186DD");

        // Act
        var result = ProtocolDecoder.Decode(frame.AsMemory(0, 13), LinkLayerProtocol.Ethernet);

        // Assert
        await Assert.That(result is EthernetDecodeResult ethernet && ethernet is EthernetParseResult.IncompleteHeader).IsTrue();
    }

    [Test]
    public async Task Unsupported_link_layer_does_not_dispatch_payload()
    {
        // Arrange
        var frame = Convert.FromHexString("FFFFFFFFFFFF02000000000186DD");

        // Act
        var result = ProtocolDecoder.Decode(frame, LinkLayerProtocol.Unsupported);

        // Assert
        await Assert.That(result is ProtocolDecodeResult.UnsupportedLinkLayer).IsTrue();
    }

    [Test]
    public async Task Ipv4_dispatch_preserves_each_layer_and_places_udp_failure_inside_ip_payload()
    {
        // Arrange
        const string bytes = "450000141234400040113C6EC0000201C6336402";

        // Act
        var frame = Decode("0800", bytes) is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();

        // Assert
        await Assert.That(frame.Frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(Convert.ToHexString(frame.Frame.RemainingBytes.Span)).IsEqualTo(bytes);
        var ip = frame.Payload is IPv4DecodeResult result && result is DecodedIPv4 decoded ? decoded : throw new InvalidOperationException();
        await Assert.That(ip.Packet.Header.Source.ToString()).IsEqualTo("192.0.2.1");
        await Assert.That(ip.Payload is UdpParseResult udp && udp is UdpParseResult.IpLengthTooShort).IsTrue();
    }

    [Test]
    public async Task Ipv4_header_failure_keeps_ethernet_without_constructing_decoded_ip()
    {
        // Act
        var frame = Decode("0800", "AABB") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();

        // Assert
        await Assert.That(frame.Payload is IPv4DecodeResult ip && ip is IPv4ParseResult.IncompleteHeader { CapturedLength: 2 }).IsTrue();
        await Assert.That(frame.Frame.EtherType).IsEqualTo((ushort)0x0800);
    }

    [Test]
    public async Task Ipv6_header_failure_keeps_ethernet_without_constructing_decoded_ip()
    {
        // Act
        var frame = Decode("86DD", "AABB") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();

        // Assert
        await Assert.That(frame.Payload is IPv6DecodeResult ip && ip is IPv6ParseResult.IncompleteHeader { CapturedLength: 2 }).IsTrue();
        await Assert.That(frame.Frame.EtherType).IsEqualTo((ushort)0x86DD);
    }

    [Test]
    public async Task Complete_arp_dispatch_preserves_outer_frame_and_packet()
    {
        // Arrange
        const string payload = "0001080006040001020000000001C0000201000000000000C0000202";

        // Act
        var frame = Decode("0806", payload) is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();

        // Assert
        await Assert.That(frame.Frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(Convert.ToHexString(frame.Frame.RemainingBytes.Span)).IsEqualTo(payload);
        var arp = frame.Payload is ArpParseResult result ? result : throw new InvalidOperationException();
        await Assert.That(arp is ArpPacket).IsTrue();
    }

    [Test]
    public async Task Truncated_arp_dispatch_preserves_outer_frame_and_diagnostic()
    {
        // Arrange
        const string payload = "AABB";

        // Act
        var frame = Decode("0806", payload) is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();

        // Assert
        await Assert.That(frame.Frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(Convert.ToHexString(frame.Frame.RemainingBytes.Span)).IsEqualTo(payload);
        var arp = frame.Payload is ArpParseResult result ? result : throw new InvalidOperationException();
        await Assert.That(arp is ArpParseResult.IncompleteHeader { RequiredLength: 8, CapturedLength: 2 }).IsTrue();
    }

    private const string Ipv4Payload = "450000141234400040113C6EC0000201C6336402";
    private const string ArpPayload = "0001080006040001020000000001C0000201000000000000C0000202";
    private const string Ipv6Payload = "6000000000003B4020010DB8000000000000000000000001FF020000000000000000000000000002";

    [Test]
    [Arguments("0800", ArpPayload, typeof(IPv4DecodeResult))]
    [Arguments("0806", Ipv6Payload, typeof(ArpParseResult))]
    [Arguments("86DD", Ipv4Payload, typeof(IPv6DecodeResult))]
    [Arguments("05DC", Ipv4Payload, typeof(EthernetParseResult.Ieee8023Length))]
    [Arguments("05DD", ArpPayload, typeof(EthernetParseResult.InvalidLengthOrType))]
    [Arguments("05FF", Ipv6Payload, typeof(EthernetParseResult.InvalidLengthOrType))]
    [Arguments("0600", Ipv4Payload, typeof(UnsupportedEtherType))]
    [Arguments("8100", ArpPayload, typeof(UnsupportedEtherType))]
    [Arguments("88B5", Ipv6Payload, typeof(UnsupportedEtherType))]
    public async Task Recognizable_payloads_follow_the_outer_field(string field, string payload, Type expected)
    {
        // Act
        var result = Decode(field, payload);

        // Assert
        await Assert.That(DispatchType(result)).IsEqualTo(expected);
    }

    [Test]
    [Arguments("0800")]
    [Arguments("0806")]
    [Arguments("86DD")]
    [Arguments("05DC")]
    [Arguments("05DD")]
    [Arguments("88B5")]
    public void Changing_the_payload_preserves_the_dispatch_type(string field) =>
        Prop.ForAll((byte[] first, byte[] second) =>
        {
            // Act
            var firstResult = Decode(field, Convert.ToHexString(first));
            var secondResult = Decode(field, Convert.ToHexString(second));

            // Assert
            return DispatchType(firstResult) == DispatchType(secondResult);
        }).Check(Config.QuickThrowOnFailure);

    private static Type DispatchType(EthernetDecodeResult result) =>
        result is DecodedEthernet frame ? frame.Payload.Value!.GetType() : result.Value!.GetType();

    [Test]
    [Arguments("450000141234400040013C7EC0000201C6336402", 1)]
    [Arguments("450000141234400040FD3B82C0000201C6336402", 253)]
    public async Task Unsupported_ipv4_has_an_explicit_protocol_branch(string bytes, byte protocol)
    {
        // Act
        var ip = DecodedIPv4.Decode(Convert.FromHexString(bytes)) is DecodedIPv4 decoded ? decoded : throw new InvalidOperationException();

        // Assert
        await Assert.That(ip.Payload is UnsupportedIpProtocol { DeclaredLength: 0 } other && other.Protocol == protocol).IsTrue();
    }

    [Test]
    [Arguments("2001", 6, 1, true)]
    [Arguments("1FFF", 6, 0x1FFF, false)]
    [Arguments("1FFF", 17, 0x1FFF, false)]
    public async Task Ipv4_fragments_preserve_metadata_and_bytes_before_reassembly(
        string fragmentField, byte protocol, ushort offset, bool moreFragments)
    {
        // Arrange
        var packet = Convert.FromHexString($"450000161234{fragmentField}40{protocol:X2}0000C0000201C6336402CAFE");

        // Act
        var ip = DecodedIPv4.Decode(packet) is DecodedIPv4 decoded
            ? decoded : throw new InvalidOperationException();

        // Assert
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
        // Act
        var frame = Decode("0800", "350000140000000040110000C0000201C6336402") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();

        // Assert
        var ip = frame.Payload is IPv4DecodeResult result ? result : throw new InvalidOperationException();
        await Assert.That(ip is IPv4ParseResult.InvalidVersion { Version: 3 }).IsTrue();
    }

    [Test]
    public async Task Ipv4_invalid_ihl_stays_in_the_header_error_branch()
    {
        // Act
        var frame = Decode("0800", "440000140000000040110000C0000201C6336402") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();

        // Assert
        var ip = frame.Payload is IPv4DecodeResult result ? result : throw new InvalidOperationException();
        await Assert.That(ip is IPv4ParseResult.InvalidHeaderLength { Ihl: 4 }).IsTrue();
    }

    [Test]
    public async Task Ipv4_invalid_total_length_stays_in_the_header_error_branch()
    {
        // Act
        var frame = Decode("0800", "450000130000000040110000C0000201C6336402") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();

        // Assert
        var ip = frame.Payload is IPv4DecodeResult result ? result : throw new InvalidOperationException();
        await Assert.That(ip is IPv4ParseResult.InvalidTotalLength { TotalLength: 19, HeaderLength: 20 }).IsTrue();
    }

    [Test]
    public async Task Ipv4_truncated_options_stay_in_the_header_error_branch()
    {
        // Act
        var frame = Decode("0800", "460000180000000040110000C0000201C6336402") is DecodedEthernet ethernet ? ethernet : throw new InvalidOperationException();

        // Assert
        var ip = frame.Payload is IPv4DecodeResult result ? result : throw new InvalidOperationException();
        await Assert.That(ip is IPv4ParseResult.IncompleteHeader { RequiredLength: 24, CapturedLength: 20 }).IsTrue();
    }

    [Test]
    public async Task Ipv6_invalid_version_stays_in_the_header_error_branch()
    {
        // Arrange
        var bytes = new byte[40];
        bytes[0] = 0x40;

        // Act
        var result = DecodedIPv6.Decode(bytes);

        // Assert
        await Assert.That(result is IPv6ParseResult.InvalidVersion { Version: 4 }).IsTrue();
    }

    private static EthernetDecodeResult Decode(string type, string payload) =>
        DecodedEthernet.Decode(Convert.FromHexString("FFFFFFFFFFFF020000000001" + type + payload));
}
