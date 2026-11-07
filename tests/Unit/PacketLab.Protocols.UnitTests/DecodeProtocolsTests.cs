using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;

namespace PacketLab.Protocols.UnitTests;

public class DecodeProtocolsTests
{
    [Test]
    [Arguments("0800")]
    [Arguments("86DD")]
    [Arguments("8100")]
    [Arguments("05DC")]
    [Arguments("05DD")]
    public async Task Other_outer_types_do_not_dispatch_arp(string type)
    {
        var result = ProtocolDecoder.Decode(Convert.FromHexString("FFFFFFFFFFFF020000000001" + type +
            "0001080006040001020000000001C0000201000000000000C0000202"), LinkLayerProtocol.Ethernet);
        await Assert.That(result is ProtocolDecodeResult.EthernetArp).IsFalse();
    }

    [Test]
    public async Task Incomplete_outer_header_does_not_dispatch_arp()
    {
        var result = ProtocolDecoder.Decode(Convert.FromHexString("FFFFFFFFFFFF02000000000108"), LinkLayerProtocol.Ethernet);
        await Assert.That(result is EthernetParseResult ethernet && ethernet is EthernetParseResult.IncompleteHeader).IsTrue();
    }

    [Test]
    [Arguments("0806")]
    [Arguments("86DD")]
    [Arguments("8100")]
    [Arguments("05DC")]
    [Arguments("05DD")]
    public async Task Other_outer_types_do_not_dispatch_ipv4(string type)
    {
        var result = ProtocolDecoder.Decode(Convert.FromHexString("FFFFFFFFFFFF020000000001" + type +
            "450000141234400040113C6EC0000201C6336402"), LinkLayerProtocol.Ethernet);
        await Assert.That(result is ProtocolDecodeResult.EthernetIPv4).IsFalse();
    }

    [Test]
    [Arguments(true)]
    [Arguments(false)]
    public async Task Arp_dispatch_preserves_outer_frame_and_inner_result(bool complete)
    {
        var payload = complete ? "0001080006040001020000000001C0000201000000000000C0000202" : "AABB";
        var result = ProtocolDecoder.Decode(Convert.FromHexString("FFFFFFFFFFFF0200000000010806" + payload), LinkLayerProtocol.Ethernet);
        var decoded = result is ProtocolDecodeResult.EthernetArp arp ? arp : throw new InvalidOperationException("Expected ARP dispatch.");
        await Assert.That(decoded.Ethernet.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(Convert.ToHexString(decoded.Ethernet.RemainingBytes.Span)).IsEqualTo(payload);
        if (complete)
            await Assert.That(decoded.Arp is ArpPacket).IsTrue();
        else
            await Assert.That(decoded.Arp is ArpParseResult.IncompleteHeader { RequiredLength: 8, CapturedLength: 2 }).IsTrue();
    }
}
