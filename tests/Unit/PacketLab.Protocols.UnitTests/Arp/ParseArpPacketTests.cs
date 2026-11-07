using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;

namespace PacketLab.Protocols.UnitTests.Arp;

public class ParseArpPacketTests
{
    [Test]
    [Arguments("0001", "000000000000", "00000000")]
    [Arguments("0001", "102030405060", "C0000201")]
    [Arguments("0002", "102030405060", "C0000201")]
    public async Task Ethernet_ipv4_packets_preserve_all_fields(string operation, string targetHardware, string senderProtocol)
    {
        var packet = Parse("000108000604" + operation + "020000000001" + senderProtocol + targetHardware + "C0000202");
        await Assert.That(packet.HardwareType).IsEqualTo((ushort)1);
        await Assert.That(packet.ProtocolType).IsEqualTo((ushort)0x0800);
        await Assert.That(packet.HardwareAddressLength).IsEqualTo((byte)6);
        await Assert.That(packet.ProtocolAddressLength).IsEqualTo((byte)4);
        await Assert.That(packet.Operation).IsEqualTo(Convert.ToUInt16(operation, 16));
        await Assert.That(Convert.ToHexString(packet.SenderHardwareAddress.Span)).IsEqualTo("020000000001");
        await Assert.That(Convert.ToHexString(packet.SenderProtocolAddress.Span)).IsEqualTo(senderProtocol);
        await Assert.That(Convert.ToHexString(packet.TargetHardwareAddress.Span)).IsEqualTo(targetHardware);
        await Assert.That(Convert.ToHexString(packet.TargetProtocolAddress.Span)).IsEqualTo("C0000202");
        await Assert.That(packet.RemainingBytes.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments("0001080006040001020000000001C0000201000000000000C0000202", "020000000001", "C0000201", "000000000000", "C0000202", 1)]
    [Arguments("123456780203ABCD0102030405060708090A", "0102", "030405", "0607", "08090A", 0xABCD)]
    [Arguments("123456780000ABCD", "", "", "", "", 0xABCD)]
    public async Task Declared_lengths_split_addresses_and_preserve_padding(string hex, string senderHardware,
        string senderProtocol, string targetHardware, string targetProtocol, int operation)
    {
        var original = Parse(hex);
        var packet = Parse(hex + "00AABB00");
        await Assert.That(packet.HardwareType).IsEqualTo(original.HardwareType);
        await Assert.That(packet.ProtocolType).IsEqualTo(original.ProtocolType);
        await Assert.That(packet.HardwareAddressLength).IsEqualTo(original.HardwareAddressLength);
        await Assert.That(packet.ProtocolAddressLength).IsEqualTo(original.ProtocolAddressLength);
        await Assert.That(packet.Operation).IsEqualTo((ushort)operation);
        await Assert.That(Convert.ToHexString(packet.SenderHardwareAddress.Span)).IsEqualTo(senderHardware);
        await Assert.That(Convert.ToHexString(packet.SenderProtocolAddress.Span)).IsEqualTo(senderProtocol);
        await Assert.That(Convert.ToHexString(packet.TargetHardwareAddress.Span)).IsEqualTo(targetHardware);
        await Assert.That(Convert.ToHexString(packet.TargetProtocolAddress.Span)).IsEqualTo(targetProtocol);
        await Assert.That(Convert.ToHexString(packet.RemainingBytes.Span)).IsEqualTo("00AABB00");
    }

    [Test]
    [Arguments(0, 8)]
    [Arguments(7, 8)]
    [Arguments(27, 28)]
    public async Task Truncation_reports_required_and_captured_lengths(int captured, int required)
    {
        var bytes = Convert.FromHexString("0001080006040001020000000001C0000201000000000000C0000202")[..captured];
        var result = ArpParser.Parse(bytes);
        await Assert.That(result is ArpParseResult.IncompleteHeader incomplete &&
            incomplete.RequiredLength == required && incomplete.CapturedLength == captured &&
            incomplete.RemainingBytes.Span.SequenceEqual(bytes)).IsTrue();
    }

    private static ArpPacket Parse(string hex) => ArpParser.Parse(Convert.FromHexString(hex)) is ArpPacket packet
        ? packet : throw new InvalidOperationException("Expected a complete ARP packet.");
}
