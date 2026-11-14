using FsCheck;
using FsCheck.Fluent;
using PacketLab.Protocols.Arp;

namespace PacketLab.Protocols.UnitTests.Arp;

public class ParseArpPacketTests
{
    [Test]
    [Arguments("0001", "000000000000", "00000000")]
    [Arguments("0001", "102030405060", "C0000201")]
    [Arguments("0002", "102030405060", "C0000201")]
    [Arguments("ABCD", "102030405060", "C0000201")]
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
    public void Declared_lengths_split_addresses_and_preserve_padding()
    {
        var empty = new Addresses([], [], [], []);
        var hardwareOnly = new Addresses([1], [], [2], []);
        var protocolOnly = new Addresses([], [3], [], [4]);
        if (!FieldsMatch(empty, [], 0) || !FieldsMatch(hardwareOnly, [0], 1) || !FieldsMatch(protocolOnly, [], 2))
            throw new InvalidOperationException("Failed to preserve a zero-length address field.");
        Prop.ForAll(((byte[] Sender, byte[] Target) hardware, (byte[] Sender, byte[] Target) protocol,
            (byte[] Padding, ushort Operation) fields) =>
            FieldsMatch(Addresses.Create(hardware, protocol), fields.Padding, fields.Operation)).Check(Config.QuickThrowOnFailure);
    }

    private static bool FieldsMatch(Addresses addresses, byte[] padding, ushort operation)
    {
        byte[] wire = [.. addresses.Encode(operation), .. padding];
        return ArpParser.Parse(wire) is ArpPacket packet
            && packet.HardwareType == 0x1234 && packet.ProtocolType == 0x5678 && packet.Operation == operation
            && packet.HardwareAddressLength == addresses.SenderHardware.Length
            && packet.ProtocolAddressLength == addresses.SenderProtocol.Length
            && packet.SenderHardwareAddress.Span.SequenceEqual(addresses.SenderHardware)
            && packet.TargetHardwareAddress.Span.SequenceEqual(addresses.TargetHardware)
            && packet.SenderProtocolAddress.Span.SequenceEqual(addresses.SenderProtocol)
            && packet.TargetProtocolAddress.Span.SequenceEqual(addresses.TargetProtocol)
            && packet.RemainingBytes.Span.SequenceEqual(padding);
    }

    private sealed record Addresses(byte[] SenderHardware, byte[] SenderProtocol, byte[] TargetHardware, byte[] TargetProtocol)
    {
        internal static Addresses Create((byte[] Sender, byte[] Target) hardware, (byte[] Sender, byte[] Target) protocol)
        {
            int h = Math.Min(byte.MaxValue, Math.Min(hardware.Sender.Length, hardware.Target.Length));
            int p = Math.Min(byte.MaxValue, Math.Min(protocol.Sender.Length, protocol.Target.Length));
            return new(hardware.Sender[..h], protocol.Sender[..p], hardware.Target[..h], protocol.Target[..p]);
        }

        internal byte[] Encode(ushort operation) =>
            [0x12, 0x34, 0x56, 0x78, (byte)SenderHardware.Length, (byte)SenderProtocol.Length,
                (byte)(operation >> 8), (byte)operation, .. SenderHardware, .. SenderProtocol, .. TargetHardware, .. TargetProtocol];
    }

    [Test]
    public void Truncation_reports_required_and_captured_lengths() =>
        Prop.ForAll(((byte[] Sender, byte[] Target) hardware, (byte[] Sender, byte[] Target) protocol, DoNotSize<ushort> cut) =>
        {
            var wire = Addresses.Create(hardware, protocol).Encode(1);
            return Truncated(wire, 0) && Truncated(wire, 7) && Truncated(wire, wire.Length - 1)
                && Truncated(wire, cut.Item % wire.Length);
        }).Check(Config.QuickThrowOnFailure);

    private static bool Truncated(byte[] wire, int length) =>
        ArpParser.Parse(wire.AsMemory(0, length)) is ArpParseResult.IncompleteHeader error
        && error.RequiredLength == (length < 8 ? 8 : wire.Length) && error.CapturedLength == length
        && error.RemainingBytes.Span.SequenceEqual(wire.AsSpan(0, length));

    private static ArpPacket Parse(string hex) => ArpParser.Parse(Convert.FromHexString(hex)) is ArpPacket packet
        ? packet : throw new InvalidOperationException("Expected a complete ARP packet.");
}
