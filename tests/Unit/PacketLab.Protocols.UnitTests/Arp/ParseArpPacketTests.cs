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
        // Act
        var packet = Parse("000108000604" + operation + "020000000001" + senderProtocol + targetHardware + "C0000202");

        // Assert
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
    public void Declared_lengths_split_addresses_and_preserve_padding() =>
        Prop.ForAll(((byte[] Sender, byte[] Target) hardware, (byte[] Sender, byte[] Target) protocol,
            (byte[] Padding, ushort Operation) fields) =>
            {
                // Act
                var matches = FieldsMatch(Addresses.Create(hardware, protocol), fields.Padding, fields.Operation);

                // Assert
                return matches;
            }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments("", "", "", "", "", 0)]
    [Arguments("01", "", "02", "", "00", 1)]
    [Arguments("", "03", "", "04", "", 2)]
    public async Task Zero_length_arp_addresses_preserve_the_other_fields(
        string senderHardware, string senderProtocol, string targetHardware, string targetProtocol, string padding, ushort operation)
    {
        // Arrange
        var addresses = new Addresses(Convert.FromHexString(senderHardware), Convert.FromHexString(senderProtocol),
            Convert.FromHexString(targetHardware), Convert.FromHexString(targetProtocol));

        // Act
        var matches = FieldsMatch(addresses, Convert.FromHexString(padding), operation);

        // Assert
        await Assert.That(matches).IsTrue();
    }

    private static bool FieldsMatch(Addresses addresses, byte[] padding, ushort operation)
    {
        // Arrange
        byte[] wire = [.. addresses.Encode(operation), .. padding];

        // Act
        var result = ArpParser.Parse(wire);

        // Assert
        return result is ArpPacket packet
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
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(2)]
    [Arguments(3)]
    public void Truncation_reports_required_and_captured_lengths(int scenario) =>
        Prop.ForAll(((byte[] Sender, byte[] Target) hardware, (byte[] Sender, byte[] Target) protocol, DoNotSize<ushort> cut) =>
        {
            // Arrange
            var wire = Addresses.Create(hardware, protocol).Encode(1);
            int length = scenario switch { 0 => 0, 1 => 7, 2 => wire.Length - 1, _ => cut.Item % wire.Length };

            // Act
            var matches = Truncated(wire, length);

            // Assert
            return matches;
        }).Check(Config.QuickThrowOnFailure);

    private static bool Truncated(byte[] wire, int length) =>
        ArpParser.Parse(wire.AsMemory(0, length)) is ArpParseResult.IncompleteHeader error
        && error.RequiredLength == (length < 8 ? 8 : wire.Length) && error.CapturedLength == length
        && error.RemainingBytes.Span.SequenceEqual(wire.AsSpan(0, length));

    private static ArpPacket Parse(string hex) => ArpParser.Parse(Convert.FromHexString(hex)) is ArpPacket packet
        ? packet : throw new InvalidOperationException("Expected a complete ARP packet.");
}
