using PacketLab.Protocols;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;

namespace PacketLab.Cli.UnitTests;

public class FormatProtocolTests
{
    [Test]
    [Arguments(1, 2048, 1, "020000000001", "00000000", "000000000000", "C0000202", "Request", "02:00:00:00:00:01", "0.0.0.0", "00:00:00:00:00:00", "192.0.2.2")]
    [Arguments(1, 2048, 2, "102030405060", "C0000202", "020000000001", "C0000201", "Reply", "10:20:30:40:50:60", "192.0.2.2", "02:00:00:00:00:01", "192.0.2.1")]
    [Arguments(4660, 2048, 1, "020000000001", "C0000201", "000000000000", "C0000202", "Request", "020000000001", "192.0.2.1", "000000000000", "192.0.2.2")]
    [Arguments(1, 4660, 1, "020000000001", "C0000201", "000000000000", "C0000202", "Request", "02:00:00:00:00:01", "C0000201", "00:00:00:00:00:00", "C0000202")]
    [Arguments(1, 2048, 43981, "0102", "C0000201", "0304", "C0000202", "43981", "0102", "192.0.2.1", "0304", "192.0.2.2")]
    [Arguments(1, 2048, 1, "020000000001", "010203", "102030405060", "040506", "Request", "02:00:00:00:00:01", "010203", "10:20:30:40:50:60", "040506")]
    public async Task Addresses_are_formatted_independently(int hardwareType, int protocolType, int opcode,
        string senderHardwareBytes, string senderProtocolBytes, string targetHardwareBytes, string targetProtocolBytes,
        string operation, string senderHardware, string senderProtocol, string targetHardware, string targetProtocol)
    {
        var arp = new ArpPacket((ushort)hardwareType, (ushort)protocolType,
            (byte)(senderHardwareBytes.Length / 2), (byte)(senderProtocolBytes.Length / 2), (ushort)opcode,
            Convert.FromHexString(senderHardwareBytes), Convert.FromHexString(senderProtocolBytes),
            Convert.FromHexString(targetHardwareBytes), Convert.FromHexString(targetProtocolBytes), ReadOnlyMemory<byte>.Empty);
        var ethernet = new EthernetFrame(new(255, 255, 255, 255, 255, 255), new(2, 0, 0, 0, 0, 1), 0x0806, ReadOnlyMemory<byte>.Empty);
        var output = ProtocolFormatter.Describe(new ProtocolDecodeResult.EthernetArp(ethernet, arp));
        await Assert.That(output).IsEqualTo($"src 02:00:00:00:00:01 dst FF:FF:FF:FF:FF:FF EtherType 0x0806 (ARP); ARP {operation} sender hardware {senderHardware} protocol {senderProtocol} target hardware {targetHardware} protocol {targetProtocol}");
    }

    [Test]
    [Arguments(8, 0)]
    [Arguments(8, 7)]
    [Arguments(28, 27)]
    public async Task Incomplete_arp_displays_required_and_captured_lengths(int required, int captured)
    {
        var frame = new EthernetFrame(default, default, 0x0806, ReadOnlyMemory<byte>.Empty);
        var output = ProtocolFormatter.Describe(new ProtocolDecodeResult.EthernetArp(frame,
            new ArpParseResult.IncompleteHeader(required, new byte[captured])));
        await Assert.That(output).Contains($"Incomplete ARP header: expected {required} bytes, captured {captured}.");
    }
}
