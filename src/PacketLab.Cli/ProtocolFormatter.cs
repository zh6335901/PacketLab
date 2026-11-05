using PacketLab.Protocols;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;

namespace PacketLab.Cli;

internal static class ProtocolFormatter
{
    internal static string Describe(ProtocolDecodeResult result) => result switch
    {
        ProtocolDecodeResult.EthernetArp arp => $"{DescribeEthernet(arp.Ethernet)}; {DescribeArp(arp.Arp)}",
        EthernetParseResult ethernet => DescribeEthernet(ethernet),
        ProtocolDecodeResult.UnsupportedLinkLayer => "Unsupported link layer.",
        null => throw new InvalidOperationException("Uninitialized protocol decode result.")
    };

    private static string DescribeEthernet(EthernetParseResult result) => result switch
    {
        EthernetFrame frame => $"src {frame.Source} dst {frame.Destination} EtherType 0x{frame.EtherType:X4}{TypeName(frame.EtherType)}",
        EthernetParseResult.IncompleteHeader shortHeader => $"Incomplete Ethernet header: expected 14 bytes, captured {shortHeader.CapturedLength}.",
        EthernetParseResult.Ieee8023Length field => $"Unsupported IEEE 802.3 length encapsulation (length {field.Length}).",
        EthernetParseResult.InvalidLengthOrType field => $"Invalid Length/Type field: 0x{field.Value:X4}.",
        null => throw new InvalidOperationException("Uninitialized Ethernet parse result.")
    };

    private static string DescribeArp(ArpParseResult result) => result switch
    {
        ArpPacket arp => $"ARP {OperationName(arp.Operation)} sender hardware {HardwareAddress(arp, arp.SenderHardwareAddress)} protocol {ProtocolAddress(arp, arp.SenderProtocolAddress)} target hardware {HardwareAddress(arp, arp.TargetHardwareAddress)} protocol {ProtocolAddress(arp, arp.TargetProtocolAddress)}",
        ArpParseResult.IncompleteHeader incomplete => $"Incomplete ARP header: expected {incomplete.RequiredLength} bytes, captured {incomplete.CapturedLength}.",
        null => throw new InvalidOperationException("Uninitialized ARP parse result.")
    };

    private static string OperationName(ushort operation) => operation switch
    {
        1 => "Request",
        2 => "Reply",
        _ => operation.ToString(System.Globalization.CultureInfo.InvariantCulture)
    };

    private static string HardwareAddress(ArpPacket arp, ReadOnlyMemory<byte> address) =>
        arp.HardwareType == 1 && arp.HardwareAddressLength == 6
            ? string.Join(":", address.ToArray().Select(value => value.ToString("X2")))
            : Convert.ToHexString(address.Span);

    private static string ProtocolAddress(ArpPacket arp, ReadOnlyMemory<byte> address) =>
        arp.ProtocolType == 0x0800 && arp.ProtocolAddressLength == 4
            ? $"{address.Span[0]}.{address.Span[1]}.{address.Span[2]}.{address.Span[3]}"
            : Convert.ToHexString(address.Span);

    private static string TypeName(ushort etherType) => etherType switch
    {
        0x0800 => " (IPv4)",
        0x0806 => " (ARP)",
        0x86DD => " (IPv6)",
        _ => ""
    };

}
