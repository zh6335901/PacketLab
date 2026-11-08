using PacketLab.Protocols;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Cli;

internal static class ProtocolFormatter
{
    internal static string Describe(ProtocolDecodeResult result) => result switch
    {
        ProtocolDecodeResult.EthernetArp arp => $"{DescribeEthernet(arp.Ethernet)}; {DescribeArp(arp.Arp)}",
        ProtocolDecodeResult.EthernetIPv4 ip => $"{DescribeEthernet(ip.Ethernet)}; {DescribeIPv4(ip.IPv4)}",
        ProtocolDecodeResult.EthernetIPv6 ip => $"{DescribeEthernet(ip.Ethernet)}; {DescribeIPv6(ip.IPv6)}",
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

    private static string DescribeIPv4(IPv4ParseResult result) => result switch
    {
        IPv4Packet packet => DescribeIPv4Packet(packet),
        IPv4ParseResult.IncompleteHeader incomplete => $"Incomplete IPv4 header: expected {incomplete.RequiredLength} bytes, captured {incomplete.CapturedLength}; checksum unavailable.",
        IPv4ParseResult.InvalidVersion invalid => $"Invalid IPv4 version: expected 4, found {invalid.Version}; checksum unavailable.",
        IPv4ParseResult.InvalidHeaderLength invalid => $"Invalid IPv4 IHL: expected at least 5, found {invalid.Ihl}; checksum unavailable.",
        IPv4ParseResult.InvalidTotalLength invalid => $"Invalid IPv4 Total Length: {invalid.TotalLength} bytes is less than header length {invalid.HeaderLength}; checksum unavailable.",
        null => throw new InvalidOperationException("Uninitialized IPv4 parse result.")
    };

    private static string DescribeIPv4Packet(IPv4Packet packet)
    {
        var header = packet.Header;
        var capture = packet.IsDatagramComplete ? "complete" : "incomplete";
        var options = header.Options.IsEmpty ? "none" : Convert.ToHexString(header.Options.Span);
        var checksum = packet.ChecksumStatus switch
        {
            IPv4ChecksumStatus.Match => "match",
            IPv4ChecksumStatus.Mismatch => "mismatch (captured header bytes fail checksum; outbound capture may precede checksum offload, but neither offload nor on-wire corruption is established)",
            _ => "unavailable"
        };
        return $"IPv4 src {header.Source} dst {header.Destination} Version {header.Version} IHL {header.Ihl} DSCP {header.Dscp} ECN {header.Ecn} Protocol {header.Protocol} TTL {header.Ttl}"
            + $"; header complete: {header.HeaderLength} bytes, datagram {capture}: declared {header.TotalLength} bytes, captured {packet.CapturedLength} bytes"
            + $"; Identification 0x{header.Identification:X4} Flags 0x{header.Flags:X1} (reserved {Bit(header.ReservedFlag)} DF {Bit(header.DontFragment)} MF {Bit(header.MoreFragments)}) Fragment Offset {header.FragmentOffset} (8-byte units, {header.FragmentOffsetBytes} bytes)"
            + $"; Options {options}; payload {packet.Payload.Length} bytes, trailing {packet.TrailingBytes.Length} bytes"
            + $"; Header Checksum 0x{header.HeaderChecksum:X4}: {checksum}.";
    }

    private static string DescribeIPv6(IPv6ParseResult result) => result switch
    {
        IPv6Packet packet => DescribeIPv6Packet(packet),
        IPv6ParseResult.IncompleteHeader incomplete => $"Incomplete IPv6 header: expected {incomplete.RequiredLength} bytes, captured {incomplete.CapturedLength}.",
        IPv6ParseResult.InvalidVersion invalid => $"Invalid IPv6 version: expected 6, found {invalid.Version}.",
        null => throw new InvalidOperationException("Uninitialized IPv6 parse result.")
    };

    private static string DescribeIPv6Packet(IPv6Packet packet)
    {
        var header = packet.Header;
        var payload = packet.Payload switch
        {
            IPv6Payload.KnownLength known => $"datagram {(known.IsDatagramComplete ? "complete" : "incomplete")}: declared {known.DeclaredDatagramLength} bytes, available {40 + known.Bytes.Length} bytes"
                + $"; payload declared {known.DeclaredLength} bytes, available {known.Bytes.Length} bytes, trailing {known.TrailingBytes.Length} bytes",
            IPv6Payload.UndeterminedLength unknown => "effective payload length undetermined: no valid Jumbo Payload option"
                + $"; {unknown.CapturedBytes.Length} bytes captured after fixed header; datagram completeness undetermined",
            null => throw new InvalidOperationException("Uninitialized IPv6 payload result.")
        };
        return $"IPv6 src {header.Source} dst {header.Destination} Version {header.Version} Traffic Class {header.TrafficClass} Flow Label 0x{header.FlowLabel:X5}"
            + $" Next Header {header.NextHeader} Hop Limit {header.HopLimit} Payload Length {header.PayloadLength}"
            + $"; header complete: 40 bytes; {payload}; {DescribeExtensions(packet.Extensions)}.";
    }

    private static string DescribeExtensions(IPv6ExtensionChain chain)
    {
        var headers = chain.Headers.IsEmpty ? "none" : string.Join(" -> ", chain.Headers.Select(header =>
            $"{ExtensionName(header.Type)}({header.Type}) offset {header.Offset} length {header.Length} next {header.NextHeader}"
            + (header.Fragment is { } fragment
                ? $" [offset {fragment.Offset} (8-byte units, {fragment.OffsetBytes} bytes) M {Bit(fragment.MoreFragments)} ID 0x{fragment.Identification:X8} {(fragment.IsAtomic ? "atomic" : "reassembly required")}]" : "")));
        var upper = chain.UpperLayer is { } layer
            ? $"upper protocol {layer.Protocol} offset {layer.Offset} declared {layer.DeclaredLength} bytes, available {layer.Bytes.Length} bytes"
            : $"upper layer {chain.Status}";
        var diagnostics = string.Join("", chain.Diagnostics.Select(d => $"; {d.Code} at IPv6 offset {d.Offset}: {d.Message}"));
        return $"extensions {headers}; {upper}; remaining offset {chain.RemainingOffset}, {chain.RemainingBytes.Length} bytes"
            + $"; upper checksum context {(chain.ChecksumContext is null ? "unavailable" : "available (not validated)")}{diagnostics}";
    }

    private static string ExtensionName(byte type) => type switch
    {
        0 => "Hop-by-Hop", 60 => "Destination", 43 => "Routing", 44 => "Fragment", 51 => "AH", _ => type.ToString()
    };

    private static int Bit(bool value) => value ? 1 : 0;

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
