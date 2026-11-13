using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Protocols.IP;
using PacketLab.Protocols;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.Udp;
using PacketLab.Protocols.Tcp;

namespace PacketLab.Cli;

internal static class ProtocolFormatter
{
    internal static string Describe(ReassembledIpDecoding result) => result switch
    {
        IPv4DecodeResult ipv4 => DescribeIPv4(ipv4),
        IPv6DecodeResult ipv6 => DescribeIPv6(ipv6),
        null => throw new InvalidOperationException("Uninitialized reassembled IP decoding.")
    };

    private static string DescribeTcp(TcpParseResult result) => result switch
    {
        TcpSegment tcp => DescribeTcpHeader(tcp.Header)
            + $"; segment declared {tcp.DeclaredLength} bytes; payload declared {tcp.DeclaredPayloadLength} bytes, available {tcp.Payload.Length} bytes ({(tcp.IsComplete ? "complete" : "incomplete")})"
            + DescribeTcpOptions(tcp.Options) + $"; Checksum 0x{tcp.Header.Checksum:X4}: {DescribeTcpChecksum(tcp.Checksum)}.",
        TcpParseResult.IpLengthTooShort error => "; TCP " + DescribeTcpFailure("IpLengthTooShort", 20, error.DeclaredLength, error.RemainingBytes.Length),
        TcpParseResult.HeaderTruncated error => "; TCP " + DescribeTcpFailure("HeaderTruncated", 20, error.DeclaredLength, error.RemainingBytes.Length),
        TcpParseResult.InvalidDataOffset error => DescribeTcpHeader(error.Header) + "; "
            + DescribeTcpFailure("InvalidDataOffset (minimum 5)", 20, error.DeclaredLength, error.RemainingBytes.Length),
        TcpParseResult.HeaderExceedsSegment error => DescribeTcpHeader(error.Header) + "; "
            + DescribeTcpFailure("HeaderExceedsSegment", error.Header.HeaderLength, error.DeclaredLength, error.RemainingBytes.Length),
        TcpParseResult.OptionsTruncated error => DescribeTcpHeader(error.Header) + DescribeTcpOptions(error.Options) + "; "
            + DescribeTcpFailure("HeaderTruncated (options)", error.Header.HeaderLength, error.DeclaredLength, error.RemainingBytes.Length),
        null => throw new InvalidOperationException("Uninitialized TCP parse result.")
    };

    private static string DescribeTcpHeader(TcpHeader header) =>
        $"; TCP src port {header.SourcePort} dst port {header.DestinationPort} Seq {header.SequenceNumber} Ack {header.AcknowledgmentNumber}"
        + $" Flags [{header.Flags}] Reserved {header.Reserved} Window {header.Window} Urgent Pointer {header.UrgentPointer}"
        + $"; Data Offset {header.DataOffset}, header {header.HeaderLength} bytes";

    private static string DescribeTcpFailure(string reason, int required, uint declared, int captured) =>
        $"{reason}: header requires {required} bytes, IP upper layer declared {declared} bytes, available {captured} bytes; checksum unavailable.";

    private static string DescribeTcpChecksum(TcpChecksum checksum) => checksum.Value switch
    {
        TcpChecksumStatus.Match => "match",
        TcpChecksumStatus.Mismatch => "mismatch (captured bytes fail checksum; neither offload nor on-wire corruption is established)",
        TcpChecksumUnavailable unavailable => $"unavailable ({unavailable.Reason})",
        _ => throw new InvalidOperationException("Uninitialized TCP checksum result.")
    };

    private static string DescribeTcpOptions(TcpOptions options) =>
        "; Options " + (options.Items.IsEmpty ? "none" : string.Join(", ", options.Items.Select(option =>
            $"offset {option.Offset} " + (option.Value switch
            {
                TcpOptionValue.End => "EOL",
                TcpOptionValue.NoOperation => "NOP",
                TcpOptionValue.MaximumSegmentSize mss => $"MSS {mss.Value}",
                TcpOptionValue.WindowScale scale => $"Window Scale {scale.ShiftCount}" + (scale.IsInRange ? "" : " (out of range; maximum 14)"),
                TcpOptionValue.SackPermitted => "SACK Permitted",
                TcpOptionValue.Sack sack => "SACK [" + string.Join(", ", sack.Blocks.Select(b => $"{b.LeftEdge}-{b.RightEdge}")) + "]",
                TcpOptionValue.Timestamp ts => $"Timestamp {ts.Value} echo {ts.EchoReply}",
                TcpOptionValue.Unknown => $"unknown kind {option.Kind} raw {Convert.ToHexString(option.Bytes.Span)}",
                TcpOptionValue.Invalid invalid => $"kind {option.Kind} {invalid.Reason} (required {invalid.RequiredLength}, available {invalid.AvailableLength})",
                null => throw new InvalidOperationException("Uninitialized TCP option.")
            })))) + $"; option bytes {Convert.ToHexString(options.RawBytes.Span)}; padding {options.Padding.Length} bytes"
        + (options.HasNonZeroPadding ? " (nonzero)" : "");

    internal static string Describe(ProtocolDecodeResult result) => result switch
    {
        EthernetDecodeResult ethernet => DescribeEthernet(ethernet),
        ProtocolDecodeResult.UnsupportedLinkLayer => "Unsupported link layer.",
        null => throw new InvalidOperationException("Uninitialized protocol decode result.")
    };

    private static string DescribeUdp(UdpParseResult result) => result switch
    {
        UdpDatagram udp => $"; UDP src port {udp.Header.SourcePort} dst port {udp.Header.DestinationPort} Length {udp.Header.Length} effective {udp.EffectiveLength}"
            + $"; payload {udp.Payload.Length} bytes ({(udp.IsComplete ? "complete" : "incomplete")})"
            + $"; surplus declared {udp.DeclaredSurplusLength} bytes, available {udp.SurplusArea.Length} bytes"
            + $"; Checksum 0x{udp.Header.Checksum:X4}: {DescribeUdpChecksum(udp.Checksum)}.",
        UdpParseResult.IpLengthTooShort error => "; UDP " + DescribeUdpFailure(nameof(UdpParseResult.IpLengthTooShort), error.DeclaredUpperLayerLength, error.RemainingBytes.Length),
        UdpParseResult.HeaderTruncated error => "; UDP " + DescribeUdpFailure(nameof(UdpParseResult.HeaderTruncated), error.DeclaredUpperLayerLength, error.RemainingBytes.Length),
        UdpParseResult.InvalidLength error => DescribeUdpHeader(error.Header) + DescribeUdpFailure(nameof(UdpParseResult.InvalidLength), error.DeclaredUpperLayerLength, error.RemainingBytes.Length),
        UdpParseResult.LengthExceedsIpPayload error => DescribeUdpHeader(error.Header) + DescribeUdpFailure(nameof(UdpParseResult.LengthExceedsIpPayload), error.DeclaredUpperLayerLength, error.RemainingBytes.Length),
        null => throw new InvalidOperationException("Uninitialized UDP parse result.")
    };

    private static string DescribeUdpFailure(string reason, uint declared, int captured) =>
        $"{reason}: IP upper layer declared {declared} bytes, available {captured} bytes; checksum unavailable.";

    private static string DescribeUdpHeader(UdpHeader header) =>
        $"; UDP src port {header.SourcePort} dst port {header.DestinationPort} Length {header.Length} Checksum 0x{header.Checksum:X4}; ";

    private static string DescribeUdpChecksum(UdpChecksum checksum) => checksum.Value switch
    {
        UdpChecksumStatus.NotPresent => "not present (IPv4)",
        UdpChecksumStatus.Match => "match",
        UdpChecksumStatus.Mismatch => "mismatch (captured bytes fail checksum; capture may precede checksum offload, but neither offload nor on-wire corruption is established)",
        UdpChecksumStatus.ZeroNotAllowed => "zero not allowed for ordinary IPv6 UDP; RFC 6935/6936 tunnel exception not established",
        UdpChecksumUnavailable unavailable => $"unavailable ({unavailable.Reason})",
        _ => throw new InvalidOperationException("Uninitialized UDP checksum result.")
    };

    private static string DescribeEthernet(EthernetDecodeResult result) => result switch
    {
        DecodedEthernet ethernet => $"src {ethernet.Frame.Source} dst {ethernet.Frame.Destination} EtherType 0x{ethernet.Frame.EtherType:X4}{TypeName(ethernet.Frame.EtherType)}{DescribeEthernetPayload(ethernet.Payload)}",
        EthernetParseResult.IncompleteHeader shortHeader => $"Incomplete Ethernet header: expected 14 bytes, captured {shortHeader.CapturedLength}.",
        EthernetParseResult.Ieee8023Length field => $"Unsupported IEEE 802.3 length encapsulation (length {field.Length}).",
        EthernetParseResult.InvalidLengthOrType field => $"Invalid Length/Type field: 0x{field.Value:X4}.",
        null => throw new InvalidOperationException("Uninitialized Ethernet parse result.")
    };

    private static string DescribeEthernetPayload(EthernetPayloadResult result) => result switch
    {
        ArpParseResult arp => $"; {DescribeArp(arp)}",
        IPv4DecodeResult ip => $"; {DescribeIPv4(ip)}",
        IPv6DecodeResult ip => $"; {DescribeIPv6(ip)}",
        UnsupportedEtherType => "",
        null => throw new InvalidOperationException("Uninitialized Ethernet payload result.")
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

    private static string DescribeIPv4(IPv4DecodeResult result) => result switch
    {
        DecodedIPv4 ip => DescribeIPv4Packet(ip.Packet) + DescribeIPv4Payload(ip.Payload),
        IPv4ParseResult.IncompleteHeader incomplete => $"Incomplete IPv4 header: expected {incomplete.RequiredLength} bytes, captured {incomplete.CapturedLength}; checksum unavailable.",
        IPv4ParseResult.InvalidVersion invalid => $"Invalid IPv4 version: expected 4, found {invalid.Version}; checksum unavailable.",
        IPv4ParseResult.InvalidHeaderLength invalid => $"Invalid IPv4 IHL: expected at least 5, found {invalid.Ihl}; checksum unavailable.",
        IPv4ParseResult.InvalidTotalLength invalid => $"Invalid IPv4 Total Length: {invalid.TotalLength} bytes is less than header length {invalid.HeaderLength}; checksum unavailable.",
        null => throw new InvalidOperationException("Uninitialized IPv4 parse result.")
    };

    private static string DescribeIPv4Payload(IPv4PayloadResult result) => result switch
    {
        TcpParseResult tcp => DescribeTcp(tcp),
        UdpParseResult udp => DescribeUdp(udp),
        IPv4FragmentPayload => "; IP reassembly required; complete upper layer unavailable.",
        UnsupportedIpProtocol => "",
        null => throw new InvalidOperationException("Uninitialized IPv4 payload result.")
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

    private static string DescribeIPv6(IPv6DecodeResult result) => result switch
    {
        DecodedIPv6 ip => DescribeIPv6Packet(ip) + DescribeIPv6Payload(ip.Payload),
        IPv6ParseResult.IncompleteHeader incomplete => $"Incomplete IPv6 header: expected {incomplete.RequiredLength} bytes, captured {incomplete.CapturedLength}.",
        IPv6ParseResult.InvalidVersion invalid => $"Invalid IPv6 version: expected 6, found {invalid.Version}.",
        null => throw new InvalidOperationException("Uninitialized IPv6 parse result.")
    };

    private static string DescribeIPv6Packet(DecodedIPv6 packet)
    {
        var header = packet.Header;
        var payload = packet.Capture switch
        {
            IPv6Payload.KnownLength known => $"datagram {(known.IsDatagramComplete ? "complete" : "incomplete")}: declared {known.DeclaredDatagramLength} bytes, available {40 + known.Bytes.Length} bytes"
                + $"; payload declared {known.DeclaredLength} bytes, available {known.Bytes.Length} bytes, trailing {known.TrailingBytes.Length} bytes",
            IPv6Payload.UndeterminedLength unknown => "effective payload length undetermined: no valid Jumbo Payload option"
                + $"; {unknown.CapturedBytes.Length} bytes captured after fixed header; datagram completeness undetermined",
            null => throw new InvalidOperationException("Uninitialized IPv6 payload result.")
        };
        return $"IPv6 src {header.Source} dst {header.Destination} Version {header.Version} Traffic Class {header.TrafficClass} Flow Label 0x{header.FlowLabel:X5}"
            + $" Next Header {header.NextHeader} Hop Limit {header.HopLimit} Payload Length {header.PayloadLength}"
            + $"; header complete: 40 bytes; {payload}; {DescribeIPv6Extensions(packet)}.";
    }

    private static string DescribeIPv6Payload(IPv6PayloadResult result) => result switch
    {
        TcpParseResult tcp => DescribeTcp(tcp),
        UdpParseResult udp => DescribeUdp(udp),
        IPv6FragmentPayload => "",
        IPv6NoNextHeader => "",
        IPv6PayloadUnavailable => "",
        UnsupportedIpProtocol => "",
        null => throw new InvalidOperationException("Uninitialized IPv6 payload result.")
    };

    private static string DescribeIPv6Extensions(DecodedIPv6 packet)
    {
        var headers = packet.Extensions.IsEmpty ? "none" : string.Join(" -> ", packet.Extensions.Select(header =>
            $"{ExtensionName(header.Type)}({header.Type}) offset {header.Offset} length {header.Length} next {header.NextHeader}"
            + (header.Fragment is { } fragment
                ? $" [offset {fragment.Offset} (8-byte units, {fragment.OffsetBytes} bytes) M {Bit(fragment.MoreFragments)} ID 0x{fragment.Identification:X8} {(fragment.IsAtomic ? "atomic" : "reassembly required")}]" : "")));
        var upper = packet.Payload switch
        {
            TcpParseResult when packet.Capture is IPv6Payload.KnownLength known =>
                DescribeLocatedProtocol(6, known.DeclaredLength - (uint)(packet.RemainingOffset - 40)),
            UdpParseResult when packet.Capture is IPv6Payload.KnownLength known =>
                DescribeLocatedProtocol(17, known.DeclaredLength - (uint)(packet.RemainingOffset - 40)),
            UnsupportedIpProtocol other => DescribeLocatedProtocol(other.Protocol, other.DeclaredLength),
            IPv6FragmentPayload => "upper layer ReassemblyRequired",
            IPv6NoNextHeader => "upper layer NoNextHeader",
            IPv6PayloadUnavailable unavailable => $"upper layer {unavailable.Reason}",
            _ => throw new InvalidOperationException("Inconsistent IPv6 decoded payload.")
        };
        var diagnostics = string.Join("", packet.Diagnostics.Select(d => $"; {d.Code} at IPv6 offset {d.Offset}: {d.Message}"));
        return $"extensions {headers}; {upper}; remaining offset {packet.RemainingOffset}, {packet.RemainingBytes.Length} bytes"
            + $"; upper checksum context {(packet.CanBuildChecksumContext ? "available (not validated)" : "unavailable")}{diagnostics}";

        string DescribeLocatedProtocol(byte protocol, uint length) =>
            $"upper protocol {protocol} offset {packet.RemainingOffset} declared {length} bytes, available {packet.RemainingBytes.Length} bytes";
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
