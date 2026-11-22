using System.Buffers.Binary;
using PacketLab.Protocols;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.Udp;

namespace PacketLab.Desktop;

internal enum Protocol : byte { Raw, Ethernet, Arp, IPv4, IPv6, Tcp, Udp }

[Flags]
internal enum PacketIssue : ushort
{
    None = 0, Unsupported = 1, Truncated = 2, Invalid = 4, Mismatch = 8, Unknown = 16,
    ChecksumUnavailable = 32, NoTime = 64, InvalidTime = 128, InvalidCaptureLength = 256
}

internal enum AddressKind : byte { None, Mac, IPv4, IPv6 }

internal readonly record struct PacketAddress(ulong High, ulong Low, AddressKind Kind)
{
    internal static PacketAddress From(IPv4Address address)
    {
        var packed = (uint)address.Octet0 << 24 | (uint)address.Octet1 << 16 | (uint)address.Octet2 << 8 | address.Octet3;

        return new(0, packed, AddressKind.IPv4);
    }

    internal static PacketAddress From(IPv6Address address) => new(address.High, address.Low, AddressKind.IPv6);

    internal static PacketAddress From(MacAddress address)
    {
        ulong high = (ulong)address.Octet0 << 40 | (ulong)address.Octet1 << 32 | (ulong)address.Octet2 << 24;
        uint low = (uint)address.Octet3 << 16 | (uint)address.Octet4 << 8 | address.Octet5;

        return new(0, high | low, AddressKind.Mac);
    }

    internal static PacketAddress FromArp(ReadOnlySpan<byte> address, ushort type) => (type, address.Length) switch
    {
        (0x0800, 4) => new(0, BinaryPrimitives.ReadUInt32BigEndian(address), AddressKind.IPv4),
        (0x86dd, 16) => new(BinaryPrimitives.ReadUInt64BigEndian(address),
            BinaryPrimitives.ReadUInt64BigEndian(address[8..]), AddressKind.IPv6),
        _ => default
    };

    public override string ToString() => Kind switch
    {
        AddressKind.Mac => $"{Low >> 40:X2}:{(byte)(Low >> 32):X2}:{(byte)(Low >> 24):X2}:{(byte)(Low >> 16):X2}:{(byte)(Low >> 8):X2}:{(byte)Low:X2}",
        AddressKind.IPv4 => new IPv4Address((byte)(Low >> 24),
            (byte)(Low >> 16),
                (byte)(Low >> 8), (byte)Low).ToString(),
        AddressKind.IPv6 => new IPv6Address(High, Low).ToString(),
        _ => "未知"
    };

    internal string Endpoint(ushort? port) => (Kind, port) switch
    {
        (_, null) => ToString(),
        (AddressKind.IPv6, _) => $"[{this}]:{port}",
        _ => $"{this}:{port}"
    };
}

internal readonly record struct FragmentSlice(int Offset, int Start, int Length, bool More)
{
    internal int End => Offset + Length;
    internal bool Covers(int offset) => offset >= Offset && offset < End;
}

internal readonly record struct PacketSummary(PacketAddress Source, PacketAddress Destination, PacketIssue Issue,
    Protocol Protocol, ushort SourcePort = 0, ushort DestinationPort = 0, bool HasPorts = false,
    ushort Detail = 0, byte IpVersion = 0)
{
    internal string Name => Protocol switch
    {
        Protocol.Raw => "原始",
        Protocol.Arp => "ARP",
        Protocol.Tcp => "TCP",
        Protocol.Udp => "UDP",
        _ => Protocol.ToString()
    };

    internal string SourceAddress => Source.Endpoint(HasPorts ? SourcePort : null);
    internal string DestinationAddress => Destination.Endpoint(HasPorts ? DestinationPort : null);
    internal string Transport => HasPorts ? $"{Name} {SourcePort} → {DestinationPort}" : Name;

    internal string Title => (Protocol, Issue, Detail) switch
    {
        (Protocol.Raw, _, _) => "未支持的链路类型",
        (Protocol.Ethernet, PacketIssue.Truncated, _) => "Ethernet 首部不足",
        (Protocol.Arp, PacketIssue.Truncated, _) => "ARP 地址不完整",
        (Protocol.Arp, _, 1) when Source.Low == 0 && Source.Kind == AddressKind.IPv4 => "ARP 地址探测",
        (Protocol.Arp, _, 1) => "ARP 请求",
        (Protocol.Arp, _, 2) => "ARP 应答",
        (Protocol.Arp, _, _) => $"ARP 操作码 {Detail}",
        (Protocol.Udp, _, _) when HasPorts && Issue.HasFlag(PacketIssue.Invalid) => "UDP 长度或校验和字段无效",
        (_, _, _) when Issue.HasFlag(PacketIssue.Invalid) => $"{Name} 字段无效",
        (Protocol.Udp, _, _) when HasPorts && Issue.HasFlag(PacketIssue.Truncated) => "UDP 载荷截断",
        (_, _, _) when Issue.HasFlag(PacketIssue.Truncated) => $"{Name} {(Protocol is Protocol.Tcp or Protocol.Udp ? "载荷或首部截断" : "截断")}",
        (_, _, _) when Issue.HasFlag(PacketIssue.Mismatch) => $"{Name} 校验和不匹配",
        (Protocol.Tcp, _, > 0) => $"TCP 选项 · MSS {Detail}",
        (Protocol.Udp, _, _) when IpVersion == 6 && Detail > 0 => "IPv6 扩展后承载 UDP",
        (_, _, _) when HasPorts => $"{Name} {SourcePort} → {DestinationPort}",
        (_, _, _) when Issue.HasFlag(PacketIssue.Unsupported) => $"{Name} · 未支持的封装或协议",
        _ => Name
    };

    internal static PacketSummary From(ProtocolDecodeResult decoding) => decoding.Value switch
    {
        EthernetDecodeResult { Value: DecodedEthernet ethernet } => FromEthernet(ethernet),
        EthernetDecodeResult { Value: EthernetParseResult.Ieee8023Length frame } => new(
            PacketAddress.From(frame.Source),
                PacketAddress.From(frame.Destination), PacketIssue.Unsupported, Protocol.Ethernet),
        EthernetDecodeResult { Value: EthernetParseResult.InvalidLengthOrType frame } => new(
            PacketAddress.From(frame.Source),
                PacketAddress.From(frame.Destination), PacketIssue.Invalid, Protocol.Ethernet),
        EthernetDecodeResult => new(default, default, PacketIssue.Truncated, Protocol.Ethernet),
        _ => new(default, default, PacketIssue.Unsupported, Protocol.Raw)
    };

    private static PacketSummary FromEthernet(DecodedEthernet ethernet)
    {
        var source = PacketAddress.From(ethernet.Frame.Source);
        var destination = PacketAddress.From(ethernet.Frame.Destination);

        return ethernet.Payload.Value switch
        {
            ArpParseResult { Value: ArpPacket arp } => new(
                AddressOrMac(PacketAddress.FromArp(arp.SenderProtocolAddress.Span, arp.ProtocolType), source),
                AddressOrMac(PacketAddress.FromArp(arp.TargetProtocolAddress.Span, arp.ProtocolType), destination),
                arp.Operation is 1 or 2 && arp.HardwareType == 1 && arp.ProtocolType == 0x0800 &&
                    arp.HardwareAddressLength == 6 && arp.ProtocolAddressLength == 4 ? PacketIssue.None : PacketIssue.Unknown,
                Protocol.Arp, Detail: arp.Operation),
            ArpParseResult => new(source, destination, PacketIssue.Truncated, Protocol.Arp),
            IPv4DecodeResult { Value: DecodedIPv4 ipv4 } => FromIPv4(ipv4),
            IPv6DecodeResult { Value: DecodedIPv6 ipv6 } => FromIPv6(ipv6),
            IPv4DecodeResult ipv4 => new(source, destination, ipv4.Value is IPv4ParseResult.IncompleteHeader
                ? PacketIssue.Truncated : PacketIssue.Invalid, Protocol.IPv4),
            IPv6DecodeResult ipv6 => new(source, destination, ipv6.Value is IPv6ParseResult.IncompleteHeader
                ? PacketIssue.Truncated : PacketIssue.Invalid, Protocol.IPv6),
            _ => new(source, destination, PacketIssue.Unsupported, Protocol.Ethernet)
        };
    }

    private static PacketAddress AddressOrMac(PacketAddress address, PacketAddress mac) => address.Kind == AddressKind.None ? mac : address;

    internal static PacketSummary FromIPv4(DecodedIPv4 ip)
    {
        var header = ip.Packet.Header;
        var issue = ip.Packet.IsDatagramComplete ? PacketIssue.None : PacketIssue.Truncated;
        if (ip.Packet.ChecksumStatus == IPv4ChecksumStatus.Mismatch)
            issue |= PacketIssue.Mismatch;
        if (header.ReservedFlag)
            issue |= PacketIssue.Invalid;
        var summary = new PacketSummary(PacketAddress.From(header.Source),
            PacketAddress.From(header.Destination),
            issue, Protocol.IPv4, IpVersion: 4);

        return WithTransport(summary, ip.Payload.Value);
    }

    internal static PacketSummary FromIPv6(DecodedIPv6 ip)
    {
        var issue = PacketIssue.None;
        foreach (var diagnostic in ip.Diagnostics)
        {
            issue |= diagnostic.Code switch
            {
                IPv6DiagnosticCode.ReassemblyRequired => PacketIssue.None,
                IPv6DiagnosticCode.PayloadTruncated or IPv6DiagnosticCode.HeaderTruncated => PacketIssue.Truncated,
                IPv6DiagnosticCode.EncryptedEsp or IPv6DiagnosticCode.UnsupportedNextHeader => PacketIssue.Unsupported,
                IPv6DiagnosticCode.FinalDestinationUnavailable or IPv6DiagnosticCode.SourceAddressUnavailable =>
                    PacketIssue.ChecksumUnavailable,
                _ => PacketIssue.Invalid
            };
        }
        var summary = new PacketSummary(PacketAddress.From(ip.Header.Source),
            PacketAddress.From(ip.Header.Destination),
            issue, Protocol.IPv6, Detail: (ushort)ip.Extensions.Length, IpVersion: 6);

        return WithTransport(summary, ip.Payload.Value);
    }

    private static PacketSummary WithTransport(PacketSummary summary, object? transport) => transport switch
    {
        TcpParseResult tcp => WithTcp(summary, tcp),
        UdpParseResult udp => WithUdp(summary, udp),
        UnsupportedIpProtocol => summary with { Issue = summary.Issue | PacketIssue.Unsupported },
        _ => summary
    };

    private static PacketSummary WithTcp(PacketSummary summary, TcpParseResult tcp)
    {
        summary = summary with { Protocol = Protocol.Tcp, Detail = 0 };

        return tcp.Value switch
        {
            TcpSegment segment => WithPorts(summary, segment.Header.SourcePort, segment.Header.DestinationPort,
                TcpIssue(segment),
                    MaximumSegmentSize(segment.Options)),
            TcpParseResult.OptionsTruncated(var header, _, _, _) => WithPorts(summary, header.SourcePort, header.DestinationPort,
                PacketIssue.Truncated | PacketIssue.ChecksumUnavailable, 0),
            TcpParseResult.InvalidDataOffset(var header, _, _) =>
                WithPorts(summary, header.SourcePort, header.DestinationPort, PacketIssue.Invalid | PacketIssue.ChecksumUnavailable, 0),
            TcpParseResult.HeaderExceedsSegment(var header, _, _) =>
                WithPorts(summary, header.SourcePort, header.DestinationPort, PacketIssue.Invalid | PacketIssue.ChecksumUnavailable, 0),
            TcpParseResult.HeaderTruncated => summary with { Issue = summary.Issue | PacketIssue.Truncated | PacketIssue.ChecksumUnavailable },
            _ => summary with { Issue = summary.Issue | PacketIssue.Invalid | PacketIssue.ChecksumUnavailable }
        };
    }

    private static PacketIssue TcpIssue(TcpSegment segment)
    {
        var issue = segment.IsComplete ? PacketIssue.None : PacketIssue.Truncated;
        issue |= segment.Checksum.Value switch
        {
            TcpChecksumStatus.Mismatch => PacketIssue.Mismatch,
            TcpChecksumUnavailable => PacketIssue.ChecksumUnavailable,
            _ => PacketIssue.None
        };
        foreach (var option in segment.Options.Items)
        {
            issue |= option.Value.Value switch
            {
                TcpOptionValue.Unknown => PacketIssue.Unknown,
                TcpOptionValue.Invalid { Reason: TcpOptionFailure.CaptureTruncated } => PacketIssue.Truncated,
                TcpOptionValue.Invalid => PacketIssue.Invalid,
                _ => PacketIssue.None
            };
        }

        return issue;
    }

    private static ushort MaximumSegmentSize(TcpOptions options)
    {
        foreach (var option in options.Items)
        {
            if (option.Value.Value is TcpOptionValue.MaximumSegmentSize size)
                return size.Value;
        }

        return 0;
    }

    private static PacketSummary WithUdp(PacketSummary summary, UdpParseResult udp)
    {
        summary = summary with { Protocol = Protocol.Udp };

        return udp.Value switch
        {
            UdpDatagram datagram => WithPorts(summary, datagram.Header.SourcePort, datagram.Header.DestinationPort,
                UdpIssue(datagram), summary.Detail),
            UdpParseResult.InvalidLength(var header, _, _) =>
                WithPorts(summary, header.SourcePort, header.DestinationPort, PacketIssue.Invalid | PacketIssue.ChecksumUnavailable, summary.Detail),
            UdpParseResult.LengthExceedsIpPayload(var header, _, _) =>
                WithPorts(summary, header.SourcePort, header.DestinationPort, PacketIssue.Invalid | PacketIssue.ChecksumUnavailable, summary.Detail),
            UdpParseResult.HeaderTruncated => summary with { Issue = summary.Issue | PacketIssue.Truncated | PacketIssue.ChecksumUnavailable },
            _ => summary with { Issue = summary.Issue | PacketIssue.Invalid | PacketIssue.ChecksumUnavailable }
        };
    }

    private static PacketIssue UdpIssue(UdpDatagram datagram)
    {
        var issue = datagram.IsComplete && datagram.IsSurplusComplete ? PacketIssue.None : PacketIssue.Truncated;

        return issue | (datagram.Checksum.Value switch
        {
            UdpChecksumStatus.Mismatch => PacketIssue.Mismatch,
            UdpChecksumStatus.ZeroNotAllowed => PacketIssue.Invalid,
            UdpChecksumUnavailable => PacketIssue.ChecksumUnavailable,
            _ => PacketIssue.None
        });
    }

    private static PacketSummary WithPorts(PacketSummary summary, ushort source, ushort destination, PacketIssue issue, ushort detail) =>
        summary with { SourcePort = source, DestinationPort = destination, HasPorts = true, Issue = summary.Issue | issue, Detail = detail };

    internal static FragmentSlice? Fragment(ProtocolDecodeResult decoding) => decoding.Value switch
    {
        EthernetDecodeResult { Value: DecodedEthernet { Payload.Value: IPv4DecodeResult
            { Value: DecodedIPv4 { Payload.Value: IPv4FragmentPayload fragment } ip } } } =>
            new(ip.Packet.Header.FragmentOffsetBytes, 14 + ip.Packet.Header.HeaderLength, fragment.Bytes.Length, fragment.MoreFragments),
        EthernetDecodeResult { Value: DecodedEthernet { Payload.Value: IPv6DecodeResult { Value: DecodedIPv6 ip } } } =>
            IPv6FragmentSlice(ip),
        _ => null
    };

    private static FragmentSlice? IPv6FragmentSlice(DecodedIPv6 ip)
    {
        var extension = ip.Extensions.FirstOrDefault(static header => header.Fragment is not null);
        if (extension is not { Fragment: { } fragment } || ip.Capture is not IPv6Payload.KnownLength payload)
            return null;

        var start = extension.Offset + extension.Length;

        return new(fragment.OffsetBytes, 14 + start,
            Math.Max(0, payload.Bytes.Length - (start - 40)), fragment.MoreFragments);
    }
}
