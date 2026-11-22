using PacketLab.Protocols;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.Udp;

namespace PacketLab.Desktop;

internal readonly record struct ByteRange(int Start, int Length)
{
    internal int End => Start + Length - 1;
    internal bool Contains(int offset) => offset >= Start && offset <= End;
    internal string Label => Start == End ? $"{Start:X4}" : $"{Start:X4}–{End:X4}";
}

internal sealed record PacketField(string Layer, string Name, string Value, ByteRange? Range);
internal sealed record PacketEvidence(byte[] Bytes, PacketSummary Summary, IReadOnlyList<PacketField> Fields);

internal sealed partial class PacketFields(byte[] bytes)
{
    private readonly List<PacketField> fields = [];

    internal static PacketEvidence Original(CaptureIndex capture, CaptureRecord record)
    {
        var data = capture.ReadBytes(record);
        var decoding = capture.Decode(record, data);
        var view = new PacketFields(data);
        if (decoding.Value is EthernetDecodeResult ethernet)
            view.Ethernet(ethernet);
        else
            view.Add("原始", "链路类型", $"未支持 · {capture.LinkTypeFor(record)}");

        if (record.Time.Kind != TimeKind.Present)
            view.Add("捕获", "时间戳", record.Time.Format());
        if (record.Length != record.OriginalLength)
            view.Add("捕获", "捕获 / 原始长度", $"{record.Length} / {record.OriginalLength} B");

        return view.Finish(record.Summary);
    }

    internal static PacketEvidence Reassembled(CaptureIndex capture, FragmentGroup group)
    {
        var data = capture.ReadDerived(group);
        var view = new PacketFields(data);
        var summary = group.Version == 4
            ? view.IPv4(DecodedIPv4.Decode(data), 0)
            : view.IPv6(DecodedIPv6.Decode(data), 0);

        return view.Finish(summary);
    }

    private PacketEvidence Finish(PacketSummary summary)
    {
        if (!fields.Any(static field => field.Range.HasValue))
            Add("原始", "未解析字节", Size(bytes.Length), 0, bytes.Length);

        return new(bytes, summary, fields);
    }

    private void Add(string layer, string name, string value, int start = -1, int length = 0)
    {
        ByteRange? range = start >= 0 && length > 0 && start <= bytes.Length - length ? new(start, length) : null;
        fields.Add(new(layer, name, value, range));
    }

    private static string Size(long bytes) => $"{bytes} B";
    private static string Bit(bool value) => value ? "1" : "0";
    private static string IpProtocol(byte value) => value switch { 6 => "6 · TCP", 17 => "17 · UDP", _ => value.ToString() };

    private static string EtherType(ushort type) => type switch
    {
        0x0800 => "0x0800 · IPv4",
        0x0806 => "0x0806 · ARP",
        0x86dd => "0x86DD · IPv6",
        _ => $"0x{type:X4} · 未知或未支持"
    };

    private void Ethernet(EthernetDecodeResult ethernet)
    {
        switch (ethernet.Value)
        {
            case DecodedEthernet decoded:
                EthernetHeader(decoded.Frame.Source, decoded.Frame.Destination, "EtherType", EtherType(decoded.Frame.EtherType));
                switch (decoded.Payload.Value)
                {
                    case ArpParseResult arp:
                        Arp(arp, 14);
                        break;

                    case IPv4DecodeResult ip:
                        IPv4(ip, 14);
                        break;

                    case IPv6DecodeResult ip:
                        IPv6(ip, 14);
                        break;

                    case UnsupportedEtherType unsupported:
                        Add("载荷", "未解析载荷", Size(unsupported.Bytes.Length), 14, unsupported.Bytes.Length);
                        break;
                }
                break;

            case EthernetParseResult.Ieee8023Length length:
                EthernetHeader(length.Source, length.Destination, "802.3 长度", Size(length.Length));
                Add("载荷", "802.3 载荷未解析", Size(length.RemainingBytes.Length), 14, length.RemainingBytes.Length);
                break;

            case EthernetParseResult.InvalidLengthOrType invalid:
                EthernetHeader(invalid.Source, invalid.Destination, "无效长度 / 类型", $"0x{invalid.Value:X4}");
                Add("载荷", "未解析载荷", Size(invalid.RemainingBytes.Length), 14, invalid.RemainingBytes.Length);
                break;

            case EthernetParseResult.IncompleteHeader truncated:
                Add("Ethernet", "首部截断", $"需要 14 B · 已捕获 {truncated.CapturedLength} B");
                break;
        }
    }

    private void EthernetHeader(MacAddress source, MacAddress destination, string label, string value)
    {
        Add("Ethernet", "目的 MAC", destination.ToString(), 0, 6);
        Add("Ethernet", "源 MAC", source.ToString(), 6, 6);
        Add("Ethernet", label, value, 12, 2);
    }

    private void Arp(ArpParseResult arp, int start)
    {
        if (arp.Value is not ArpPacket packet)
        {
            if (arp.Value is ArpParseResult.IncompleteHeader failure)
                Add("ARP", "报文截断", $"需要 {failure.RequiredLength} B · 已捕获 {failure.CapturedLength} B",
                    start, failure.CapturedLength);

            return;
        }

        var hardware = packet.HardwareAddressLength;
        var protocol = packet.ProtocolAddressLength;
        Add("ARP", "硬件类型", packet.HardwareType == 1 ? "1 · Ethernet" : $"{packet.HardwareType} · 未知", start, 2);
        Add("ARP", "协议类型", EtherType(packet.ProtocolType),
            start + 2, 2);
        Add("ARP", "硬件地址长度", hardware.ToString(),
            start + 4, 1);
        Add("ARP", "协议地址长度", protocol.ToString(),
            start + 5, 1);
        var operation = packet.Operation switch { 1 => "1 · 请求", 2 => "2 · 应答", _ => $"{packet.Operation} · 未知" };
        Add("ARP", "操作码", operation, start + 6, 2);
        var isMac = hardware == 6 && packet.HardwareType == 1;
        var sender = start + 8;
        var target = sender + hardware + protocol;
        ArpAddress(isMac ? "发送方 MAC" : "发送方硬件地址", packet.SenderHardwareAddress.Span, sender, isMac, null);
        ArpAddress("发送方", packet.SenderProtocolAddress.Span, sender + hardware, false, packet.ProtocolType);
        ArpAddress(isMac ? "目标 MAC" : "目标硬件地址", packet.TargetHardwareAddress.Span, target, isMac, null);
        ArpAddress("目标", packet.TargetProtocolAddress.Span, target + hardware, false, packet.ProtocolType);
        AddTrailing(packet.RemainingBytes, target + hardware + protocol, "ARP");
    }

    private void ArpAddress(string name, ReadOnlySpan<byte> value, int start, bool mac, ushort? protocol)
    {
        var address = protocol is { } type ? PacketAddress.FromArp(value, type) : default;
        if (protocol.HasValue)
            name += address.Kind == AddressKind.None ? "协议地址" : " IP";
        var text = address.Kind != AddressKind.None ? address.ToString() : Raw(value, mac ? ":" : " ");
        Add("ARP", name, text, start, value.Length);
    }

    private PacketSummary IPv4(IPv4DecodeResult result, int start)
    {
        switch (result.Value)
        {
            case DecodedIPv4 ip:
                var packet = ip.Packet;
                var header = packet.Header;
                Add("IPv4", "版本 / IHL", $"{header.Version} · {Size(header.HeaderLength)} 首部", start, 1);
                Add("IPv4", "DSCP / ECN", $"{header.Dscp} / {header.Ecn}", start + 1, 1);
                Add("IPv4", "总长度", Size(header.TotalLength),
                    start + 2, 2);
                Add("IPv4", "标识符", $"0x{header.Identification:X4}", start + 4, 2);
                var reserved = header.ReservedFlag ? "R 1 · " : "";
                var flags = $"{reserved}DF {Bit(header.DontFragment)} · MF {Bit(header.MoreFragments)} · {Size(header.FragmentOffsetBytes)}";
                Add("IPv4", "标志 / 片偏移", flags, start + 6, 2);
                Add("IPv4", "TTL", $"{header.Ttl} 跳", start + 8, 1);
                Add("IPv4", "上层协议", IpProtocol(header.Protocol),
                    start + 9, 1);
                var checksum = packet.ChecksumStatus switch { IPv4ChecksumStatus.Match => "匹配", IPv4ChecksumStatus.Mismatch => "不匹配", _ => "不可用" };
                Add("IPv4", "首部校验和", $"0x{header.HeaderChecksum:X4} · {checksum}", start + 10, 2);
                Add("IPv4", "源地址", header.Source.ToString(),
                    start + 12, 4);
                Add("IPv4", "目的地址", header.Destination.ToString(),
                    start + 16, 4);
                if (!header.Options.IsEmpty)
                    Add("IPv4 选项", "选项原值", Raw(header.Options.Span),
                        start + 20, header.Options.Length);

                Transport(ip.Payload.Value, start + header.HeaderLength);
                AddTrailing(packet.TrailingBytes, start + header.TotalLength, "IP 数据报");

                return PacketSummary.FromIPv4(ip);

            case IPv4ParseResult.IncompleteHeader failure:
                Add("IPv4", "首部截断", $"需要 {failure.RequiredLength} B · 已捕获 {failure.CapturedLength} B");
                break;

            case IPv4ParseResult.InvalidVersion invalid:
                Add("IPv4", "版本无效", invalid.Version.ToString(), start, 1);
                break;

            case IPv4ParseResult.InvalidHeaderLength invalid:
                Add("IPv4", "IHL 无效", invalid.Ihl.ToString(), start, 1);
                break;

            case IPv4ParseResult.InvalidTotalLength invalid:
                Add("IPv4", "总长度无效", $"{Size(invalid.TotalLength)} · 首部 {Size(invalid.HeaderLength)}", start + 2, 2);
                break;
        }

        return new(default, default, PacketIssue.Invalid, Protocol.IPv4);
    }

    private PacketSummary IPv6(IPv6DecodeResult result, int start)
    {
        if (result.Value is not DecodedIPv6 ip)
        {
            if (result.Value is IPv6ParseResult.InvalidVersion invalid)
                Add("IPv6", "版本无效", invalid.Version.ToString(), start, 1);
            if (result.Value is IPv6ParseResult.IncompleteHeader failure)
                Add("IPv6", "首部截断", $"需要 {failure.RequiredLength} B · 已捕获 {failure.CapturedLength} B");

            return new(default, default, PacketIssue.Invalid, Protocol.IPv6);
        }

        var header = ip.Header;
        Add("IPv6", "版本 / 流量类 / 流标签", $"{header.Version} / {header.TrafficClass} / 0x{header.FlowLabel:X5}", start, 4);
        Add("IPv6", "载荷长度", Size(header.PayloadLength),
            start + 4, 2);
        Add("IPv6", "下一首部", header.NextHeader.ToString(),
            start + 6, 1);
        Add("IPv6", "跳数限制", header.HopLimit.ToString(),
            start + 7, 1);
        Add("IPv6", "源地址", header.Source.ToString(),
            start + 8, 16);
        Add("IPv6", "目的地址", header.Destination.ToString(),
            start + 24, 16);
        for (var index = 0; index < ip.Extensions.Length; index++)
            IPv6Extension(ip.Extensions[index], start, index);

        Transport(ip.Payload.Value, start + ip.RemainingOffset);
        foreach (var diagnostic in ip.Diagnostics)
            Add("诊断", diagnostic.Code.ToString(), $"+{diagnostic.Offset} B · {diagnostic.Message}");
        if (ip.Capture.Value is IPv6Payload.KnownLength known)
        {
            if (known.DeclaredLength != header.PayloadLength)
                Add("IPv6", "Jumbo 载荷长度", Size(known.DeclaredLength));

            AddTrailing(known.TrailingBytes, start + 40 + known.Bytes.Length, "IP 数据报");
        }
        else
            Add("IPv6", "有效载荷长度", "无法确认");

        return PacketSummary.FromIPv6(ip);
    }

    private void IPv6Extension(IPv6ExtensionHeader extension, int ipStart, int index)
    {
        var start = ipStart + extension.Offset;
        var kind = extension.Type switch
        {
            0 => "Hop-by-Hop", 43 => "Routing", 44 => "Fragment", 51 => "AH", 60 => "Destination", _ => $"扩展 {extension.Type}"
        };
        var layer = fields.Any(field => field.Layer == kind) ? $"{kind} · {index + 1}" : kind;
        Add(layer, "下一首部", extension.NextHeader.ToString(), start, 1);
        if (extension.Fragment is { } fragment)
        {
            Add(layer, "保留字节", bytes[start + 1].ToString(),
                start + 1, 1);
            Add(layer, "片偏移 / M", $"{Size(fragment.OffsetBytes)} · M {Bit(fragment.MoreFragments)}", start + 2, 2);
            Add(layer, "标识符", $"0x{fragment.Identification:X8}", start + 4, 4);

            return;
        }

        Add(layer, "扩展长度", Size(extension.Length),
            start + 1, 1);
        Add(layer, "扩展数据", Raw(extension.Bytes.Span[2..]),
            start + 2,
                extension.Length - 2);
    }

    private void Transport(object? payload, int start)
    {
        switch (payload)
        {
            case TcpParseResult tcp:
                Tcp(tcp, start);
                break;

            case UdpParseResult udp:
                Udp(udp, start);
                break;

            case IPv4FragmentPayload fragment:
                Add("分片载荷", "已捕获片段", Size(fragment.Bytes.Length), start, fragment.Bytes.Length);
                Add("分片载荷", "声明片段长度", Size(fragment.DeclaredLength));
                break;

            case IPv6FragmentPayload fragment:
                Add("分片载荷", "已捕获片段", Size(fragment.Bytes.Length), start, fragment.Bytes.Length);
                Add("分片载荷", "声明片段长度", Size(fragment.DeclaredLength));
                break;

            case UnsupportedIpProtocol unknown:
                Add("载荷", $"协议 {unknown.Protocol} · 未支持", Size(unknown.DeclaredLength));
                Add("载荷", "未解析载荷", Size(unknown.Bytes.Length), start, unknown.Bytes.Length);
                break;

            case IPv6NoNextHeader:
                Add("载荷", "无下一首部", "59");
                break;

            case IPv6PayloadUnavailable unavailable:
                Add("载荷", "协议解析不可用", unavailable.Reason.ToString());
                break;
        }
    }

    private void AddTrailing(ReadOnlyMemory<byte> unused, int start, string source)
    {
        if (!unused.IsEmpty)
            Add("尾随", $"{source}后字节", Size(unused.Length), start, unused.Length);
    }

    internal static string Raw(ReadOnlySpan<byte> bytes, string separator = " ")
    {
        if (bytes.IsEmpty)
            return "—";

        var preview = Convert.ToHexString(bytes[..Math.Min(20, bytes.Length)]);
        var pairs = Enumerable.Range(0, preview.Length / 2).Select(i => preview.Substring(i * 2, 2));
        var formatted = string.Join(separator, pairs);

        return bytes.Length > 20 ? formatted + " …" : formatted;
    }
}
