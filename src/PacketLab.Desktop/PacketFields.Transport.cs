using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.Udp;

namespace PacketLab.Desktop;

internal sealed partial class PacketFields
{
    private void Tcp(TcpParseResult result, int start)
    {
        switch (result.Value)
        {
            case TcpSegment segment:
                TcpHeader(segment.Header, result.Checksum, start);
                TcpOptions(segment.Options, start);
                Add("载荷", "已捕获载荷", Size(segment.Payload.Length),
                    start + segment.Header.HeaderLength, segment.Payload.Length);
                if (!segment.IsComplete)
                    Add("载荷", "声明载荷长度", Size(segment.DeclaredPayloadLength));
                break;

            case TcpParseResult.OptionsTruncated truncated:
                TcpHeader(truncated.Header, result.Checksum, start);
                TcpOptions(truncated.Options, start);
                Add("TCP", "诊断", "选项截断");
                break;

            case TcpParseResult.InvalidDataOffset invalid:
                TcpHeader(invalid.Header, result.Checksum, start);
                Add("TCP", "诊断", "Data Offset 小于 5");
                break;

            case TcpParseResult.HeaderExceedsSegment invalid:
                TcpHeader(invalid.Header, result.Checksum, start);
                Add("TCP", "诊断", $"首部超过 IP 声明的 TCP 长度 {Size(invalid.DeclaredLength)}");
                break;

            case TcpParseResult.IpLengthTooShort invalid:
                Add("TCP", "上层长度无效", Size(invalid.DeclaredLength));
                TcpPartial(invalid.RemainingBytes.Span, start);
                break;

            case TcpParseResult.HeaderTruncated truncated:
                Add("TCP", "首部截断", $"需要 20 B · 已捕获 {Size(truncated.RemainingBytes.Length)}");
                TcpPartial(truncated.RemainingBytes.Span, start);
                break;
        }
    }

    private void TcpPartial(ReadOnlySpan<byte> available, int start)
    {
        if (!available.IsEmpty)
            Add("TCP", "未解析首部原值", Raw(available), start, available.Length);

        Add("TCP", "校验状态", "不可用");
    }

    private void TcpHeader(TcpHeader header, TcpChecksum sum, int start)
    {
        Add("TCP", "源端口", header.SourcePort.ToString(), start, 2);
        Add("TCP", "目的端口", header.DestinationPort.ToString(),
            start + 2, 2);
        Add("TCP", "序列号", header.SequenceNumber.ToString(),
            start + 4, 4);
        Add("TCP", "确认号", header.AcknowledgmentNumber.ToString(),
            start + 8, 4);
        Add("TCP", "首部长度", Size(header.HeaderLength),
            start + 12, 1);
        Add("TCP", "保留位", header.Reserved.ToString(),
            start + 12, 1);
        var flags = header.Flags.ToString().Replace(", ", " · ");
        Add("TCP", "标志位", flags,
            start + 12, 2);
        Add("TCP", "窗口", header.Window.ToString(),
            start + 14, 2);
        var checksum = sum.Value switch
        {
            TcpChecksumStatus.Match => "匹配",
            TcpChecksumStatus.Mismatch => "不匹配",
            TcpChecksumUnavailable unavailable => $"不可用 · {unavailable.Reason}",
            _ => "不可用"
        };
        Add("TCP", "校验和", $"0x{header.Checksum:X4} · {checksum}", start + 16, 2);
        Add("TCP", "紧急指针", header.UrgentPointer.ToString(),
            start + 18, 2);
    }

    private void TcpOptions(TcpOptions options, int start)
    {
        foreach (var option in options.Items)
        {
            var (name, value) = option.Value.Value switch
            {
                TcpOptionValue.MaximumSegmentSize mss => ("MSS", Size(mss.Value)),
                TcpOptionValue.WindowScale scale => ("窗口缩放", scale.IsInRange ? scale.ShiftCount.ToString() : $"{scale.ShiftCount} · 超出范围"),
                TcpOptionValue.SackPermitted => ("SACK Permitted", "允许"),
                TcpOptionValue.Sack sack => ("SACK", string.Join(" · ", sack.Blocks.Select(block => $"{block.LeftEdge}–{block.RightEdge}"))),
                TcpOptionValue.Timestamp stamp => ("时间戳", $"{stamp.Value} / {stamp.EchoReply}"),
                TcpOptionValue.NoOperation => ("NOP", "单字节"),
                TcpOptionValue.End => ("EOL", "选项结束"),
                TcpOptionValue.Invalid invalid => ("无效选项", $"Kind {option.Kind} · {invalid.Reason} · {invalid.AvailableLength}/{invalid.RequiredLength} B"),
                _ => ("未知选项", $"Kind {option.Kind} · {Raw(option.Bytes.Span)}")
            };
            Add("TCP 选项", name, value, start + option.Offset, option.Bytes.Length);
        }
        if (!options.Padding.IsEmpty)
        {
            var offset = start + 20 + options.RawBytes.Length - options.Padding.Length;
            Add("TCP 选项", "填充", Size(options.Padding.Length) + (options.HasNonZeroPadding ? " · 含非零字节" : ""),
                offset, options.Padding.Length);
        }
    }

    private void Udp(UdpParseResult result, int start)
    {
        switch (result.Value)
        {
            case UdpDatagram datagram:
                UdpHeader(datagram.Header, result.Checksum, start);
                if (datagram.EffectiveLength != datagram.Header.Length)
                    Add("UDP", "有效长度", Size(datagram.EffectiveLength));

                Add("载荷", "已捕获载荷", Size(datagram.Payload.Length),
                    start + 8, datagram.Payload.Length);
                if (!datagram.IsComplete)
                    Add("载荷", "声明载荷长度", Size(datagram.EffectiveLength - 8));
                if (datagram.DeclaredSurplusLength > 0)
                    Add("尾随", "UDP 长度外字节", $"{Size(datagram.SurplusArea.Length)} / {Size(datagram.DeclaredSurplusLength)}",
                        start + 8 + datagram.Payload.Length, datagram.SurplusArea.Length);
                break;

            case UdpParseResult.InvalidLength invalid:
                UdpHeader(invalid.Header, result.Checksum, start);
                Add("UDP", "诊断", "UDP 长度字段无效");
                break;

            case UdpParseResult.LengthExceedsIpPayload invalid:
                UdpHeader(invalid.Header, result.Checksum, start);
                Add("UDP", "诊断", $"UDP 长度超过 IP 声明的载荷 {Size(invalid.DeclaredUpperLayerLength)}");
                break;

            case UdpParseResult.HeaderTruncated truncated:
                UdpPartial(truncated.RemainingBytes.Span, start, "首部截断");
                break;

            case UdpParseResult.IpLengthTooShort invalid:
                UdpPartial(invalid.RemainingBytes.Span, start, $"IP 声明的 UDP 长度无效 · {Size(invalid.DeclaredUpperLayerLength)}");
                break;
        }
    }

    private void UdpPartial(ReadOnlySpan<byte> available, int start, string reason)
    {
        Add("UDP", "诊断", reason);
        if (!available.IsEmpty)
            Add("UDP", "未解析首部原值", Raw(available), start, available.Length);

        Add("UDP", "校验状态", "不可用");
    }

    private void UdpHeader(UdpHeader header, UdpChecksum sum, int start)
    {
        Add("UDP", "源端口", header.SourcePort.ToString(), start, 2);
        Add("UDP", "目的端口", header.DestinationPort.ToString(),
            start + 2, 2);
        Add("UDP", "UDP 长度", Size(header.Length),
            start + 4, 2);
        var checksum = sum.Value switch
        {
            UdpChecksumStatus.Match => "匹配",
            UdpChecksumStatus.Mismatch => "不匹配",
            UdpChecksumStatus.NotPresent => "未提供",
            UdpChecksumStatus.ZeroNotAllowed => "此上下文禁止零校验和",
            UdpChecksumUnavailable unavailable => $"不可用 · {unavailable.Reason}",
            _ => "不可用"
        };
        Add("UDP", "校验和", $"0x{header.Checksum:X4} · {checksum}", start + 6, 2);
    }
}
