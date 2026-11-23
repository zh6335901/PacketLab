using PacketLab.Desktop.Localization;
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
                Add(Strings.Payload, Strings.CapturedPayload, Size(segment.Payload.Length),
                    start + segment.Header.HeaderLength, segment.Payload.Length);
                if (!segment.IsComplete)
                    Add(Strings.Payload, Strings.DeclaredPayloadLength, Size(segment.DeclaredPayloadLength));
                break;

            case TcpParseResult.OptionsTruncated truncated:
                TcpHeader(truncated.Header, result.Checksum, start);
                TcpOptions(truncated.Options, start);
                Add("TCP", Strings.Diagnostics, Strings.TruncatedOptions);
                break;

            case TcpParseResult.InvalidDataOffset invalid:
                TcpHeader(invalid.Header, result.Checksum, start);
                Add("TCP", Strings.Diagnostics, Strings.InvalidTcpDataOffset);
                break;

            case TcpParseResult.HeaderExceedsSegment invalid:
                TcpHeader(invalid.Header, result.Checksum, start);
                var headerTooLong = UiText.Format(Strings.TcpHeaderTooLong, Size(invalid.DeclaredLength));
                Add("TCP", Strings.Diagnostics, headerTooLong);
                break;

            case TcpParseResult.IpLengthTooShort invalid:
                Add("TCP", Strings.InvalidUpperLayerLength, Size(invalid.DeclaredLength));
                TcpPartial(invalid.RemainingBytes.Span, start);
                break;

            case TcpParseResult.HeaderTruncated truncated:
                var truncatedHeader = UiText.Format(Strings.TcpRequiredBytes, Size(truncated.RemainingBytes.Length));
                Add("TCP", Strings.TruncatedHeader, truncatedHeader);
                TcpPartial(truncated.RemainingBytes.Span, start);
                break;
        }
    }

    private void TcpPartial(ReadOnlySpan<byte> available, int start)
    {
        if (!available.IsEmpty)
            Add("TCP", Strings.UnparsedHeaderBytes, Raw(available), start, available.Length);

        Add("TCP", Strings.ChecksumStatus, Strings.Unavailable);
    }

    private void TcpHeader(TcpHeader header, TcpChecksum sum, int start)
    {
        Add("TCP", Strings.SourcePort, header.SourcePort.ToString(), start, 2);
        Add("TCP", Strings.DestinationPort, header.DestinationPort.ToString(),
            start + 2, 2);
        Add("TCP", Strings.SequenceNumber, header.SequenceNumber.ToString(),
            start + 4, 4);
        Add("TCP", Strings.AcknowledgmentNumber, header.AcknowledgmentNumber.ToString(),
            start + 8, 4);
        Add("TCP", Strings.HeaderLength, Size(header.HeaderLength),
            start + 12, 1);
        Add("TCP", Strings.ReservedBits, header.Reserved.ToString(),
            start + 12, 1);
        var flags = header.Flags.ToString().Replace(", ", " · ");
        Add("TCP", Strings.Flags, flags,
            start + 12, 2);
        Add("TCP", Strings.WindowSize, header.Window.ToString(),
            start + 14, 2);
        var checksum = sum.Value switch
        {
            TcpChecksumStatus.Match => Strings.Match,
            TcpChecksumStatus.Mismatch => Strings.Mismatch,
            TcpChecksumUnavailable unavailable => UiText.Format(Strings.UnavailableReason, TcpChecksumReason(unavailable.Reason)),
            _ => Strings.Unavailable
        };
        Add("TCP", Strings.Checksum, $"0x{header.Checksum:X4} · {checksum}", start + 16, 2);
        Add("TCP", Strings.UrgentPointer, header.UrgentPointer.ToString(),
            start + 18, 2);
    }

    private static string TcpChecksumReason(TcpUnavailableReason reason) => reason switch
    {
        TcpUnavailableReason.IpLengthTooShort => Strings.InvalidUpperLayerLength,
        TcpUnavailableReason.HeaderTruncated => Strings.TruncatedHeader,
        TcpUnavailableReason.InvalidDataOffset => Strings.InvalidTcpDataOffset,
        TcpUnavailableReason.HeaderExceedsSegment => Strings.TcpHeaderExceedsSegment,
        TcpUnavailableReason.PayloadTruncated => Strings.TruncatedPayloadOrHeader,
        TcpUnavailableReason.PseudoHeaderUnavailable => Strings.PseudoHeaderUnavailable,
        _ => Strings.Unknown
    };

    private void TcpOptions(TcpOptions options, int start)
    {
        foreach (var option in options.Items)
        {
            var kind = UiText.Format(Strings.OptionKind, option.Kind);
            var (name, value) = option.Value.Value switch
            {
                TcpOptionValue.MaximumSegmentSize mss => ("MSS", Size(mss.Value)),
                TcpOptionValue.WindowScale scale => (Strings.WindowScale, scale.IsInRange ? scale.ShiftCount.ToString() : UiText.Format(Strings.FractionOutOfRange, scale.ShiftCount)),
                TcpOptionValue.SackPermitted => (Strings.SackPermitted, Strings.Permitted),
                TcpOptionValue.Sack sack => ("SACK", string.Join(" · ", sack.Blocks.Select(block => $"{block.LeftEdge}–{block.RightEdge}"))),
                TcpOptionValue.Timestamp stamp => (Strings.Timestamp, $"{stamp.Value} / {stamp.EchoReply}"),
                TcpOptionValue.NoOperation => ("NOP", Strings.SingleByte),
                TcpOptionValue.End => ("EOL", Strings.EndOfOptions),
                TcpOptionValue.Invalid invalid => (Strings.InvalidOption, $"{kind} · {TcpOptionReason(invalid.Reason)} · {invalid.AvailableLength}/{invalid.RequiredLength} B"),
                _ => (Strings.UnknownOption, $"{kind} · {Raw(option.Bytes.Span)}")
            };
            Add(Strings.TcpOptions, name, value, start + option.Offset, option.Bytes.Length);
        }
        if (!options.Padding.IsEmpty)
        {
            var offset = start + 20 + options.RawBytes.Length - options.Padding.Length;
            Add(Strings.TcpOptions, Strings.PaddingBytes, Size(options.Padding.Length) + (options.HasNonZeroPadding ? Strings.NonZeroPadding : ""),
                offset, options.Padding.Length);
        }
    }

    private static string TcpOptionReason(TcpOptionFailure reason) => reason switch
    {
        TcpOptionFailure.InvalidLength => Strings.InvalidOptionLength,
        TcpOptionFailure.ExceedsHeader => Strings.OptionExceedsHeader,
        TcpOptionFailure.CaptureTruncated => Strings.OptionCaptureTruncated,
        _ => Strings.Unknown
    };

    private void Udp(UdpParseResult result, int start)
    {
        switch (result.Value)
        {
            case UdpDatagram datagram:
                UdpHeader(datagram.Header, result.Checksum, start);
                if (datagram.EffectiveLength != datagram.Header.Length)
                    Add("UDP", Strings.EffectiveLength, Size(datagram.EffectiveLength));

                Add(Strings.Payload, Strings.CapturedPayload, Size(datagram.Payload.Length),
                    start + 8, datagram.Payload.Length);
                if (!datagram.IsComplete)
                    Add(Strings.Payload, Strings.DeclaredPayloadLength, Size(datagram.EffectiveLength - 8));
                if (datagram.DeclaredSurplusLength > 0)
                    Add(Strings.Trailing, Strings.BytesBeyondUdpLength, $"{Size(datagram.SurplusArea.Length)} / {Size(datagram.DeclaredSurplusLength)}",
                        start + 8 + datagram.Payload.Length, datagram.SurplusArea.Length);
                break;

            case UdpParseResult.InvalidLength invalid:
                UdpHeader(invalid.Header, result.Checksum, start);
                Add("UDP", Strings.Diagnostics, Strings.InvalidUdpLengthField);
                break;

            case UdpParseResult.LengthExceedsIpPayload invalid:
                UdpHeader(invalid.Header, result.Checksum, start);
                var lengthExceeds = UiText.Format(Strings.UdpLengthExceedsIpPayload, Size(invalid.DeclaredUpperLayerLength));
                Add("UDP", Strings.Diagnostics, lengthExceeds);
                break;

            case UdpParseResult.HeaderTruncated truncated:
                UdpPartial(truncated.RemainingBytes.Span, start, Strings.TruncatedHeader);
                break;

            case UdpParseResult.IpLengthTooShort invalid:
                var invalidLength = UiText.Format(Strings.InvalidUdpLengthFromIp, Size(invalid.DeclaredUpperLayerLength));
                UdpPartial(invalid.RemainingBytes.Span, start, invalidLength);
                break;
        }
    }

    private void UdpPartial(ReadOnlySpan<byte> available, int start, string reason)
    {
        Add("UDP", Strings.Diagnostics, reason);
        if (!available.IsEmpty)
            Add("UDP", Strings.UnparsedHeaderBytes, Raw(available), start, available.Length);

        Add("UDP", Strings.ChecksumStatus, Strings.Unavailable);
    }

    private void UdpHeader(UdpHeader header, UdpChecksum sum, int start)
    {
        Add("UDP", Strings.SourcePort, header.SourcePort.ToString(), start, 2);
        Add("UDP", Strings.DestinationPort, header.DestinationPort.ToString(),
            start + 2, 2);
        Add("UDP", Strings.UdpLength, Size(header.Length),
            start + 4, 2);
        var checksum = sum.Value switch
        {
            UdpChecksumStatus.Match => Strings.Match,
            UdpChecksumStatus.Mismatch => Strings.Mismatch,
            UdpChecksumStatus.NotPresent => Strings.NotProvided,
            UdpChecksumStatus.ZeroNotAllowed => Strings.ZeroChecksumNotAllowed,
            UdpChecksumUnavailable unavailable => UiText.Format(Strings.UnavailableReason, UdpChecksumReason(unavailable.Reason)),
            _ => Strings.Unavailable
        };
        Add("UDP", Strings.Checksum, $"0x{header.Checksum:X4} · {checksum}", start + 6, 2);
    }

    private static string UdpChecksumReason(UdpUnavailableReason reason) => reason switch
    {
        UdpUnavailableReason.IpLengthTooShort => Strings.InvalidUpperLayerLength,
        UdpUnavailableReason.HeaderTruncated => Strings.TruncatedHeader,
        UdpUnavailableReason.InvalidLength => Strings.InvalidUdpLengthField,
        UdpUnavailableReason.LengthExceedsIpPayload => Strings.UdpLengthBeyondIpPayload,
        UdpUnavailableReason.PayloadTruncated => Strings.TruncatedUdpPayload,
        UdpUnavailableReason.PseudoHeaderUnavailable => Strings.PseudoHeaderUnavailable,
        _ => Strings.Unknown
    };
}
