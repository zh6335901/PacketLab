using PacketLab.Desktop.Localization;
using PacketLab.Desktop.Models.PacketExplorer;
using PacketLab.Protocols;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.Udp;

namespace PacketLab.Desktop.Services.PacketExplorer;

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
        {
            var unsupported = UIText.Format(Strings.UnsupportedValue, capture.LinkTypeFor(record));
            view.Add(Strings.Raw, Strings.LinkType, unsupported);
        }

        if (record.Time.Kind != TimeKind.Present)
            view.Add(Strings.Capture, Strings.Timestamp, record.Time.Format());
        if (record.Length != record.OriginalLength)
            view.Add(Strings.Capture, Strings.CapturedOriginalLength, $"{record.Length} / {record.OriginalLength} B");

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
            Add(Strings.Raw, Strings.UnparsedBytes, Size(bytes.Length), 0, bytes.Length);

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
        _ => UIText.Format(Strings.UnknownEtherType, type)
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
                        Add(Strings.Payload, Strings.UnparsedPayload, Size(unsupported.Bytes.Length), 14, unsupported.Bytes.Length);
                        break;
                }
                break;

            case EthernetParseResult.Ieee8023Length length:
                EthernetHeader(length.Source, length.Destination, Strings.IeeeLength, Size(length.Length));
                Add(Strings.Payload, Strings.UnparsedIeeePayload, Size(length.RemainingBytes.Length), 14, length.RemainingBytes.Length);
                break;

            case EthernetParseResult.InvalidLengthOrType invalid:
                EthernetHeader(invalid.Source, invalid.Destination, Strings.InvalidLengthType, $"0x{invalid.Value:X4}");
                Add(Strings.Payload, Strings.UnparsedPayload, Size(invalid.RemainingBytes.Length), 14, invalid.RemainingBytes.Length);
                break;

            case EthernetParseResult.IncompleteHeader truncated:
                Add("Ethernet", Strings.TruncatedHeader, UIText.Format(Strings.EthernetRequiredBytes, truncated.CapturedLength));
                break;
        }
    }

    private void EthernetHeader(MacAddress source, MacAddress destination, string label, string value)
    {
        Add("Ethernet", Strings.DestinationMac, destination.ToString(), 0, 6);
        Add("Ethernet", Strings.SourceMac, source.ToString(), 6, 6);
        Add("Ethernet", label, value, 12, 2);
    }

    private void Arp(ArpParseResult arp, int start)
    {
        if (arp.Value is not ArpPacket packet)
        {
            if (arp.Value is ArpParseResult.IncompleteHeader failure)
                Add("ARP", Strings.PacketTruncated, UIText.Format(Strings.RequiredAndCapturedBytes, failure.RequiredLength, failure.CapturedLength),
                    start, failure.CapturedLength);

            return;
        }

        var hardware = packet.HardwareAddressLength;
        var protocol = packet.ProtocolAddressLength;
        Add("ARP", Strings.HardwareType, packet.HardwareType == 1 ? "1 · Ethernet" : UIText.Format(Strings.UnknownValue, packet.HardwareType), start, 2);
        Add("ARP", Strings.ProtocolType, EtherType(packet.ProtocolType),
            start + 2, 2);
        Add("ARP", Strings.HardwareAddressLength, hardware.ToString(),
            start + 4, 1);
        Add("ARP", Strings.ProtocolAddressLength, protocol.ToString(),
            start + 5, 1);
        var operation = packet.Operation switch { 1 => Strings.ArpOperationRequest, 2 => Strings.ArpOperationReply, _ => UIText.Format(Strings.UnknownValue, packet.Operation) };
        Add("ARP", Strings.Opcode, operation, start + 6, 2);
        var isMac = hardware == 6 && packet.HardwareType == 1;
        var sender = start + 8;
        var target = sender + hardware + protocol;
        ArpHardwareAddress(isMac ? Strings.SenderMac : Strings.SenderHardwareAddress, packet.SenderHardwareAddress.Span, sender, isMac);
        ArpProtocolAddress(packet.SenderProtocolAddress.Span, packet.ProtocolType, sender + hardware, isTarget: false);
        ArpHardwareAddress(isMac ? Strings.TargetMac : Strings.TargetHardwareAddress, packet.TargetHardwareAddress.Span, target, isMac);
        ArpProtocolAddress(packet.TargetProtocolAddress.Span, packet.ProtocolType, target + hardware, isTarget: true);
        AddTrailing(packet.RemainingBytes, target + hardware + protocol, "ARP");
    }

    private void ArpHardwareAddress(string name, ReadOnlySpan<byte> value, int start, bool mac) =>
        Add("ARP", name, Raw(value, mac ? ":" : " "), start, value.Length);

    private void ArpProtocolAddress(ReadOnlySpan<byte> value, ushort protocol, int start, bool isTarget)
    {
        var address = PacketAddress.FromArp(value, protocol);
        var isIp = address.Kind != AddressKind.None;
        var name = (isTarget, isIp) switch
        {
            (true, true) => Strings.TargetIp,
            (true, false) => Strings.TargetProtocolAddress,
            (false, true) => Strings.SenderIp,
            (false, false) => Strings.SenderProtocolAddress
        };
        var text = isIp ? address.ToString() : Raw(value);
        Add("ARP", name, text, start, value.Length);
    }

    private PacketSummary IPv4(IPv4DecodeResult result, int start)
    {
        switch (result.Value)
        {
            case DecodedIPv4 ip:
                var packet = ip.Packet;
                var header = packet.Header;
                var versionAndHeader = UIText.Format(Strings.VersionAndHeaderSize, header.Version, Size(header.HeaderLength));
                Add("IPv4", Strings.VersionIhl, versionAndHeader, start, 1);
                Add("IPv4", "DSCP / ECN", $"{header.Dscp} / {header.Ecn}", start + 1, 1);
                Add("IPv4", Strings.TotalLength, Size(header.TotalLength),
                    start + 2, 2);
                Add("IPv4", Strings.Identification, $"0x{header.Identification:X4}", start + 4, 2);
                var reserved = header.ReservedFlag ? "R 1 · " : "";
                var flags = $"{reserved}DF {Bit(header.DontFragment)} · MF {Bit(header.MoreFragments)} · {Size(header.FragmentOffsetBytes)}";
                Add("IPv4", Strings.FlagsAndFragmentOffset, flags, start + 6, 2);
                var ttl = UIText.Format(Strings.HopCount, header.Ttl);
                Add("IPv4", "TTL", ttl, start + 8, 1);
                Add("IPv4", Strings.UpperLayerProtocol, IpProtocol(header.Protocol),
                    start + 9, 1);
                var checksum = packet.ChecksumStatus switch { IPv4ChecksumStatus.Match => Strings.Match, IPv4ChecksumStatus.Mismatch => Strings.Mismatch, _ => Strings.Unavailable };
                Add("IPv4", Strings.HeaderChecksum, $"0x{header.HeaderChecksum:X4} · {checksum}", start + 10, 2);
                Add("IPv4", Strings.SourceAddress, header.Source.ToString(),
                    start + 12, 4);
                Add("IPv4", Strings.DestinationAddress, header.Destination.ToString(),
                    start + 16, 4);
                if (!header.Options.IsEmpty)
                    Add(Strings.Ipv4Options, Strings.RawOptionBytes, Raw(header.Options.Span),
                        start + 20, header.Options.Length);

                Transport(ip.Payload.Value, start + header.HeaderLength);
                AddTrailing(packet.TrailingBytes, start + header.TotalLength, Strings.IpDatagram);

                return PacketSummary.FromIPv4(ip);

            case IPv4ParseResult.IncompleteHeader failure:
                Add("IPv4", Strings.TruncatedHeader, UIText.Format(Strings.RequiredAndCapturedBytes, failure.RequiredLength, failure.CapturedLength));
                break;

            case IPv4ParseResult.InvalidVersion invalid:
                Add("IPv4", Strings.InvalidVersion, invalid.Version.ToString(), start, 1);
                break;

            case IPv4ParseResult.InvalidHeaderLength invalid:
                Add("IPv4", Strings.InvalidIhl, invalid.Ihl.ToString(), start, 1);
                break;

            case IPv4ParseResult.InvalidTotalLength invalid:
                var invalidLength = UIText.Format(Strings.LengthAndHeaderSize, Size(invalid.TotalLength), Size(invalid.HeaderLength));
                Add("IPv4", Strings.InvalidTotalLength, invalidLength, start + 2, 2);
                break;
        }

        return new(default, default, PacketIssue.Invalid, Protocol.IPv4);
    }

    private PacketSummary IPv6(IPv6DecodeResult result, int start)
    {
        if (result.Value is not DecodedIPv6 ip)
        {
            if (result.Value is IPv6ParseResult.InvalidVersion invalid)
                Add("IPv6", Strings.InvalidVersion, invalid.Version.ToString(), start, 1);
            if (result.Value is IPv6ParseResult.IncompleteHeader failure)
                Add("IPv6", Strings.TruncatedHeader, UIText.Format(Strings.RequiredAndCapturedBytes, failure.RequiredLength, failure.CapturedLength));

            return new(default, default, PacketIssue.Invalid, Protocol.IPv6);
        }

        var header = ip.Header;
        Add("IPv6", Strings.VersionTrafficFlow, $"{header.Version} / {header.TrafficClass} / 0x{header.FlowLabel:X5}", start, 4);
        Add("IPv6", Strings.PayloadLength, Size(header.PayloadLength),
            start + 4, 2);
        Add("IPv6", Strings.NextHeader, header.NextHeader.ToString(),
            start + 6, 1);
        Add("IPv6", Strings.HopLimit, header.HopLimit.ToString(),
            start + 7, 1);
        Add("IPv6", Strings.SourceAddress, header.Source.ToString(),
            start + 8, 16);
        Add("IPv6", Strings.DestinationAddress, header.Destination.ToString(),
            start + 24, 16);
        for (var index = 0; index < ip.Extensions.Length; index++)
            IPv6Extension(ip.Extensions[index], start, index);

        Transport(ip.Payload.Value, start + ip.RemainingOffset);
        foreach (var diagnostic in ip.Diagnostics)
        {
            var name = Ipv6DiagnosticName(diagnostic.Code);
            var location = Ipv6DiagnosticLocation(diagnostic);
            Add(Strings.Diagnostics, name, location);
        }
        if (ip.Capture.Value is IPv6Payload.KnownLength known)
        {
            if (known.DeclaredLength != header.PayloadLength)
                Add("IPv6", Strings.JumboPayloadLength, Size(known.DeclaredLength));

            AddTrailing(known.TrailingBytes, start + 40 + known.Bytes.Length, Strings.IpDatagram);
        }
        else
            Add("IPv6", Strings.EffectivePayloadLength, Strings.Undetermined);

        return PacketSummary.FromIPv6(ip);
    }

    private void IPv6Extension(IPv6ExtensionHeader extension, int ipStart, int index)
    {
        var start = ipStart + extension.Offset;
        var kind = extension.Type switch
        {
            0 => Strings.HopByHopHeader,
            43 => Strings.RoutingExtensionHeader,
            44 => Strings.FragmentExtensionHeader,
            51 => "AH",
            60 => Strings.DestinationOptionsHeader,
            _ => UIText.Format(Strings.ExtensionType, extension.Type)
        };
        var layer = fields.Any(field => field.Layer == kind) ? $"{kind} · {index + 1}" : kind;
        Add(layer, Strings.NextHeader, extension.NextHeader.ToString(), start, 1);
        if (extension.Fragment is { } fragment)
        {
            Add(layer, Strings.ReservedBytes, bytes[start + 1].ToString(),
                start + 1, 1);
            Add(layer, Strings.FragmentOffsetAndMore, $"{Size(fragment.OffsetBytes)} · M {Bit(fragment.MoreFragments)}", start + 2, 2);
            Add(layer, Strings.Identification, $"0x{fragment.Identification:X8}", start + 4, 4);

            return;
        }

        Add(layer, Strings.ExtensionLength, Size(extension.Length),
            start + 1, 1);
        Add(layer, Strings.ExtensionData, Raw(extension.Bytes.Span[2..]),
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
                Add(Strings.FragmentPayload, Strings.CapturedFragment, Size(fragment.Bytes.Length), start, fragment.Bytes.Length);
                Add(Strings.FragmentPayload, Strings.DeclaredFragmentLength, Size(fragment.DeclaredLength));
                break;

            case IPv6FragmentPayload fragment:
                Add(Strings.FragmentPayload, Strings.CapturedFragment, Size(fragment.Bytes.Length), start, fragment.Bytes.Length);
                Add(Strings.FragmentPayload, Strings.DeclaredFragmentLength, Size(fragment.DeclaredLength));
                break;

            case UnsupportedIpProtocol unknown:
                Add(Strings.Payload, UIText.Format(Strings.UnsupportedProtocolNumber, unknown.Protocol), Size(unknown.DeclaredLength));
                Add(Strings.Payload, Strings.UnparsedPayload, Size(unknown.Bytes.Length), start, unknown.Bytes.Length);
                break;

            case IPv6NoNextHeader:
                Add(Strings.Payload, Strings.NoNextHeader, "59");
                break;

            case IPv6PayloadUnavailable unavailable:
                var reason = unavailable.Reason switch
                {
                    IPv6PayloadFailure.Invalid => Strings.Invalid,
                    IPv6PayloadFailure.Truncated => Strings.Truncated,
                    _ => Strings.Unsupported
                };
                Add(Strings.Payload, Strings.ProtocolDecodingUnavailable, reason);
                break;
        }
    }

    private static string Ipv6DiagnosticName(IPv6DiagnosticCode code) => code switch
    {
        IPv6DiagnosticCode.PayloadTruncated => Strings.Ipv6PayloadTruncated,
        IPv6DiagnosticCode.HeaderTruncated => Strings.Ipv6ExtensionTruncated,
        IPv6DiagnosticCode.HeaderExceedsPayload => Strings.Ipv6ExtensionExceedsPayload,
        IPv6DiagnosticCode.InvalidHeaderLength => Strings.Ipv6ExtensionLengthInvalid,
        IPv6DiagnosticCode.InvalidOptions => Strings.Ipv6OptionInvalid,
        IPv6DiagnosticCode.MissingJumboPayload => Strings.Ipv6JumboMissing,
        IPv6DiagnosticCode.InvalidJumboPayload => Strings.Ipv6JumboInvalid,
        IPv6DiagnosticCode.JumboFragment => Strings.Ipv6JumboFragment,
        IPv6DiagnosticCode.InvalidHopByHopPosition => Strings.Ipv6HopByHopPosition,
        IPv6DiagnosticCode.DuplicateFragment => Strings.Ipv6DuplicateFragment,
        IPv6DiagnosticCode.ReassemblyRequired => Strings.Ipv6ReassemblyRequired,
        IPv6DiagnosticCode.EncryptedEsp => Strings.Ipv6EncryptedEsp,
        IPv6DiagnosticCode.UnsupportedNextHeader => Strings.Ipv6UnsupportedHeader,
        IPv6DiagnosticCode.FinalDestinationUnavailable => Strings.Ipv6DestinationUnavailable,
        IPv6DiagnosticCode.SourceAddressUnavailable => Strings.Ipv6SourceUnavailable,
        _ => Strings.Unknown
    };

    private static string Ipv6DiagnosticLocation(IPv6Diagnostic diagnostic)
    {
        var pattern = diagnostic.Code switch
        {
            IPv6DiagnosticCode.PayloadTruncated => Strings.Ipv6PayloadCaptureLengths,
            IPv6DiagnosticCode.HeaderTruncated => Strings.Ipv6HeaderCaptureLength,
            IPv6DiagnosticCode.HeaderExceedsPayload => Strings.Ipv6HeaderRemainingLength,
            IPv6DiagnosticCode.InvalidHeaderLength => Strings.Ipv6InvalidAhLength,
            IPv6DiagnosticCode.UnsupportedNextHeader => Strings.Ipv6UnsupportedHeaderNumber,
            IPv6DiagnosticCode.FinalDestinationUnavailable => Strings.Ipv6RoutingContext,
            _ => null
        };
        var location = $"+{diagnostic.Offset} B";
        if (pattern is null)
            return location;

        var arguments = diagnostic.Arguments;
        var detail = UIText.Format(pattern, arguments.First, arguments.Second, arguments.Third);

        return $"{location} · {detail}";
    }

    private void AddTrailing(ReadOnlyMemory<byte> unused, int start, string source)
    {
        if (!unused.IsEmpty)
        {
            var label = UIText.Format(Strings.BytesAfter, source);
            Add(Strings.Trailing, label, Size(unused.Length), start, unused.Length);
        }
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
