using System.Buffers.Binary;

namespace PacketLab.Protocols.Udp;

public sealed record UdpHeader(ushort SourcePort, ushort DestinationPort, ushort Length, ushort Checksum);

public enum UdpChecksumStatus { NotPresent, Match, Mismatch, Unavailable, ZeroNotAllowed }
public enum UdpUnavailableReason
{
    IpLengthTooShort, HeaderTruncated, InvalidLength, LengthExceedsIpPayload,
    PayloadTruncated, PseudoHeaderUnavailable, ReassemblyRequired
}

public sealed record UdpChecksum(UdpChecksumStatus Status, UdpUnavailableReason? Reason = null);

public sealed record UdpDatagram(UdpHeader Header, uint EffectiveLength, ReadOnlyMemory<byte> Payload,
    uint DeclaredSurplusLength, ReadOnlyMemory<byte> SurplusArea, UdpChecksum Checksum)
{
    public bool IsComplete => (ulong)Payload.Length + 8 == EffectiveLength;
    public bool IsSurplusComplete => SurplusArea.Length == DeclaredSurplusLength;
}

public union UdpParseResult(UdpDatagram, UdpParseResult.Unavailable)
{
    public UdpChecksum Checksum => Value switch
    {
        UdpDatagram datagram => datagram.Checksum,
        Unavailable unavailable => new(UdpChecksumStatus.Unavailable, unavailable.Reason),
        _ => throw new InvalidOperationException("Uninitialized UDP result.")
    };

    public sealed record Unavailable(UdpUnavailableReason Reason, uint DeclaredUpperLayerLength,
        ReadOnlyMemory<byte> RemainingBytes, UdpHeader? Header = null);
}

internal static class UdpParser
{
    internal static UdpParseResult Parse(ReadOnlyMemory<byte> data, uint declaredLength, bool ipv6, ulong? addressSum)
    {
        // The network layer owns the declaration; captured padding cannot extend it.
        data = data[..(int)Math.Min((ulong)data.Length, declaredLength)];
        if (declaredLength < 8)
            return new UdpParseResult.Unavailable(UdpUnavailableReason.IpLengthTooShort, declaredLength, data);
        if (data.Length < 8)
            return new UdpParseResult.Unavailable(UdpUnavailableReason.HeaderTruncated, declaredLength, data);
        var bytes = data.Span;
        var header = new UdpHeader(BinaryPrimitives.ReadUInt16BigEndian(bytes),
            BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]), BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]),
            BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]));
        // RFC 2675 receiver rule also covers zero Length without a Jumbo option.
        uint length = ipv6 && header.Length == 0 ? declaredLength : header.Length;
        if (length < 8)
            return new UdpParseResult.Unavailable(UdpUnavailableReason.InvalidLength, declaredLength, data, header);
        if (length > declaredLength)
            return new UdpParseResult.Unavailable(UdpUnavailableReason.LengthExceedsIpPayload, declaredLength, data, header);
        var end = (int)Math.Min((ulong)data.Length, length);
        var checksum = header.Checksum == 0
            ? new UdpChecksum(ipv6 ? UdpChecksumStatus.ZeroNotAllowed : UdpChecksumStatus.NotPresent)
            : data.Length < length ? new(UdpChecksumStatus.Unavailable, UdpUnavailableReason.PayloadTruncated)
            : addressSum is null ? new(UdpChecksumStatus.Unavailable, UdpUnavailableReason.PseudoHeaderUnavailable)
            : new(Validate(bytes[..end], addressSum.Value + 17 + (length >> 16) + (length & 0xffff)));
        return new UdpDatagram(header, length, data[8..end], declaredLength - length, data[end..], checksum);
    }

    private static UdpChecksumStatus Validate(ReadOnlySpan<byte> bytes, ulong sum)
    {
        for (var i = 0; i < bytes.Length; i += 2)
            sum += i + 1 < bytes.Length ? BinaryPrimitives.ReadUInt16BigEndian(bytes[i..]) : (uint)bytes[i] << 8;
        while (sum > ushort.MaxValue)
            sum = (sum & 0xffff) + (sum >> 16);
        return sum == ushort.MaxValue ? UdpChecksumStatus.Match : UdpChecksumStatus.Mismatch;
    }
}
