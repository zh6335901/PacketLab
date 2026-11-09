using System.Buffers.Binary;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Protocols.Tcp;

[Flags]
public enum TcpFlags : ushort
{
    None = 0, FIN = 1, SYN = 2, RST = 4, PSH = 8, ACK = 16, URG = 32,
    ECE = 64, CWR = 128, AE = 256
}

public sealed record TcpHeader(ushort SourcePort, ushort DestinationPort, uint SequenceNumber,
    uint AcknowledgmentNumber, byte DataOffset, byte Reserved, TcpFlags Flags,
    ushort Window, ushort Checksum, ushort UrgentPointer)
{
    public int HeaderLength => DataOffset * 4;
}

public enum TcpChecksumStatus { Match, Mismatch }
public enum TcpUnavailableReason
{
    IpLengthTooShort, HeaderTruncated, InvalidDataOffset, HeaderExceedsSegment,
    PayloadTruncated, PseudoHeaderUnavailable
}

public union TcpChecksum(TcpChecksumStatus, TcpChecksumUnavailable);
public sealed record TcpChecksumUnavailable(TcpUnavailableReason Reason);

public sealed record TcpSegment(TcpHeader Header, uint DeclaredLength, TcpOptions Options,
    ReadOnlyMemory<byte> Payload, TcpChecksum Checksum)
{
    public uint DeclaredPayloadLength => DeclaredLength - (uint)Header.HeaderLength;
    public bool IsComplete => Payload.Length == DeclaredPayloadLength;
}

public union TcpParseResult(TcpSegment, TcpParseResult.IpLengthTooShort, TcpParseResult.HeaderTruncated,
    TcpParseResult.InvalidDataOffset, TcpParseResult.HeaderExceedsSegment, TcpParseResult.OptionsTruncated)
{
    public TcpChecksum Checksum => Value switch
    {
        TcpSegment segment => segment.Checksum,
        IpLengthTooShort => new TcpChecksumUnavailable(TcpUnavailableReason.IpLengthTooShort),
        HeaderTruncated or OptionsTruncated => new TcpChecksumUnavailable(TcpUnavailableReason.HeaderTruncated),
        InvalidDataOffset => new TcpChecksumUnavailable(TcpUnavailableReason.InvalidDataOffset),
        HeaderExceedsSegment => new TcpChecksumUnavailable(TcpUnavailableReason.HeaderExceedsSegment),
        _ => throw new InvalidOperationException("Uninitialized TCP result.")
    };

    public sealed record IpLengthTooShort(uint DeclaredLength, ReadOnlyMemory<byte> RemainingBytes);
    public sealed record HeaderTruncated(uint DeclaredLength, ReadOnlyMemory<byte> RemainingBytes);
    public sealed record InvalidDataOffset(TcpHeader Header, uint DeclaredLength, ReadOnlyMemory<byte> RemainingBytes);
    public sealed record HeaderExceedsSegment(TcpHeader Header, uint DeclaredLength, ReadOnlyMemory<byte> RemainingBytes);
    public sealed record OptionsTruncated(TcpHeader Header, uint DeclaredLength, TcpOptions Options,
        ReadOnlyMemory<byte> RemainingBytes);
}

internal static class TcpDecoder
{
    internal static TcpParseResult Decode(IPv4Packet packet) =>
        TcpParser.Parse(packet.Payload, (uint)(packet.Header.TotalLength - packet.Header.HeaderLength),
            IpChecksumAddresses.Sum(packet.Header));

    internal static TcpParseResult Decode(IPv6UpperLayer upper) =>
        TcpParser.Parse(upper.Bytes, upper.DeclaredLength, IpChecksumAddresses.Sum(upper.ChecksumContext));
}

internal static class TcpParser
{
    internal static TcpParseResult Parse(ReadOnlyMemory<byte> data, uint declaredLength, ulong? addressSum)
    {
        data = data[..(int)Math.Min((ulong)data.Length, declaredLength)];
        if (declaredLength < 20) return new TcpParseResult.IpLengthTooShort(declaredLength, data);
        if (data.Length < 20) return new TcpParseResult.HeaderTruncated(declaredLength, data);
        var bytes = data.Span;
        var header = new TcpHeader(BinaryPrimitives.ReadUInt16BigEndian(bytes),
            BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]), BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]),
            BinaryPrimitives.ReadUInt32BigEndian(bytes[8..]), (byte)(bytes[12] >> 4), (byte)((bytes[12] >> 1) & 7),
            (TcpFlags)(BinaryPrimitives.ReadUInt16BigEndian(bytes[12..]) & 0x1ff),
            BinaryPrimitives.ReadUInt16BigEndian(bytes[14..]), BinaryPrimitives.ReadUInt16BigEndian(bytes[16..]),
            BinaryPrimitives.ReadUInt16BigEndian(bytes[18..]));
        if (header.DataOffset < 5) return new TcpParseResult.InvalidDataOffset(header, declaredLength, data);
        if (header.HeaderLength > declaredLength) return new TcpParseResult.HeaderExceedsSegment(header, declaredLength, data);
        var options = TcpOptionParser.Parse(data[20..Math.Min(data.Length, header.HeaderLength)], header.HeaderLength - 20);
        if (data.Length < header.HeaderLength) return new TcpParseResult.OptionsTruncated(header, declaredLength, options, data);
        TcpChecksum checksum = data.Length < declaredLength ? new TcpChecksumUnavailable(TcpUnavailableReason.PayloadTruncated)
            : addressSum is not { } sum ? new TcpChecksumUnavailable(TcpUnavailableReason.PseudoHeaderUnavailable)
            : Validate(bytes, sum + 6 + (declaredLength >> 16) + (declaredLength & 0xffff));
        return new TcpSegment(header, declaredLength, options, data[header.HeaderLength..], checksum);
    }

    private static TcpChecksumStatus Validate(ReadOnlySpan<byte> bytes, ulong sum)
    {
        for (var i = 0; i < bytes.Length; i += 2)
            sum += i + 1 < bytes.Length ? BinaryPrimitives.ReadUInt16BigEndian(bytes[i..]) : (uint)bytes[i] << 8;
        while (sum > ushort.MaxValue) sum = (sum & 0xffff) + (sum >> 16);
        return sum == ushort.MaxValue ? TcpChecksumStatus.Match : TcpChecksumStatus.Mismatch;
    }
}
