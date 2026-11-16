using PacketLab.Protocols.IP;
using System.Buffers.Binary;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

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

public static class TcpParser
{
    internal const int FixedHeaderLength = 20;

    public static TcpParseResult Parse(ReadOnlyMemory<byte> data, uint declaredLength, ulong? pseudoHeaderAddressSum)
    {
        if (data.Length > declaredLength)
            data = data[..(int)declaredLength];

        if (declaredLength < FixedHeaderLength)
            return new TcpParseResult.IpLengthTooShort(declaredLength, data);
        if (data.Length < FixedHeaderLength)
            return new TcpParseResult.HeaderTruncated(declaredLength, data);

        var header = ReadHeader(data.Span);
        var headerLength = header.HeaderLength;
        if (headerLength < FixedHeaderLength)
            return new TcpParseResult.InvalidDataOffset(header, declaredLength, data);
        if (headerLength > declaredLength)
            return new TcpParseResult.HeaderExceedsSegment(header, declaredLength, data);

        var capturedHeaderLength = Math.Min(data.Length, headerLength);
        var options = TcpOptionParser.Parse(data[FixedHeaderLength..capturedHeaderLength], headerLength - FixedHeaderLength);
        if (data.Length < headerLength)
            return new TcpParseResult.OptionsTruncated(header, declaredLength, options, data);

        var checksum = Checksum(data.Span, declaredLength, pseudoHeaderAddressSum);

        return new TcpSegment(header, declaredLength, options, data[headerLength..], checksum);
    }

    private static TcpHeader ReadHeader(ReadOnlySpan<byte> bytes) => new(
        SourcePort: BinaryPrimitives.ReadUInt16BigEndian(bytes),
        DestinationPort: BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]),
        SequenceNumber: BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]),
        AcknowledgmentNumber: BinaryPrimitives.ReadUInt32BigEndian(bytes[8..]),
        DataOffset: (byte)(bytes[12] >> 4),
        Reserved: (byte)((bytes[12] >> 1) & 7),
        Flags: (TcpFlags)(BinaryPrimitives.ReadUInt16BigEndian(bytes[12..]) & 0x1ff),
        Window: BinaryPrimitives.ReadUInt16BigEndian(bytes[14..]),
        Checksum: BinaryPrimitives.ReadUInt16BigEndian(bytes[16..]),
        UrgentPointer: BinaryPrimitives.ReadUInt16BigEndian(bytes[18..]));

    private static TcpChecksum Checksum(ReadOnlySpan<byte> bytes, uint declaredLength, ulong? pseudoHeaderAddressSum)
    {
        if (bytes.Length < declaredLength)
            return new TcpChecksumUnavailable(TcpUnavailableReason.PayloadTruncated);
        if (pseudoHeaderAddressSum is not { } addressSum)
            return new TcpChecksumUnavailable(TcpUnavailableReason.PseudoHeaderUnavailable);

        var pseudoHeaderSum = addressSum + 6 + (declaredLength >> 16) + (declaredLength & 0xffff);

        return InternetChecksum.IsValid(bytes, pseudoHeaderSum) ? TcpChecksumStatus.Match : TcpChecksumStatus.Mismatch;
    }
}
