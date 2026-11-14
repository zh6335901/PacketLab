using System.Buffers.Binary;
using System.Collections.Immutable;

namespace PacketLab.Protocols.Tcp;

public enum TcpOptionFailure { InvalidLength, ExceedsHeader, CaptureTruncated }
public union TcpOptionValue(TcpOptionValue.End, TcpOptionValue.NoOperation, TcpOptionValue.MaximumSegmentSize,
    TcpOptionValue.WindowScale, TcpOptionValue.SackPermitted, TcpOptionValue.Sack,
    TcpOptionValue.Timestamp, TcpOptionValue.Unknown, TcpOptionValue.Invalid)
{
    public sealed record End;
    public sealed record NoOperation;
    public sealed record MaximumSegmentSize(ushort Value);
    public sealed record WindowScale(byte ShiftCount)
    {
        public bool IsInRange => ShiftCount <= 14;
    }
    public sealed record SackPermitted;
    public sealed record Sack(ImmutableArray<TcpSackBlock> Blocks);
    public sealed record Timestamp(uint Value, uint EchoReply);
    public sealed record Unknown;
    public sealed record Invalid(TcpOptionFailure Reason, int RequiredLength, int AvailableLength);
}

public sealed record TcpSackBlock(uint LeftEdge, uint RightEdge);
// Offsets are measured from the start of the TCP header.
public sealed record TcpOption(int Offset, ReadOnlyMemory<byte> Bytes, TcpOptionValue Value)
{
    public byte Kind => Bytes.Span[0];
}

public sealed record TcpOptions(ReadOnlyMemory<byte> RawBytes, ImmutableArray<TcpOption> Items,
    ReadOnlyMemory<byte> Padding)
{
    public bool HasNonZeroPadding => Padding.Span.ContainsAnyExcept((byte)0);
}

internal static class TcpOptionParser
{
    internal static TcpOptions Parse(ReadOnlyMemory<byte> data, int declaredLength)
    {
        if (data.IsEmpty) return new(data, [], ReadOnlyMemory<byte>.Empty);
        var items = ImmutableArray.CreateBuilder<TcpOption>();
        for (var i = 0; i < data.Length;)
        {
            var kind = data.Span[i];
            if (kind == 0)
            {
                items.Add(new(20 + i, data.Slice(i, 1), new TcpOptionValue.End()));
                return new(data, items.ToImmutable(), data[(i + 1)..]);
            }
            if (kind == 1)
            {
                items.Add(new(20 + i, data.Slice(i++, 1), new TcpOptionValue.NoOperation()));
                continue;
            }
            if (i + 2 > data.Length)
            {
                items.Add(new(20 + i, data[i..], BoundaryFailure(2, i)));
                break;
            }
            var length = data.Span[i + 1];
            if (length < 2)
            {
                items.Add(new(20 + i, data[i..], new TcpOptionValue.Invalid(TcpOptionFailure.InvalidLength, 2, length)));
                break;
            }
            if (i + length > data.Length)
            {
                items.Add(new(20 + i, data[i..], BoundaryFailure(length, i)));
                break;
            }
            var bytes = data.Span.Slice(i, length);
            TcpOptionValue value = kind switch
            {
                2 when length == 4 => new TcpOptionValue.MaximumSegmentSize(BinaryPrimitives.ReadUInt16BigEndian(bytes[2..])),
                3 when length == 3 => new TcpOptionValue.WindowScale(bytes[2]),
                4 when length == 2 => new TcpOptionValue.SackPermitted(),
                5 when length >= 10 && (length - 2) % 8 == 0 => ReadSack(bytes[2..]),
                8 when length == 10 => new TcpOptionValue.Timestamp(BinaryPrimitives.ReadUInt32BigEndian(bytes[2..]),
                    BinaryPrimitives.ReadUInt32BigEndian(bytes[6..])),
                2 or 3 or 4 or 5 or 8 => new TcpOptionValue.Invalid(TcpOptionFailure.InvalidLength,
                    kind switch { 2 => 4, 3 => 3, 4 => 2, _ => 10 }, length),
                _ => new TcpOptionValue.Unknown()
            };
            items.Add(new(20 + i, data.Slice(i, length), value));
            i += length;
        }
        return new(data, items.ToImmutable(), ReadOnlyMemory<byte>.Empty);

        TcpOptionValue.Invalid BoundaryFailure(int required, int offset) => new(
            offset + required > declaredLength ? TcpOptionFailure.ExceedsHeader : TcpOptionFailure.CaptureTruncated,
            required, data.Length - offset);
    }

    private static TcpOptionValue.Sack ReadSack(ReadOnlySpan<byte> bytes)
    {
        var blocks = ImmutableArray.CreateBuilder<TcpSackBlock>(bytes.Length / 8);
        for (var i = 0; i < bytes.Length; i += 8)
            blocks.Add(new(BinaryPrimitives.ReadUInt32BigEndian(bytes[i..]), BinaryPrimitives.ReadUInt32BigEndian(bytes[(i + 4)..])));
        return new(blocks.MoveToImmutable());
    }
}
