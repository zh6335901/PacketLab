using System.Buffers.Binary;
using System.Net;

namespace PacketLab.Protocols.IPv6;

public readonly record struct IPv6Address(ulong High, ulong Low)
{
    internal static IPv6Address Read(ReadOnlySpan<byte> bytes) =>
        new(BinaryPrimitives.ReadUInt64BigEndian(bytes), BinaryPrimitives.ReadUInt64BigEndian(bytes[8..]));

    public override string ToString()
    {
        Span<byte> bytes = stackalloc byte[16];
        BinaryPrimitives.WriteUInt64BigEndian(bytes, High);
        BinaryPrimitives.WriteUInt64BigEndian(bytes[8..], Low);
        return new IPAddress(bytes).ToString();
    }
}

public sealed record IPv6Header(byte Version, byte TrafficClass, uint FlowLabel, ushort PayloadLength,
    byte NextHeader, byte HopLimit, IPv6Address Source, IPv6Address Destination);

public union IPv6Payload(IPv6Payload.KnownLength, IPv6Payload.UndeterminedLength)
{
    public sealed record KnownLength(uint DeclaredLength, ReadOnlyMemory<byte> Bytes, ReadOnlyMemory<byte> TrailingBytes)
    {
        public ulong DeclaredDatagramLength => 40UL + DeclaredLength;
        public bool IsDatagramComplete => Bytes.Length == DeclaredLength;
    }

    // A missing or invalid Jumbo Payload option cannot establish a declared boundary.
    public sealed record UndeterminedLength(ReadOnlyMemory<byte> CapturedBytes);
}

public sealed record IPv6Packet(IPv6Header Header, IPv6Payload Payload, IPv6ExtensionChain Extensions);

public union IPv6ParseResult(IPv6Packet, IPv6ParseResult.IncompleteHeader, IPv6ParseResult.InvalidVersion)
{
    public sealed record IncompleteHeader(int RequiredLength, ReadOnlyMemory<byte> RemainingBytes)
    {
        public int CapturedLength => RemainingBytes.Length;
    }
    public sealed record InvalidVersion(byte Version, ReadOnlyMemory<byte> RemainingBytes);
}

public static class IPv6Parser
{
    public static IPv6ParseResult Parse(ReadOnlyMemory<byte> data)
    {
        if (data.Length < 40)
            return new IPv6ParseResult.IncompleteHeader(40, data);

        var bytes = data.Span;
        var fields = BinaryPrimitives.ReadUInt32BigEndian(bytes);
        var version = (byte)(fields >> 28);
        if (version != 6)
            return new IPv6ParseResult.InvalidVersion(version, data);

        var header = new IPv6Header(version, (byte)((fields >> 20) & 0xff), fields & 0xfffff,
            BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]), bytes[6], bytes[7],
            IPv6Address.Read(bytes[8..]), IPv6Address.Read(bytes[24..]));
        return IPv6ExtensionParser.Parse(header, data[40..]);
    }
}
