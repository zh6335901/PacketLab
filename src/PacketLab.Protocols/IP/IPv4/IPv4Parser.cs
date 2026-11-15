using System.Buffers.Binary;
using System.Runtime.Intrinsics;

namespace PacketLab.Protocols.IP.IPv4;

public readonly record struct IPv4Address(byte Octet0, byte Octet1, byte Octet2, byte Octet3)
{
    internal static IPv4Address Read(ReadOnlySpan<byte> bytes) => new(bytes[0], bytes[1], bytes[2], bytes[3]);
    public override string ToString() => $"{Octet0}.{Octet1}.{Octet2}.{Octet3}";
}

public enum IPv4ChecksumStatus { Unavailable, Match, Mismatch }

public sealed record IPv4Header(byte Version, byte Ihl, byte Dscp, byte Ecn, ushort TotalLength,
    ushort Identification, byte Flags, ushort FragmentOffset, byte Ttl, byte Protocol,
    ushort HeaderChecksum, IPv4Address Source, IPv4Address Destination, ReadOnlyMemory<byte> Options)
{
    public int HeaderLength => Ihl * 4;
    public bool ReservedFlag => (Flags & 4) != 0;
    public bool DontFragment => (Flags & 2) != 0;
    public bool MoreFragments => (Flags & 1) != 0;
    public int FragmentOffsetBytes => FragmentOffset * 8;
}

public sealed record IPv4Packet(IPv4Header Header, IPv4ChecksumStatus ChecksumStatus,
    ReadOnlyMemory<byte> Payload, ReadOnlyMemory<byte> TrailingBytes)
{
    public int CapturedLength => Header.HeaderLength + Payload.Length + TrailingBytes.Length;
    public bool IsDatagramComplete => CapturedLength >= Header.TotalLength;
}

public union IPv4ParseResult(IPv4Packet, IPv4ParseResult.IncompleteHeader, IPv4ParseResult.InvalidVersion,
    IPv4ParseResult.InvalidHeaderLength, IPv4ParseResult.InvalidTotalLength)
{
    public IPv4ChecksumStatus ChecksumStatus => Value is IPv4Packet packet
        ? packet.ChecksumStatus : IPv4ChecksumStatus.Unavailable;

    public sealed record IncompleteHeader(int RequiredLength, ReadOnlyMemory<byte> RemainingBytes)
    {
        public int CapturedLength => RemainingBytes.Length;
    }
    public sealed record InvalidVersion(byte Version, ReadOnlyMemory<byte> RemainingBytes);
    public sealed record InvalidHeaderLength(byte Ihl, ReadOnlyMemory<byte> RemainingBytes);
    public sealed record InvalidTotalLength(ushort TotalLength, int HeaderLength, ReadOnlyMemory<byte> RemainingBytes);
}

public static class IPv4Parser
{
    public static IPv4ParseResult Parse(ReadOnlyMemory<byte> data)
    {
        if (data.Length < 20)
            return new IPv4ParseResult.IncompleteHeader(20, data);

        var bytes = data.Span;
        var version = (byte)(bytes[0] >> 4);
        if (version != 4)
            return new IPv4ParseResult.InvalidVersion(version, data);
        var ihl = (byte)(bytes[0] & 0x0f);
        if (ihl < 5)
            return new IPv4ParseResult.InvalidHeaderLength(ihl, data);
        var headerLength = ihl * 4;
        var totalLength = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
        if (totalLength < headerLength)
            return new IPv4ParseResult.InvalidTotalLength(totalLength, headerLength, data);
        if (data.Length < headerLength)
            return new IPv4ParseResult.IncompleteHeader(headerLength, data);

        var fragment = BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]);
        var header = new IPv4Header(
            Version: version,
            Ihl: ihl,
            Dscp: (byte)(bytes[1] >> 2),
            Ecn: (byte)(bytes[1] & 3),
            TotalLength: totalLength,
            Identification: BinaryPrimitives.ReadUInt16BigEndian(bytes[4..]),
            Flags: (byte)(fragment >> 13),
            FragmentOffset: (ushort)(fragment & 0x1fff),
            Ttl: bytes[8],
            Protocol: bytes[9],
            HeaderChecksum: BinaryPrimitives.ReadUInt16BigEndian(bytes[10..]),
            Source: IPv4Address.Read(bytes[12..]),
            Destination: IPv4Address.Read(bytes[16..]),
            Options: data[20..headerLength]);

        var capturedEnd = Math.Min(data.Length, totalLength);
        return new IPv4Packet(header, Checksum(bytes[..headerLength]),
            data[headerLength..capturedEnd], data[capturedEnd..]);
    }

    private static IPv4ChecksumStatus Checksum(ReadOnlySpan<byte> header)
    {
        uint sum = 0;
        if (Vector128.IsHardwareAccelerated)
        {
            var lanes = Vector128<uint>.Zero;
            while (header.Length >= 16)
            {
                var words = Vector128.Create(header).AsUInt32();
                lanes += (words & Vector128.Create(0xffffu)) + (words >> 16);
                header = header[16..];
            }
            // IPv4 headers are at most 60 bytes, so the lane and horizontal sums fit in uint.
            sum = Vector128.Sum(lanes);
            sum = (sum & 0xffff) + (sum >> 16);
            sum = (sum & 0xffff) + (sum >> 16);
            if (BitConverter.IsLittleEndian) sum = BinaryPrimitives.ReverseEndianness((ushort)sum);
        }
        for (var offset = 0; offset < header.Length; offset += 2)
            sum += BinaryPrimitives.ReadUInt16BigEndian(header[offset..]);
        while (sum > ushort.MaxValue)
            sum = (sum & 0xffff) + (sum >> 16);
        return sum == ushort.MaxValue ? IPv4ChecksumStatus.Match : IPv4ChecksumStatus.Mismatch;
    }
}
