using System.Buffers.Binary;

namespace PacketLab.Protocols.IP;

internal static class InternetChecksum
{
    internal static bool IsValid(ReadOnlySpan<byte> bytes, ulong sum)
    {
        while (bytes.Length >= 4)
        {
            var pair = BinaryPrimitives.ReadUInt32BigEndian(bytes);
            sum += (pair >> 16) + (pair & 0xffff);
            bytes = bytes[4..];
        }
        if (bytes.Length >= 2)
        {
            sum += BinaryPrimitives.ReadUInt16BigEndian(bytes);
            bytes = bytes[2..];
        }
        if (!bytes.IsEmpty) sum += (uint)bytes[0] << 8;
        while (sum > ushort.MaxValue) sum = (sum & 0xffff) + (sum >> 16);
        return sum == ushort.MaxValue;
    }
}
