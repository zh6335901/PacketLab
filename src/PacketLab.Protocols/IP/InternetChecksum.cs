using System.Buffers.Binary;
using System.Runtime.Intrinsics;

namespace PacketLab.Protocols.IP;

internal static class InternetChecksum
{
    internal static bool IsValid(ReadOnlySpan<byte> bytes, ulong sum)
        => Vector256.IsHardwareAccelerated && bytes.Length >= 64
            ? IsValidVectorized(bytes, sum) : IsValidScalar(bytes, sum);

    private static bool IsValidScalar(ReadOnlySpan<byte> bytes, ulong sum)
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
        if (!bytes.IsEmpty)
            sum += (uint)bytes[0] << 8;
        while (sum > ushort.MaxValue)
            sum = (sum & 0xffff) + (sum >> 16);

        return sum == ushort.MaxValue;
    }

    private static bool IsValidVectorized(ReadOnlySpan<byte> bytes, ulong sum)
    {
        while (bytes.Length >= 32)
        {
            // Bound each horizontal sum: 65536 / 2 * 65535 fits in uint.
            int length = Math.Min(bytes.Length & ~31, 65536);
            var block = bytes[..length];
            bytes = bytes[length..];
            var lanes = Vector256<uint>.Zero;
            while (block.Length >= 32)
            {
                var words = Vector256.Create(block).AsUInt32();
                lanes += (words & Vector256.Create(0xffffu)) + (words >> 16);
                block = block[32..];
            }
            uint partial = Vector256.Sum(lanes);
            partial = (partial & 0xffff) + (partial >> 16);
            partial = (partial & 0xffff) + (partial >> 16);
            // Folding first lets us fix network byte order once per block, not per word.
            sum += BitConverter.IsLittleEndian ? BinaryPrimitives.ReverseEndianness((ushort)partial) : partial;
        }

        return IsValidScalar(bytes, sum);
    }
}
