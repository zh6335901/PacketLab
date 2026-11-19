using System.Buffers.Binary;
using System.Text;

namespace PacketLab.Testing;

internal static class PcapNgSamples
{
    internal static byte[] Section(bool big = false, long length = -1, byte[]? options = null, ushort minor = 0) =>
        Block(0x0a0d0d0a, [.. U32(0x1a2b3c4d, big), .. U16(1, big), .. U16(minor, big), .. I64(length, big), .. options ?? []], big);

    internal static byte[] Interface(bool big = false, ushort link = 1, uint snap = 0, byte[]? options = null) =>
        Block(1, [.. U16(link, big), 0, 0, .. U32(snap, big), .. options ?? []], big);

    internal static byte[] Packet(byte[] data, bool big = false, uint id = 0, ulong time = 1_123456,
        uint? original = null, byte[]? options = null, uint type = 6) =>
        Block(type, [.. U32(id, big), .. U32((uint)(time >> 32), big), .. U32((uint)time, big),
            .. U32((uint)data.Length, big), .. U32(original ?? (uint)data.Length, big), .. Pad(data), .. options ?? []], big);

    internal static byte[] Simple(byte[] data, uint original, bool big = false) =>
        Block(3, [.. U32(original, big), .. Pad(data)], big);

    internal static byte[] Block(uint type, byte[] body, bool big = false)
    {
        uint length = (uint)body.Length + 12;
        return [.. U32(type, big), .. U32(length, big), .. body, .. U32(length, big)];
    }

    internal static byte[] Option(ushort code, byte[] data, bool big = false) =>
        [.. U16(code, big), .. U16((ushort)data.Length, big), .. Pad(data)];

    internal static byte[] Text(ushort code, string text, bool big = false) => Option(code, Encoding.UTF8.GetBytes(text), big);

    internal static byte[] U16(ushort value, bool big = false)
    {
        var bytes = new byte[2];
        if (big) BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
        else BinaryPrimitives.WriteUInt16LittleEndian(bytes, value);
        return bytes;
    }

    internal static byte[] U32(uint value, bool big = false)
    {
        var bytes = new byte[4];
        if (big) BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
        else BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        return bytes;
    }

    internal static byte[] I64(long value, bool big = false)
    {
        var bytes = new byte[8];
        if (big) BinaryPrimitives.WriteInt64BigEndian(bytes, value);
        else BinaryPrimitives.WriteInt64LittleEndian(bytes, value);
        return bytes;
    }

    private static byte[] Pad(byte[] bytes) => [.. bytes, .. new byte[(4 - bytes.Length % 4) % 4]];
}
