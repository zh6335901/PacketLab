using System.Buffers.Binary;

namespace PacketLab.Protocols.Benchmarks;

internal static class PacketSamples
{
    private static readonly byte[] IPv4Addresses = Convert.FromHexString("C0000201C0000202");
    private static readonly byte[] IPv6Addresses =
        Convert.FromHexString("20010DB800000000000000000000000120010DB8000000000000000000000002");

    internal static readonly ulong IPv4AddressSum = SumWords(IPv4Addresses);
    internal static readonly ulong IPv6AddressSum = SumWords(IPv6Addresses);

    internal static byte[] ArpRequest() =>
        Convert.FromHexString("0001080006040001001122334455C0000201000000000000C0000202");

    internal static byte[] Ethernet(ushort etherType, byte[] payload)
    {
        var frame = new byte[14 + payload.Length];
        byte[] macs = etherType == 0x0806
            ? Convert.FromHexString("FFFFFFFFFFFF001122334455")
            : Convert.FromHexString("66778899AABB001122334455");
        macs.CopyTo(frame, 0);
        Write16(frame, 12, etherType);
        payload.CopyTo(frame, 14);
        return frame;
    }

    internal static byte[] Udp(int payloadLength, bool checksum, ulong addressSum)
    {
        var bytes = new byte[8 + payloadLength];
        Write16(bytes, 0, 12345);
        Write16(bytes, 2, 54321);
        Write16(bytes, 4, bytes.Length);
        FillPayload(bytes.AsSpan(8));
        if (checksum)
        {
            var value = Checksum(bytes, addressSum + 17 + (uint)bytes.Length);
            Write16(bytes, 6, value == 0 ? ushort.MaxValue : value);
        }
        return bytes;
    }

    internal static byte[] Tcp(int segmentLength, bool timestamp)
    {
        var bytes = new byte[segmentLength];
        var headerLength = timestamp ? 32 : 20;
        Write16(bytes, 0, 12345);
        Write16(bytes, 2, 443);
        bytes[12] = (byte)(headerLength / 4 << 4);
        bytes[13] = 0x10;
        Write16(bytes, 14, 8192);
        if (timestamp) Convert.FromHexString("0101080A0000000100000002").CopyTo(bytes, 20);
        FillPayload(bytes.AsSpan(headerLength));
        Write16(bytes, 16, Checksum(bytes, IPv4AddressSum + 6 + (uint)bytes.Length));
        return bytes;
    }

    internal static byte[] IPv4(ReadOnlySpan<byte> payload, bool options = false,
        int identification = 1, int offset = 0, bool more = false)
    {
        int headerLength = options ? 32 : 20;
        var packet = new byte[headerLength + payload.Length];
        packet[0] = (byte)(0x40 | headerLength / 4);
        Write16(packet, 2, packet.Length);
        Write16(packet, 4, identification);
        Write16(packet, 6, offset / 8 | (more ? 0x2000 : 0));
        packet[8] = 64;
        packet[9] = 17;
        IPv4Addresses.CopyTo(packet, 12);
        if (options) packet.AsSpan(20, 12).Fill(1); // Twelve one-byte NOP options.
        Write16(packet, 10, Checksum(packet.AsSpan(0, headerLength)));
        payload.CopyTo(packet.AsSpan(headerLength));
        return packet;
    }

    internal static byte[] IPv6(ReadOnlySpan<byte> payload, byte nextHeader)
    {
        var packet = new byte[40 + payload.Length];
        packet[0] = 0x60;
        Write16(packet, 4, payload.Length);
        packet[6] = nextHeader;
        packet[7] = 64;
        IPv6Addresses.CopyTo(packet, 8);
        payload.CopyTo(packet.AsSpan(40));
        return packet;
    }

    internal static byte[] IPv6WithExtensions(byte[] udp)
    {
        var payload = new byte[16 + udp.Length];
        payload[0] = 60; // Hop-by-Hop followed by Destination Options; both use Pad1.
        payload[8] = 17;
        udp.CopyTo(payload, 16);
        return IPv6(payload, 0);
    }

    internal static byte[] IPv6Fragment(ReadOnlySpan<byte> data, int offset, bool more)
    {
        var payload = new byte[8 + data.Length];
        payload[0] = 17;
        Write16(payload, 2, offset | (more ? 1 : 0));
        BinaryPrimitives.WriteUInt32BigEndian(payload.AsSpan(4), 1);
        data.CopyTo(payload.AsSpan(8));
        return IPv6(payload, 44);
    }

    private static void FillPayload(Span<byte> payload)
    {
        for (int i = 0; i < payload.Length; i++)
            payload[i] = (byte)(i ^ (i >> 8));
    }

    private static void Write16(byte[] bytes, int offset, int value) =>
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(offset), checked((ushort)value));

    private static ulong SumWords(ReadOnlySpan<byte> bytes)
    {
        ulong sum = 0;
        for (int i = 0; i < bytes.Length; i++)
            sum += (uint)(i % 2 == 0 ? bytes[i] << 8 : bytes[i]);
        return sum;
    }

    private static ushort Checksum(ReadOnlySpan<byte> bytes, ulong initial = 0)
    {
        ulong sum = initial + SumWords(bytes);
        while (sum > ushort.MaxValue) sum = (sum & 0xffff) + (sum >> 16);
        return (ushort)~sum;
    }
}
