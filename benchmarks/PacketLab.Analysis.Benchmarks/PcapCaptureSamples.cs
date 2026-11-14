namespace PacketLab.Analysis.Benchmarks;

internal static class PcapCaptureSamples
{
    internal const int PacketCount = 4096;
    internal const int EthernetHeaderLength = 14;

    internal static MemoryStream Ethernet(int frameSize)
    {
        var frame = new byte[frameSize];
        // An unrecognized EtherType keeps this workload focused on Ethernet decoding.
        Convert.FromHexString("00112233445566778899AABBABCD").CopyTo(frame, 0);
        frame.AsSpan(EthernetHeaderLength).Fill(0x5a);
        return Create(frame);
    }

    internal static MemoryStream IPv4Udp()
    {
        var frame = new byte[1500];
        // The encoded UDP checksum assumes a payload of 1458 bytes of 0x5a.
        var headers = Convert.FromHexString("00112233445566778899AABB0800" +
            "450005CE000140004011B11AC0000201C0000202" + "3039D43105BA20C0");
        headers.CopyTo(frame, 0);
        frame.AsSpan(headers.Length).Fill(0x5a);
        return Create(frame);
    }

    private static MemoryStream Create(byte[] frame)
    {
        using var bytes = new MemoryStream(24 + PacketCount * (16 + frame.Length));
        using var writer = new BinaryWriter(bytes);
        writer.Write(0xa1b2c3d4u);
        writer.Write((ushort)2);
        writer.Write((ushort)4);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(65535u);
        writer.Write(1u);
        for (int i = 0; i < PacketCount; i++)
        {
            writer.Write(0u);
            writer.Write((uint)i);
            writer.Write((uint)frame.Length);
            writer.Write((uint)frame.Length);
            writer.Write(frame);
        }
        return new MemoryStream(bytes.GetBuffer(), 0, (int)bytes.Length, writable: false);
    }
}
