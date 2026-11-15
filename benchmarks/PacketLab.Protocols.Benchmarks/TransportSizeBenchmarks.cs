using System.Buffers.Binary;
using BenchmarkDotNet.Attributes;
using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.Benchmarks;

[MemoryDiagnoser]
public class TransportSizeBenchmarks
{
    private ReadOnlyMemory<byte> tcp;
    private ReadOnlyMemory<byte> udp;
    private const ulong Addresses = 0x123456;

    [Params(0, 64, 256, 9000, 200008)]
    public int PayloadLength { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        tcp = CreatePacket(20, 6, 16);
        udp = CreatePacket(8, 17, 6);
        if (ParseTcp() is not TcpSegment { Checksum: TcpChecksumStatus.Match } ||
            ParseUdp() is not UdpDatagram { Checksum: UdpChecksumStatus.Match })
            throw new InvalidDataException("Expected valid transport checksums.");
    }

    [Benchmark]
    public TcpParseResult ParseTcp() => TcpParser.Parse(tcp, (uint)tcp.Length, Addresses);

    [Benchmark]
    public UdpParseResult ParseUdp() => UdpParser.Parse(udp, (uint)udp.Length, true, Addresses);

    private byte[] CreatePacket(int headerLength, byte protocol, int checksumOffset)
    {
        var bytes = new byte[headerLength + PayloadLength];
        if (protocol == 6) bytes[12] = 0x50;
        else BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4),
            bytes.Length > ushort.MaxValue ? (ushort)0 : (ushort)bytes.Length);
        for (int i = headerLength; i < bytes.Length; i++) bytes[i] = (byte)(i ^ (i >> 8));
        ulong sum = Addresses + protocol + (uint)(bytes.Length >> 16) + (uint)(bytes.Length & 0xffff);
        for (int i = 0; i < bytes.Length; i++) sum += (uint)bytes[i] << (i % 2 == 0 ? 8 : 0);
        while (sum > ushort.MaxValue) sum = (sum & 0xffff) + (sum >> 16);
        var checksum = (ushort)~sum;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(checksumOffset), checksum == 0 ? ushort.MaxValue : checksum);
        return bytes;
    }
}
