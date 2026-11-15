using System.Buffers.Binary;
using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.UnitTests.IP;

public class TransportChecksumTests
{
#pragma warning disable PL0003 // All lengths and offsets verify the same checksum/oracle invariant.
    [Test]
    [Arguments(0)]
    [Arguments(1)]
    [Arguments(15)]
    [Arguments(31)]
    public async Task Checksums_match_the_bytewise_oracle_across_vector_boundaries_and_offsets(int offset)
    {
        const ulong addresses = 0x123456;
        var lengths = Enumerable.Range(40, 140).Concat([255, 256, 257, 65515, 65516, 65517,
            65527, 65528, 65529, 131059, 131060, 131061, 131071, 131072, 131073, 200008]);
        foreach (int payloadLength in lengths)
        foreach (byte protocol in new byte[] { 6, 17 })
        {
            int headerLength = protocol == 6 ? 20 : 8;
            var storage = new byte[offset + headerLength + payloadLength];
            var packet = storage.AsMemory(offset);
            for (int i = headerLength; i < packet.Length; i++) packet.Span[i] = (byte)(i ^ (i >> 8));
            uint length = (uint)packet.Length;
            if (protocol == 6) packet.Span[12] = 0x50;
            else BinaryPrimitives.WriteUInt16BigEndian(packet.Span[4..], length > ushort.MaxValue ? (ushort)0 : (ushort)length);
            var checksum = Checksum(packet.Span, addresses + protocol + (length >> 16) + (length & 0xffff));
            BinaryPrimitives.WriteUInt16BigEndian(packet.Span[(protocol == 6 ? 16 : 6)..],
                checksum == 0 ? ushort.MaxValue : checksum);
            if (protocol == 6)
            {
                await Assert.That(TcpParser.Parse(packet, length, addresses).Checksum.Value).IsEqualTo(TcpChecksumStatus.Match);
                packet.Span[^1] ^= 1;
                await Assert.That(TcpParser.Parse(packet, length, addresses).Checksum.Value).IsEqualTo(TcpChecksumStatus.Mismatch);
            }
            else
            {
                await Assert.That(UdpParser.Parse(packet, length, true, addresses).Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
                packet.Span[^1] ^= 1;
                await Assert.That(UdpParser.Parse(packet, length, true, addresses).Checksum.Value).IsEqualTo(UdpChecksumStatus.Mismatch);
            }
        }
    }

#pragma warning restore PL0003

    public static IEnumerable<int> PayloadLengths() =>
        Enumerable.Range(0, 34).Concat([1400, 65515, 65516, 65527, 65528, 131073, 200008]);

    [Test]
    [MethodDataSource(nameof(PayloadLengths))]
    public async Task Tcp_checksum_handles_word_tails_and_large_carry_sums(int payloadLength)
    {
        const ulong addresses = 0x123456;
        var bytes = new byte[20 + payloadLength];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[12] = 0x50;
        bytes.AsSpan(20).Fill(0xff);
        var length = (uint)bytes.Length;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(16),
            Checksum(bytes, addresses + 6 + (length >> 16) + (length & 0xffff)));

        var parsed = TcpParser.Parse(bytes, length, addresses);
        await Assert.That(parsed.Checksum.Value).IsEqualTo(TcpChecksumStatus.Match);
        bytes[^1] ^= 1;
        await Assert.That(TcpParser.Parse(bytes, length, addresses).Checksum.Value).IsEqualTo(TcpChecksumStatus.Mismatch);
    }

    [Test]
    [MethodDataSource(nameof(PayloadLengths))]
    public async Task Udp_checksum_handles_word_tails_and_large_carry_sums(int payloadLength)
    {
        const ulong addresses = 0x123456;
        var bytes = new byte[8 + payloadLength];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes.AsSpan(8).Fill(0xff);
        var length = (uint)bytes.Length;
        bool jumbo = length > ushort.MaxValue;
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), jumbo ? (ushort)0 : (ushort)length);
        var checksum = Checksum(bytes, addresses + 17 + (length >> 16) + (length & 0xffff));
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), checksum == 0 ? ushort.MaxValue : checksum);

        var parsed = UdpParser.Parse(bytes, length, jumbo, addresses);
        await Assert.That(parsed.Checksum.Value).IsEqualTo(UdpChecksumStatus.Match);
        bytes[0] ^= 1;
        await Assert.That(UdpParser.Parse(bytes, length, jumbo, addresses).Checksum.Value).IsEqualTo(UdpChecksumStatus.Mismatch);
    }

    private static ushort Checksum(ReadOnlySpan<byte> bytes, ulong sum)
    {
        for (int i = 0; i < bytes.Length; i++)
            sum += (uint)bytes[i] << (i % 2 == 0 ? 8 : 0);
        while (sum > ushort.MaxValue) sum = (sum & 0xffff) + (sum >> 16);
        return (ushort)~sum;
    }
}
