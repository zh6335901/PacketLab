using System.Buffers.Binary;
using PacketLab.Protocols.Tcp;

namespace PacketLab.Protocols.UnitTests.IP;

public class TransportChecksumTests
{
    public static IEnumerable<int> PayloadLengths() =>
        Enumerable.Range(0, 34).Concat([1400, 65515, 65516, 131073, 200008]);

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

    private static ushort Checksum(byte[] bytes, ulong sum)
    {
        for (int i = 0; i < bytes.Length; i++)
            sum += (uint)bytes[i] << (i % 2 == 0 ? 8 : 0);
        while (sum > ushort.MaxValue) sum = (sum & 0xffff) + (sum >> 16);
        return (ushort)~sum;
    }
}
