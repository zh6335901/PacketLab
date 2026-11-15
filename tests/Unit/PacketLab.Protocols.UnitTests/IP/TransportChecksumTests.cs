using System.Buffers.Binary;
using FsCheck;
using FsCheck.Fluent;
using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.UnitTests.IP;

public class TransportChecksumTests
{
    private const ulong Addresses = 0x123456;

    [Test]
    public void Valid_tcp_checksums_match_for_varied_payloads_and_memory_offsets() =>
        Prop.ForAll(ChecksumInputs(), input =>
        {
            // Arrange
            var packet = PayloadSlice(20, input.Length, input.Offset, input.Seed);
            packet.Span[12] = 0x50;
            var length = (uint)packet.Length;
            BinaryPrimitives.WriteUInt16BigEndian(packet.Span[16..],
                Checksum(packet.Span, Addresses + 6 + (length >> 16) + (length & 0xffff)));

            // Act
            var parsed = TcpParser.Parse(packet, length, Addresses);

            // Assert
            return parsed.Checksum.Value is TcpChecksumStatus.Match;
        }).Check(Config.QuickThrowOnFailure.WithMaxTest(300));

    [Test]
    public void Valid_udp_checksums_match_for_varied_payloads_and_memory_offsets() =>
        Prop.ForAll(ChecksumInputs(), input =>
        {
            // Arrange
            var packet = PayloadSlice(8, input.Length, input.Offset, input.Seed);
            var length = (uint)packet.Length;
            bool jumbo = length > ushort.MaxValue;
            BinaryPrimitives.WriteUInt16BigEndian(packet.Span[4..], jumbo ? (ushort)0 : (ushort)length);
            var checksum = Checksum(packet.Span, Addresses + 17 + (length >> 16) + (length & 0xffff));
            BinaryPrimitives.WriteUInt16BigEndian(packet.Span[6..], checksum == 0 ? ushort.MaxValue : checksum);

            // Act
            var parsed = UdpParser.Parse(packet, length, jumbo, Addresses);

            // Assert
            return parsed.Checksum.Value is UdpChecksumStatus.Match;
        }).Check(Config.QuickThrowOnFailure.WithMaxTest(300));

    private static Arbitrary<(int Length, int Offset, int Seed)> ChecksumInputs() =>
        Arb.From(
            from length in Gen.OneOf(Gen.Choose(0, 1500), Gen.Choose(1501, 65535), Gen.Choose(65536, 200008))
            from offset in Gen.Choose(0, 255)
            from seed in Gen.Choose(0, int.MaxValue)
            select (length, offset, seed));

    private static Memory<byte> PayloadSlice(int headerLength, int payloadLength, int offset, int seed)
    {
        var storage = new byte[offset + headerLength + payloadLength];
        var packet = storage.AsMemory(offset);
        new Random(seed).NextBytes(packet.Span[headerLength..]);
        return packet;
    }

    private static ushort Checksum(ReadOnlySpan<byte> bytes, ulong sum)
    {
        for (int i = 0; i < bytes.Length; i++)
            sum += (uint)bytes[i] << (i % 2 == 0 ? 8 : 0);
        while (sum > ushort.MaxValue) sum = (sum & 0xffff) + (sum >> 16);
        return (ushort)~sum;
    }
}
