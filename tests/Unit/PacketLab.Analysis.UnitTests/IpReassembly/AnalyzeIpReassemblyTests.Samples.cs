using System.Buffers.Binary;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Analysis.UnitTests.IpReassembly;

public partial class AnalyzeIpReassemblyTests
{
    private static readonly byte[] Payload = Convert.FromHexString("04D20035001800000102030405060708090A0B0C0D0E0F10");

    private static (ReadOnlyMemory<byte> Bytes, DecodedIPv4 Packet, IPv4FragmentPayload Payload) IPv4Fragment(
        int offset, bool more, byte[] payload, ushort id = 1)
    {
        byte[] bytes = [.. Convert.FromHexString("4500000000000000401100000A0000000B000000"), .. payload];
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(2), (ushort)bytes.Length);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), id);
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(6), (ushort)(offset / 8 | (more ? 0x2000 : 0)));
        var packet = DecodedIPv4.Decode(bytes) is DecodedIPv4 parsed ? parsed : throw new InvalidOperationException();
        var fragment = packet.Payload is IPv4FragmentPayload value ? value : throw new InvalidOperationException();

        return (bytes, packet, fragment);
    }

    private static (ReadOnlyMemory<byte> Bytes, DecodedIPv6 Packet, IPv6ExtensionHeader Extension, IPv6Fragment Fragment) IPv6Fragment(
        int offset, bool more, byte[] payload)
    {
        byte[] bytes = [.. Convert.FromHexString("6000000000002C4000000000000000000000000000000001000000000000000000000000000000021100000000000001"), .. payload];
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(4), (ushort)(8 + payload.Length));
        BinaryPrimitives.WriteUInt16BigEndian(bytes.AsSpan(42), (ushort)(offset | (more ? 1 : 0)));
        var packet = DecodedIPv6.Decode(bytes) is DecodedIPv6 parsed ? parsed : throw new InvalidOperationException();
        var extension = packet.Extensions.Single();

        return (bytes, packet, extension, extension.Fragment!);
    }
}
