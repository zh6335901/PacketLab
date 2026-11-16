using System.Buffers.Binary;

namespace PacketLab.Protocols.Arp;

public sealed record ArpPacket(ushort HardwareType, ushort ProtocolType, byte HardwareAddressLength,
    byte ProtocolAddressLength, ushort Operation, ReadOnlyMemory<byte> SenderHardwareAddress,
    ReadOnlyMemory<byte> SenderProtocolAddress, ReadOnlyMemory<byte> TargetHardwareAddress,
    ReadOnlyMemory<byte> TargetProtocolAddress, ReadOnlyMemory<byte> RemainingBytes);

public union ArpParseResult(ArpPacket, ArpParseResult.IncompleteHeader)
{
    public sealed record IncompleteHeader(int RequiredLength, ReadOnlyMemory<byte> RemainingBytes)
    {
        public int CapturedLength => RemainingBytes.Length;
    }
}

public static class ArpParser
{
    public static ArpParseResult Parse(ReadOnlyMemory<byte> data)
    {
        if (data.Length < 8)
            return new ArpParseResult.IncompleteHeader(8, data);

        var bytes = data.Span;
        var hardwareLength = bytes[4];
        var protocolLength = bytes[5];
        var length = 8 + 2 * hardwareLength + 2 * protocolLength;
        if (data.Length < length)
            return new ArpParseResult.IncompleteHeader(length, data);

        var senderProtocolOffset = 8 + hardwareLength;
        var targetHardwareOffset = senderProtocolOffset + protocolLength;
        var targetProtocolOffset = targetHardwareOffset + hardwareLength;

        return new ArpPacket(
            HardwareType: BinaryPrimitives.ReadUInt16BigEndian(bytes),
            ProtocolType: BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]),
            HardwareAddressLength: hardwareLength,
            ProtocolAddressLength: protocolLength,
            Operation: BinaryPrimitives.ReadUInt16BigEndian(bytes[6..]),
            SenderHardwareAddress: data.Slice(8, hardwareLength),
            SenderProtocolAddress: data.Slice(senderProtocolOffset, protocolLength),
            TargetHardwareAddress: data.Slice(targetHardwareOffset, hardwareLength),
            TargetProtocolAddress: data.Slice(targetProtocolOffset, protocolLength),
            RemainingBytes: data[length..]);
    }
}
