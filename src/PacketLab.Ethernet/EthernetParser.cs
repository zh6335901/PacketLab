using System.Buffers.Binary;

namespace PacketLab.Ethernet;

public readonly record struct MacAddress(byte Octet0, byte Octet1, byte Octet2, byte Octet3, byte Octet4, byte Octet5)
{
    internal static MacAddress Read(ReadOnlySpan<byte> bytes) =>
        new(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);

    public override string ToString() => $"{Octet0:X2}:{Octet1:X2}:{Octet2:X2}:{Octet3:X2}:{Octet4:X2}:{Octet5:X2}";
}

public sealed record EthernetFrame(MacAddress Destination, MacAddress Source, ushort EtherType, ReadOnlyMemory<byte> RemainingBytes);

public union EthernetParseResult(EthernetFrame, EthernetParseResult.IncompleteHeader,
    EthernetParseResult.Ieee8023Length, EthernetParseResult.InvalidLengthOrType)
{
    public sealed record IncompleteHeader(int CapturedLength);
    public sealed record Ieee8023Length(ushort Length);
    public sealed record InvalidLengthOrType(ushort Value);
}

public static class EthernetParser
{
    public static EthernetParseResult Parse(ReadOnlyMemory<byte> data)
    {
        const int headerLength = 14;
        if (data.Length < headerLength)
            return new EthernetParseResult.IncompleteHeader(data.Length);

        var bytes = data.Span;
        var field = BinaryPrimitives.ReadUInt16BigEndian(bytes[12..]);
        return field switch
        {
            <= 1500 => new EthernetParseResult.Ieee8023Length(field),
            < 0x0600 => new EthernetParseResult.InvalidLengthOrType(field),
            _ => new EthernetFrame(MacAddress.Read(bytes), MacAddress.Read(bytes[6..]), field, data[headerLength..])
        };
    }
}
