using PacketLab.Protocols.Arp;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Protocols.Ethernet;

public union EthernetDecodeResult(DecodedEthernet, EthernetParseResult.IncompleteHeader,
    EthernetParseResult.Ieee8023Length, EthernetParseResult.InvalidLengthOrType);

public union EthernetPayloadResult(ArpParseResult, IPv4DecodeResult, IPv6DecodeResult, UnsupportedEtherType);

public sealed record UnsupportedEtherType(ushort EtherType, ReadOnlyMemory<byte> Bytes);

public sealed record DecodedEthernet
{
    public EthernetFrame Frame { get; }
    public EthernetPayloadResult Payload { get; }

    private DecodedEthernet(EthernetFrame frame)
    {
        Frame = frame;
        Payload = frame.EtherType switch
        {
            0x0806 => ArpParser.Parse(frame.RemainingBytes),
            0x0800 => DecodedIPv4.Decode(frame.RemainingBytes),
            0x86dd => DecodedIPv6.Decode(frame.RemainingBytes),
            _ => new UnsupportedEtherType(frame.EtherType, frame.RemainingBytes)
        };
    }

    public static EthernetDecodeResult Decode(ReadOnlyMemory<byte> data) => EthernetParser.Parse(data) switch
    {
        EthernetFrame frame => new DecodedEthernet(frame),
        EthernetParseResult.IncompleteHeader error => error,
        EthernetParseResult.Ieee8023Length unsupported => unsupported,
        EthernetParseResult.InvalidLengthOrType error => error,
        null => throw new InvalidOperationException("Uninitialized Ethernet parse result.")
    };
}
