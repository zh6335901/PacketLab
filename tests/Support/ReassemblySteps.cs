using System.Collections.Immutable;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Testing;

internal static class ReassemblySteps
{
    internal static ImmutableArray<IpReassemblyEvent> Process(IpReassemblyAnalyzer analyzer, long record,
        ulong? timestamp, ProtocolDecodeResult decoding)
    {
        if (timestamp is { } time)
            analyzer.AdvanceTime(time);
        var expired = analyzer.Expire(record);

        return expired.AddRange(Add(analyzer, record, decoding));
    }

    internal static ImmutableArray<IpReassemblyEvent> Add(IpReassemblyAnalyzer analyzer, long record, ProtocolDecodeResult decoding) => decoding.Value switch
    {
        EthernetDecodeResult { Value: DecodedEthernet frame } => AddEthernet(analyzer, record, frame),
        _ => []
    };

    private static ImmutableArray<IpReassemblyEvent> AddEthernet(IpReassemblyAnalyzer analyzer, long record, DecodedEthernet frame) => frame.Payload.Value switch
    {
        IPv4DecodeResult { Value: DecodedIPv4 { Payload.Value: IPv4FragmentPayload fragment } packet } =>
            analyzer.AddIPv4Fragment(record, frame.Frame.RemainingBytes, packet, fragment),
        IPv6DecodeResult { Value: DecodedIPv6 packet } => AddIPv6(analyzer, record, frame.Frame.RemainingBytes, packet),
        _ => []
    };

    private static ImmutableArray<IpReassemblyEvent> AddIPv6(IpReassemblyAnalyzer analyzer, long record,
        ReadOnlyMemory<byte> bytes, DecodedIPv6 packet)
    {
        var extension = packet.Extensions.FirstOrDefault(static header => header.Fragment is not null);

        return extension is { Fragment: { } fragment } && packet.Capture is IPv6Payload.KnownLength
            ? analyzer.AddIPv6Fragment(record, bytes, packet, extension, fragment) : [];
    }
}
