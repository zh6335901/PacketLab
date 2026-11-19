using System.Collections.Immutable;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Cli;

internal sealed class PacketInspection : IDisposable
{
    private IpReassemblyAnalyzer? reassembly;
    private ulong clock;

    internal void AdvanceTime(ulong? timestamp)
    {
        if (timestamp is not { } time)
            return;

        clock = Math.Max(clock, time);
        reassembly?.AdvanceTime(clock);
    }

    internal ImmutableArray<IpReassemblyEvent> Expire(long recordNumber) => reassembly?.Expire(recordNumber) ?? [];

    internal ImmutableArray<IpReassemblyEvent> AnalyzePacket(long recordNumber, ProtocolDecodeResult decoding) => decoding.Value switch
    {
        EthernetDecodeResult { Value: DecodedEthernet frame } => AnalyzeEthernet(recordNumber, frame),
        _ => []
    };

    private ImmutableArray<IpReassemblyEvent> AnalyzeEthernet(long recordNumber, DecodedEthernet frame) => frame.Payload.Value switch
    {
        IPv4DecodeResult { Value: DecodedIPv4 { Payload.Value: IPv4FragmentPayload fragment } packet } =>
            GetReassembly().AddIPv4Fragment(recordNumber, frame.Frame.RemainingBytes, packet, fragment),
        IPv6DecodeResult { Value: DecodedIPv6 packet } => AnalyzeIPv6(recordNumber, frame.Frame.RemainingBytes, packet),
        _ => []
    };

    private ImmutableArray<IpReassemblyEvent> AnalyzeIPv6(long recordNumber, ReadOnlyMemory<byte> bytes, DecodedIPv6 packet)
    {
        var extension = packet.Extensions.FirstOrDefault(static header => header.Fragment is not null);

        return extension is { Fragment: { } fragment } && packet.Capture is IPv6Payload.KnownLength
            ? GetReassembly().AddIPv6Fragment(recordNumber, bytes, packet, extension, fragment)
            : [];
    }

    private IpReassemblyAnalyzer GetReassembly() => reassembly ??= CreateReassemblyAt(clock);

    private static IpReassemblyAnalyzer CreateReassemblyAt(ulong timestamp)
    {
        var analyzer = new IpReassemblyAnalyzer();
        analyzer.AdvanceTime(timestamp);

        return analyzer;
    }

    internal ImmutableArray<IpReassemblyEvent> Finish(IpReassemblyAnalysisReason reason) => reassembly?.Finish(reason) ?? [];

    public void Dispose() => reassembly?.Dispose();
}
