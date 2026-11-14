using BenchmarkDotNet.Attributes;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.Benchmarks;

[MemoryDiagnoser]
public class UnfragmentedPacketBenchmarks
{
    private ReadOnlyMemory<byte> frame;
    private ReadOnlyMemory<byte> ip;
    private IpFragmentReassembler reassembler = null!;

    [GlobalSetup]
    public void Prepare()
    {
        var udp = PacketSamples.Udp(1400, true, PacketSamples.IPv4AddressSum);
        frame = PacketSamples.Ethernet(0x0800, PacketSamples.IPv4(udp));
        ip = frame[14..];
        reassembler = new();
        if (DecodeFrame() is not EthernetDecodeResult ethernet || ethernet is not DecodedEthernet decoded ||
            decoded.Payload is not IPv4DecodeResult ipv4 || ipv4 is not DecodedIPv4 packet ||
            packet.Payload is not UdpParseResult result || result is not UdpDatagram datagram ||
            datagram.Checksum is not UdpChecksumStatus.Match || !datagram.Payload.Span.SequenceEqual(udp.AsSpan(8)))
            throw new InvalidDataException("Expected the Ethernet frame to decode through IPv4 to UDP.");
        if (ProbeReassembly() != (null, null))
            throw new InvalidDataException("An unfragmented packet unexpectedly entered reassembly.");
    }

    [Benchmark]
    public ProtocolDecodeResult DecodeFrame() => ProtocolDecoder.Decode(frame, LinkLayerProtocol.Ethernet);

    [Benchmark]
    public (long? ExistingId, IpReassemblyUpdate? Update) ProbeReassembly() =>
        (reassembler.FindDatagram(ip), reassembler.Process(ip));

    [GlobalCleanup]
    public void Close() => reassembler.Dispose();
}
