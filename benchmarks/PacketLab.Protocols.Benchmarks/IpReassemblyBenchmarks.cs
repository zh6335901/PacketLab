using System.Collections.Immutable;
using BenchmarkDotNet.Attributes;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
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

public enum FragmentSequence { IPv4Two, IPv4Sixteen, IPv4SixteenOutOfOrder, IPv6Two }

[MemoryDiagnoser]
public class IpReassemblyBenchmarks
{
    private ReadOnlyMemory<byte>[] fragments = null!;
    private IpFragmentReassembler reassembler = null!;

    [ParamsAllValues]
    public FragmentSequence Sequence { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        bool ipv6 = Sequence == FragmentSequence.IPv6Two;
        var udp = PacketSamples.Udp(2040, true, ipv6 ? PacketSamples.IPv6AddressSum : PacketSamples.IPv4AddressSum);
        int count = Sequence is FragmentSequence.IPv4Two or FragmentSequence.IPv6Two ? 2 : 16;
        int partLength = udp.Length / count;
        fragments = new ReadOnlyMemory<byte>[count];
        for (int i = 0; i < count; i++)
        {
            int offset = i * partLength;
            bool more = i < count - 1;
            var part = udp.AsSpan(offset, partLength);
            fragments[i] = ipv6 ? PacketSamples.IPv6Fragment(part, offset, more)
                : PacketSamples.IPv4(part, offset: offset, more: more);
        }
        if (Sequence == FragmentSequence.IPv4SixteenOutOfOrder)
        {
            var last = fragments[^1];
            Array.Copy(fragments, 1, fragments, 2, count - 2);
            fragments[1] = last;
        }

        using var probe = new IpFragmentReassembler();
        foreach (var fragment in fragments.AsSpan()[..^1])
        {
            if (probe.Process(fragment)?.Status != IpReassemblyStatus.Pending)
                throw new InvalidDataException("Expected pending reassembly until the last input.");
        }
        var complete = probe.Process(fragments[^1]);
        if (complete?.Status != IpReassemblyStatus.Complete || complete.Packet is not { } packet ||
            probe.IsRetained(complete.DatagramId))
            throw new InvalidDataException("Expected one completed and released datagram.");
        UdpParseResult parsed = packet.Decoding switch
        {
            IPv4DecodeResult v4 when !ipv6 && v4 is DecodedIPv4 decoded && decoded.Payload is UdpParseResult result => result,
            IPv6DecodeResult v6 when ipv6 && v6 is DecodedIPv6 decoded && decoded.Payload is UdpParseResult result => result,
            _ => throw new InvalidDataException("Expected a reassembled IP/UDP packet.")
        };
        if (parsed is not UdpDatagram datagram || datagram.Checksum is not UdpChecksumStatus.Match ||
            !datagram.Payload.Span.SequenceEqual(udp.AsSpan(8)))
            throw new InvalidDataException("UDP payload or checksum changed during reassembly.");
        reassembler = new();
    }

    [Benchmark]
    public IpReassemblyUpdate? CompleteDatagram()
    {
        IpReassemblyUpdate? update = null;
        foreach (var fragment in fragments)
            update = reassembler.Process(fragment);
        return update;
    }

    [GlobalCleanup]
    public void Close() => reassembler.Dispose();
}

[MemoryDiagnoser]
public class ReassemblyClockBenchmarks
{
    private IpFragmentReassembler reassembler = null!;

    [Params(0, 32)]
    public int PendingDatagrams { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        reassembler = new();
        var udp = PacketSamples.Udp(2040, true, PacketSamples.IPv4AddressSum);
        var ids = new HashSet<long>();
        for (int i = 0; i < PendingDatagrams; i++)
        {
            var first = PacketSamples.IPv4(udp.AsSpan(0, 1024), identification: i, more: true);
            if (reassembler.Process(first) is not { Status: IpReassemblyStatus.Pending } update ||
                !ids.Add(update.DatagramId))
                throw new InvalidDataException("Expected a distinct pending datagram for each first fragment.");
        }
        if (!AdvanceTime().IsEmpty || !ids.All(reassembler.IsRetained))
            throw new InvalidDataException("Expected the clock tick to preserve all pending datagrams.");
    }

    [Benchmark]
    public ImmutableArray<IpReassemblyUpdate> AdvanceTime() => reassembler.AdvanceTime(1_000_000);

    [GlobalCleanup]
    public void Close() => reassembler.Dispose();
}
