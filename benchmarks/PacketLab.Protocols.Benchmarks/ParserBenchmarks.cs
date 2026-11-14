using BenchmarkDotNet.Attributes;
using PacketLab.Protocols.Arp;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.Tcp;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.Benchmarks;

[MemoryDiagnoser]
public class LinkLayerBenchmarks
{
    private ReadOnlyMemory<byte> frame;
    private ReadOnlyMemory<byte> arp;

    [GlobalSetup]
    public void Prepare()
    {
        frame = PacketSamples.Ethernet(0x0806, PacketSamples.ArpRequest());
        arp = frame[14..];
        if (ParseEthernet() is not EthernetFrame { EtherType: 0x0806, RemainingBytes.Length: 28 } ||
            ParseArp() is not ArpPacket { Operation: 1, HardwareAddressLength: 6, ProtocolAddressLength: 4 })
            throw new InvalidDataException("Expected an Ethernet II frame containing an IPv4 ARP request.");
    }

    [Benchmark]
    public EthernetParseResult ParseEthernet() => EthernetParser.Parse(frame);

    [Benchmark]
    public ArpParseResult ParseArp() => ArpParser.Parse(arp);
}

[MemoryDiagnoser]
public class IPv4ParserBenchmarks
{
    private ReadOnlyMemory<byte> packet;

    [Params(20, 32)]
    public int HeaderLength { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        var udp = PacketSamples.Udp(32, true, PacketSamples.IPv4AddressSum);
        packet = PacketSamples.IPv4(udp, options: HeaderLength == 32);
        if (Parse() is not IPv4Packet { ChecksumStatus: IPv4ChecksumStatus.Match } parsed ||
            parsed.Header.HeaderLength != HeaderLength || !parsed.Payload.Span.SequenceEqual(udp))
            throw new InvalidDataException("Unexpected IPv4 header or payload.");
    }

    [Benchmark]
    public IPv4ParseResult Parse() => IPv4Parser.Parse(packet);
}

[MemoryDiagnoser]
public class IPv6ParserBenchmarks
{
    private ReadOnlyMemory<byte> packet;

    [Params(false, true)]
    public bool WithExtensions { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        var udp = PacketSamples.Udp(32, true, PacketSamples.IPv6AddressSum);
        packet = WithExtensions ? PacketSamples.IPv6WithExtensions(udp) : PacketSamples.IPv6(udp, 17);
        if (Parse() is not IPv6Packet parsed || !parsed.Extensions.Diagnostics.IsEmpty ||
            parsed.Extensions.Headers.Length != (WithExtensions ? 2 : 0) ||
            parsed.Extensions.Result is not IPv6UpperLayer { Protocol: 17 } upper ||
            !upper.Bytes.Span.SequenceEqual(udp))
            throw new InvalidDataException("Expected the IPv6 chain to end at the UDP datagram.");
    }

    [Benchmark]
    public IPv6ParseResult Parse() => IPv6Parser.Parse(packet);
}

[MemoryDiagnoser]
public class UdpParserBenchmarks
{
    private ReadOnlyMemory<byte> datagram;

    [Params(32, 1400)]
    public int PayloadLength { get; set; }

    [Params(false, true)]
    public bool WithChecksum { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        datagram = PacketSamples.Udp(PayloadLength, WithChecksum, PacketSamples.IPv4AddressSum);
        var expected = WithChecksum ? UdpChecksumStatus.Match : UdpChecksumStatus.NotPresent;
        if (Parse() is not UdpDatagram { IsComplete: true } udp || udp.Payload.Length != PayloadLength ||
            udp.Checksum is not UdpChecksumStatus status || status != expected)
            throw new InvalidDataException("Unexpected UDP payload or checksum.");
    }

    [Benchmark]
    public UdpParseResult Parse() =>
        UdpParser.Parse(datagram, (uint)datagram.Length, false, PacketSamples.IPv4AddressSum);
}

public enum TcpSample { Short, ShortWithTimestamp, Long }

[MemoryDiagnoser]
public class TcpParserBenchmarks
{
    private ReadOnlyMemory<byte> segment;

    [ParamsAllValues]
    public TcpSample Sample { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        bool timestamp = Sample == TcpSample.ShortWithTimestamp;
        segment = PacketSamples.Tcp(Sample == TcpSample.Long ? 1440 : 128, timestamp);
        if (Parse() is not TcpSegment { IsComplete: true } tcp || tcp.Checksum is not TcpChecksumStatus.Match ||
            tcp.Header.HeaderLength != (timestamp ? 32 : 20))
            throw new InvalidDataException("Unexpected TCP header or checksum.");
        if (timestamp && tcp.Options.Items is not [{ Kind: 1 }, { Kind: 1 }, { Value: TcpOptionValue.Timestamp }])
            throw new InvalidDataException("Expected two NOP options followed by a timestamp.");
        if (!timestamp && !tcp.Options.Items.IsEmpty)
            throw new InvalidDataException("Expected a TCP segment without options.");
    }

    [Benchmark]
    public TcpParseResult Parse() => TcpParser.Parse(segment, (uint)segment.Length, PacketSamples.IPv4AddressSum);
}
