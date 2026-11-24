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

    [Params(20, 32, 60)]
    public int HeaderLength { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        var udp = PacketSamples.Udp(32, true, PacketSamples.IPv4AddressSum, ipv6: false);
        packet = PacketSamples.IPv4(udp, optionBytes: HeaderLength - 20, identification: 1, offset: 0, more: false);
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
        var udp = PacketSamples.Udp(32, true, PacketSamples.IPv6AddressSum, ipv6: false);
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
    private bool ipv6;
    private ulong addressSum;

    [Params(0, 32, 64, 256, 1400, 9000, 200008)]
    public int PayloadLength { get; set; }

    [Params(false, true)]
    public bool WithChecksum { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        ipv6 = PayloadLength + 8 > ushort.MaxValue;
        addressSum = ipv6 ? PacketSamples.IPv6AddressSum : PacketSamples.IPv4AddressSum;
        datagram = PacketSamples.Udp(PayloadLength, WithChecksum, addressSum, ipv6);
        var expected = (WithChecksum, ipv6) switch
        {
            (true, _) => UdpChecksumStatus.Match,
            (false, true) => UdpChecksumStatus.ZeroNotAllowed,
            (false, false) => UdpChecksumStatus.NotPresent
        };
        if (Parse() is not UdpDatagram { IsComplete: true } udp || udp.Payload.Length != PayloadLength ||
            udp.Checksum is not UdpChecksumStatus status || status != expected)
            throw new InvalidDataException("Unexpected UDP payload or checksum.");
    }

    [Benchmark]
    public UdpParseResult Parse() =>
        UdpParser.Parse(datagram, (uint)datagram.Length, ipv6, addressSum);
}

[MemoryDiagnoser]
public class TcpParserBenchmarks
{
    private ReadOnlyMemory<byte> segment;

    [Params(0, 64, 96, 108, 256, 1420, 9000, 200008)]
    public int PayloadLength { get; set; }

    [Params(false, true)]
    public bool WithTimestamp { get; set; }

    [GlobalSetup]
    public void Prepare()
    {
        int headerLength = WithTimestamp ? 32 : 20;
        segment = PacketSamples.Tcp(PayloadLength + headerLength, WithTimestamp);
        if (Parse() is not TcpSegment { IsComplete: true } tcp || tcp.Checksum is not TcpChecksumStatus.Match ||
            tcp.Header.HeaderLength != headerLength || tcp.Payload.Length != PayloadLength)
            throw new InvalidDataException("Unexpected TCP header or checksum.");
        if (WithTimestamp && tcp.Options.Items is not [{ Kind: 1 }, { Kind: 1 }, { Value: TcpOptionValue.Timestamp }])
            throw new InvalidDataException("Expected two NOP options followed by a timestamp.");
        if (!WithTimestamp && !tcp.Options.Items.IsEmpty)
            throw new InvalidDataException("Expected a TCP segment without options.");
    }

    [Benchmark]
    public TcpParseResult Parse() => TcpParser.Parse(segment, (uint)segment.Length, PacketSamples.IPv4AddressSum);
}
