using BenchmarkDotNet.Attributes;
using PacketLab.Analysis.Pcap;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.Udp;

namespace PacketLab.Analysis.Benchmarks;

[MemoryDiagnoser]
public class IPv4UdpCaptureBenchmarks
{
    private const int FrameSize = 1500;
    private MemoryStream capture = null!;

    [GlobalSetup]
    public void PrepareCapture()
    {
        var frame = new byte[FrameSize];
        // Ethernet II, IPv4 with DF set, and UDP checksums for 1458 bytes of 0x5a.
        var headers = Convert.FromHexString("00112233445566778899AABB0800" +
            "450005CE000140004011B11AC0000201C0000202" + "3039D43105BA20C0");
        headers.CopyTo(frame, 0);
        frame.AsSpan(headers.Length).Fill(0x5a);
        capture = BenchmarkCapture.Create(frame);

        using var reader = PcapAnalysisReader.Open(capture) switch
        {
            PcapAnalysisReader opened => opened,
            _ => throw new InvalidDataException("Expected a readable IPv4/UDP capture.")
        };
        if (reader.ReadNext() is not AnalyzedPacket packet || packet.Decoding is not EthernetDecodeResult ethernet ||
            ethernet is not DecodedEthernet decoded || decoded.Payload is not IPv4DecodeResult ipv4 ||
            ipv4 is not DecodedIPv4 ip || ip.Packet.ChecksumStatus != IPv4ChecksumStatus.Match ||
            ip.Payload is not UdpParseResult udp || udp is not UdpDatagram { IsComplete: true } datagram ||
            datagram.Checksum is not UdpChecksumStatus.Match || datagram.Payload.Length != FrameSize - headers.Length ||
            !reader.ReassemblyEvents.IsEmpty)
            throw new InvalidDataException("Expected an unfragmented IPv4 packet with a complete checksummed UDP datagram.");
    }

    [Benchmark]
    public void AnalyzeIPv4UdpToEnd() => BenchmarkCapture.AnalyzeToEnd(capture, FrameSize);

    [GlobalCleanup]
    public void CloseCapture() => capture.Dispose();
}
