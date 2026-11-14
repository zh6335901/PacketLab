using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Configs;
using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.Udp;

namespace PacketLab.Analysis.Benchmarks;

[MemoryDiagnoser]
[GroupBenchmarksBy(BenchmarkLogicalGroupRule.ByCategory)]
public class PcapAnalysisReaderBenchmarks
{
    private MemoryStream capture = null!;

    [GlobalSetup(Targets = [nameof(Read64), nameof(AnalyzeEthernet64)])]
    public void PrepareEthernet64() => capture = PcapCaptureSamples.Ethernet(64);

    [GlobalSetup(Targets = [nameof(Read1500), nameof(AnalyzeEthernet1500)])]
    public void PrepareEthernet1500() => capture = PcapCaptureSamples.Ethernet(1500);

    [GlobalSetup(Target = nameof(AnalyzeIPv4Udp1500))]
    public void PrepareIPv4Udp()
    {
        capture = PcapCaptureSamples.IPv4Udp();
        using var reader = OpenAnalysis();
        if (reader.ReadNext() is not AnalyzedPacket packet || packet.Decoding is not EthernetDecodeResult ethernet ||
            ethernet is not DecodedEthernet decoded || decoded.Payload is not IPv4DecodeResult ipv4 ||
            ipv4 is not DecodedIPv4 ip || ip.Packet.ChecksumStatus != IPv4ChecksumStatus.Match ||
            ip.Payload is not UdpParseResult udp || udp is not UdpDatagram { IsComplete: true } datagram ||
            datagram.Checksum is not UdpChecksumStatus.Match || datagram.Payload.Length != 1458 ||
            !reader.ReassemblyEvents.IsEmpty)
            throw new InvalidDataException("Expected an unfragmented IPv4 packet with a complete checksummed UDP datagram.");
    }

    [Benchmark(Baseline = true), BenchmarkCategory("64 B")]
    public void Read64() => ReadToEnd(64);

    [Benchmark, BenchmarkCategory("64 B")]
    public void AnalyzeEthernet64() => AnalyzeToEnd(64);

    [Benchmark(Baseline = true), BenchmarkCategory("1500 B")]
    public void Read1500() => ReadToEnd(1500);

    [Benchmark, BenchmarkCategory("1500 B")]
    public void AnalyzeEthernet1500() => AnalyzeToEnd(1500);

    [Benchmark, BenchmarkCategory("1500 B")]
    public void AnalyzeIPv4Udp1500() => AnalyzeToEnd(1500);

    [GlobalCleanup]
    public void CloseCapture() => capture.Dispose();

    private void ReadToEnd(int frameSize)
    {
        capture.Position = 0;
        var reader = PcapReader.Open(capture) switch
        {
            PcapReader opened => opened,
            PcapError error => throw new InvalidDataException(error.Message),
            null => throw new InvalidOperationException("Uninitialized open result.")
        };
        int packets = 0;
        long bytes = 0;
        while (true)
        {
            switch (reader.ReadNext())
            {
                case PcapPacket packet:
                    packets++;
                    bytes += packet.Data.Length;
                    break;
                case PcapEndOfFile when packets == PcapCaptureSamples.PacketCount && bytes == (long)PcapCaptureSamples.PacketCount * frameSize:
                    return;
                case PcapEndOfFile:
                    throw new InvalidDataException($"Unexpected EOF after {packets} packets and {bytes} bytes.");
                case PcapError error:
                    throw new InvalidDataException(error.Message);
                default:
                    throw new InvalidOperationException("Uninitialized packet result.");
            }
        }
    }

    private PcapAnalysisReader OpenAnalysis() => PcapAnalysisReader.Open(capture) switch
    {
        PcapAnalysisReader opened => opened,
        PcapError error => throw new InvalidDataException(error.Message),
        null => throw new InvalidOperationException("Uninitialized analysis open result.")
    };

    private void AnalyzeToEnd(int frameSize)
    {
        capture.Position = 0;
        using var reader = OpenAnalysis();
        int packets = 0;
        long bytes = 0;
        while (true)
        {
            switch (reader.ReadNext())
            {
                case AnalyzedPacket packet when packet.Decoding is EthernetDecodeResult ethernet && ethernet is DecodedEthernet frame:
                    packets++;
                    bytes += PcapCaptureSamples.EthernetHeaderLength + frame.Frame.RemainingBytes.Length;
                    break;
                case AnalyzedPacket:
                    throw new InvalidDataException("Expected a decoded Ethernet II frame.");
                case PcapEndOfFile when packets == PcapCaptureSamples.PacketCount && bytes == (long)PcapCaptureSamples.PacketCount * frameSize:
                    return;
                case PcapEndOfFile:
                    throw new InvalidDataException($"Unexpected EOF after {packets} packets and {bytes} bytes.");
                case PcapError error:
                    throw new InvalidDataException(error.Message);
                default:
                    throw new InvalidOperationException("Uninitialized analysis result.");
            }
        }
    }
}
