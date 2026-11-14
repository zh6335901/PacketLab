using BenchmarkDotNet.Attributes;
using PacketLab.Pcap;
using PacketLab.Analysis.Pcap;
using PacketLab.Protocols.Ethernet;

namespace PacketLab.Analysis.Benchmarks;

[MemoryDiagnoser]
public class PcapAnalysisReaderBenchmarks
{
    private const int EthernetHeaderLength = 14;
    private MemoryStream capture = null!;

    [Params(64, 1500)]
    public int FrameSize { get; set; }

    [GlobalSetup]
    public void PrepareCapture()
    {
        var frame = new byte[FrameSize];
        // An unrecognized EtherType keeps this workload focused on Ethernet decoding.
        Convert.FromHexString("00112233445566778899AABBABCD").CopyTo(frame, 0);
        frame.AsSpan(EthernetHeaderLength).Fill(0x5a);
        capture = BenchmarkCapture.Create(frame);
    }

    [Benchmark(Baseline = true)]
    public void ReadToEnd()
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
                case PcapEndOfFile when packets == BenchmarkCapture.PacketCount && bytes == (long)BenchmarkCapture.PacketCount * FrameSize:
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

    [Benchmark]
    public void AnalyzeToEnd() => BenchmarkCapture.AnalyzeToEnd(capture, FrameSize);

    [GlobalCleanup]
    public void CloseCapture() => capture.Dispose();
}

internal static class BenchmarkCapture
{
    internal const int PacketCount = 4096;

    internal static MemoryStream Create(byte[] frame)
    {
        using var bytes = new MemoryStream(24 + PacketCount * (16 + frame.Length));
        using var writer = new BinaryWriter(bytes);
        writer.Write(0xa1b2c3d4u);
        writer.Write((ushort)2);
        writer.Write((ushort)4);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(65535u);
        writer.Write(1u);
        for (int i = 0; i < PacketCount; i++)
        {
            writer.Write(0u);
            writer.Write((uint)i);
            writer.Write((uint)frame.Length);
            writer.Write((uint)frame.Length);
            writer.Write(frame);
        }
        return new MemoryStream(bytes.GetBuffer(), 0, (int)bytes.Length, writable: false);
    }

    internal static void AnalyzeToEnd(MemoryStream capture, int frameSize)
    {
        capture.Position = 0;
        using var reader = PcapAnalysisReader.Open(capture) switch
        {
            PcapAnalysisReader opened => opened,
            PcapError error => throw new InvalidDataException(error.Message),
            null => throw new InvalidOperationException("Uninitialized analysis open result.")
        };
        int packets = 0;
        long bytes = 0;
        while (true)
        {
            switch (reader.ReadNext())
            {
                case AnalyzedPacket packet when packet.Decoding is EthernetDecodeResult ethernet && ethernet is DecodedEthernet frame:
                    packets++;
                    bytes += 14 + frame.Frame.RemainingBytes.Length;
                    break;
                case AnalyzedPacket:
                    throw new InvalidDataException("Expected a decoded Ethernet II frame.");
                case PcapEndOfFile when packets == PacketCount && bytes == (long)PacketCount * frameSize:
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
