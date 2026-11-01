using BenchmarkDotNet.Attributes;

namespace PacketLab.Pcap.Benchmarks;

[MemoryDiagnoser]
public class PcapReaderBenchmarks
{
    private const int PacketCount = 4096;
    private MemoryStream capture = null!;

    [Params(64, 1500)]
    public int PayloadSize { get; set; }

    [GlobalSetup]
    public void PrepareCapture()
    {
        using var bytes = new MemoryStream(24 + PacketCount * (16 + PayloadSize));
        using var writer = new BinaryWriter(bytes);
        writer.Write(0xa1b2c3d4u);
        writer.Write((ushort)2);
        writer.Write((ushort)4);
        writer.Write(0u);
        writer.Write(0u);
        writer.Write(65535u);
        writer.Write(1u);

        byte[] payload = new byte[PayloadSize];
        for (int i = 0; i < PacketCount; i++)
        {
            writer.Write(0u);
            writer.Write((uint)i);
            writer.Write((uint)PayloadSize);
            writer.Write((uint)PayloadSize);
            writer.Write(payload);
        }
        capture = new MemoryStream(bytes.GetBuffer(), 0, (int)bytes.Length, writable: false);
    }

    [Benchmark]
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
                case PcapEndOfFile when packets == PacketCount && bytes == (long)PacketCount * PayloadSize:
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

    [GlobalCleanup]
    public void CloseCapture() => capture.Dispose();
}
