using System.Runtime.CompilerServices;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Testing;

internal static class Program
{
    private static int Main()
    {
        try
        {
            if (RuntimeFeature.IsDynamicCodeSupported)
                throw new InvalidOperationException("Run the published Native AOT executable.");

            string[] samples = ["little-micro.pcap", "big-micro.pcap", "little-nano.pcap", "big-nano.pcap",
                "arp-little.pcap", "arp-big.pcap", "ethernet-little.pcap", "ipv4-mixed.pcap", "ipv6-little.pcap", "ipv6-big.pcap", "udp-little.pcap", "udp-big.pcap", "tcp-little.pcap", "tcp-big.pcap", "ip-reassembly-little.pcap", "ip-reassembly-big.pcap"];
            foreach (var sample in samples)
                InspectPcap(sample);
            InspectPcapNg();

            return 0;
        }
        catch (Exception error)
        {
            Console.Error.WriteLine(error);

            return 1;
        }
    }

    private static void InspectPcap(string sample)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample));
        if (Capture.Open(stream) is not PcapReader reader)
            throw new InvalidOperationException($"Could not detect PCAP in {sample}.");

        using var reassembly = new IpReassemblyAnalyzer();
        long count = 0;
        foreach (var result in reader.ReadPackets())
        {
            if (result is not PcapPacket packet)
                throw new InvalidOperationException($"Could not read {sample}.");

            var decoding = PcapAnalysis.Decode(reader.Header, packet);
            if (decoding.Value is null)
                throw new InvalidOperationException($"Could not decode {sample}.");

            if (PcapAnalysis.GetTimestampNanoseconds(packet.Timestamp) is { } time)
                reassembly.AdvanceTime(time);
            reassembly.Expire(++count);
            ReassemblySteps.Add(reassembly, count, decoding);
        }
        reassembly.Finish(IpReassemblyAnalysisReason.EndOfCapture);
        if (count == 0)
            throw new InvalidOperationException($"No records exercised decoding in {sample}.");

        Console.WriteLine($"PASS: Native AOT consumed {sample}.");
    }

    private static void InspectPcapNg()
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "PcapNg", "mixed.pcapng"));
        if (Capture.Open(stream) is not PcapNgReader reader)
            throw new InvalidOperationException("Could not detect PCAPNG.");

        int count = 0;
        foreach (var result in reader.ReadPackets())
        {
            if (result is not PcapNgPacket packet || PcapAnalysis.Decode(packet).Value is null)
                throw new InvalidOperationException("Could not analyze PCAPNG.");

            count++;
            Console.WriteLine($"PASS: Native AOT consumed PCAPNG packet at {packet.Timestamp}.");
        }
        if (count != 3)
            throw new InvalidOperationException("Expected three PCAPNG packets.");
    }
}
