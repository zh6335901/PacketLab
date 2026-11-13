using System.Runtime.CompilerServices;
using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;

try
{
    if (RuntimeFeature.IsDynamicCodeSupported)
        throw new InvalidOperationException("Run the published Native AOT executable.");

    string[] samples = ["little-micro.pcap", "big-micro.pcap", "little-nano.pcap", "big-nano.pcap",
        "arp-little.pcap", "arp-big.pcap", "ethernet-little.pcap", "ipv4-mixed.pcap", "ipv6-little.pcap", "ipv6-big.pcap", "udp-little.pcap", "udp-big.pcap", "tcp-little.pcap", "tcp-big.pcap", "ip-reassembly-little.pcap", "ip-reassembly-big.pcap"];
    foreach (var sample in samples)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample));
        if (PcapAnalysisReader.Open(stream) is not PcapAnalysisReader reader)
            throw new InvalidOperationException($"Could not open {sample}.");

        using var lifetime = reader;
        var sawPacket = false;
        while (true)
        {
            var result = reader.ReadNext();
            if (result is PcapEndOfFile) break;
            if (result is not AnalyzedPacket packet || packet.Decoding.Value is null)
                throw new InvalidOperationException($"Could not read and decode {sample}.");
            sawPacket = true;
        }
        if (!sawPacket)
            throw new InvalidOperationException($"No records exercised decoding in {sample}.");
        Console.WriteLine($"PASS: Native AOT consumed {sample}.");
    }

    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    return 1;
}
