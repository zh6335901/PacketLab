using System.Runtime.CompilerServices;
using PacketLab.Analysis;
using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.IPv6;

try
{
    if (RuntimeFeature.IsDynamicCodeSupported)
        throw new InvalidOperationException("Run the published Native AOT executable.");

    string[] samples = ["little-micro.pcap", "big-micro.pcap", "little-nano.pcap", "big-nano.pcap",
        "arp-little.pcap", "arp-big.pcap", "ethernet-little.pcap", "ipv4-mixed.pcap", "ipv6-little.pcap", "ipv6-big.pcap"];
    foreach (var sample in samples)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample));
        if (PcapAnalysisReader.Open(stream) is not PcapAnalysisReader reader)
            throw new InvalidOperationException($"Could not open {sample}.");

        var sawPacket = false;
        var sawIPv6Packet = false;
        while (true)
        {
            var result = reader.ReadNext();
            if (result is PcapEndOfFile) break;
            if (result is not AnalyzedPacket packet || packet.Decoding.Value is null)
                throw new InvalidOperationException($"Could not read and decode {sample}.");
            if (packet.Decoding is ProtocolDecodeResult.EthernetIPv6 ipv6 && ipv6.IPv6 is IPv6Packet datagram)
            {
                sawIPv6Packet = true;
                if (datagram.Header.Source.ToString() != "2001:db8::1" || datagram.Header.Destination.ToString() != "ff02::2")
                    throw new InvalidOperationException($"Unexpected IPv6 address formatting in {sample}.");
            }
            sawPacket = true;
        }
        if (!sawPacket)
            throw new InvalidOperationException($"No records exercised decoding in {sample}.");
        if (sample is "ipv6-little.pcap" or "ipv6-big.pcap" && !sawIPv6Packet)
            throw new InvalidOperationException($"No records exercised successful IPv6 decoding in {sample}.");
        Console.WriteLine($"PASS: Native AOT consumed {sample}.");
    }

    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    return 1;
}
