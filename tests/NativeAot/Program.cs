using System.Runtime.CompilerServices;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.IP.Reassembly;

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
            ReassembleFragments();

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

        long count = 0;
        foreach (var result in reader.ReadPackets())
        {
            if (result is not PcapPacket packet)
                throw new InvalidOperationException($"Could not read {sample}.");

            var decoding = PcapAnalysis.Decode(reader.Header, packet);
            if (decoding.Value is null)
                throw new InvalidOperationException($"Could not decode {sample}.");

            count++;
        }
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
    private static void ReassembleFragments()
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "ip-reassembly-little.pcap"));
        var reader = PcapReader.Open(stream, PcapReaderOptions.Default) is PcapReader opened ? opened : throw new InvalidOperationException();
        var records = reader.ReadPackets().Take(4).Select(result => result is PcapPacket packet ? packet : throw new InvalidOperationException()).ToArray();
        var first4 = DecodedIPv4.Decode(records[0].Data[14..]) is DecodedIPv4 v4 ? v4 : throw new InvalidOperationException();
        var first6 = DecodedIPv6.Decode(records[1].Data[14..]) is DecodedIPv6 v6 ? v6 : throw new InvalidOperationException();
        var tail4 = DecodedIPv4.Decode(records[2].Data[14..]) is DecodedIPv4 t4 ? t4 : throw new InvalidOperationException();
        var tail6 = DecodedIPv6.Decode(records[3].Data[14..]) is DecodedIPv6 t6 ? t6 : throw new InvalidOperationException();
        var fragment4 = first4.Payload is IPv4FragmentPayload f4 ? f4 : throw new InvalidOperationException();
        var last4 = tail4.Payload is IPv4FragmentPayload l4 ? l4 : throw new InvalidOperationException();
        var extension6 = first6.Extensions.Single(header => header.Fragment is not null);
        var last6 = tail6.Extensions.Single(header => header.Fragment is not null);
        using var analyzer = new IpReassemblyAnalyzer(IpReassemblyAnalysisOptions.Default);
        analyzer.AddIPv4Fragment(1, records[0].Data[14..], first4, fragment4);
        analyzer.AddIPv6Fragment(2, records[1].Data[14..], first6, extension6, extension6.Fragment!);
        var complete4 = analyzer.AddIPv4Fragment(3, records[2].Data[14..], tail4, last4).Single();
        var complete6 = analyzer.AddIPv6Fragment(4, records[3].Data[14..], tail6, last6, last6.Fragment!).Single();
        if (complete4.Status != IpReassemblyStatus.Complete || complete6.Status != IpReassemblyStatus.Complete)
            throw new InvalidOperationException("Native reassembly did not complete.");

        Console.WriteLine("PASS: Native AOT reassembled IPv4 and IPv6 fragments.");
    }

}
