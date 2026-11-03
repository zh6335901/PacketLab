using System.Runtime.CompilerServices;
using PacketLab.Analysis;
using PacketLab.Protocols;
using PacketLab.Protocols.Arp;

try
{
    if (RuntimeFeature.IsDynamicCodeSupported)
        throw new InvalidOperationException("Run the published Native AOT executable.");

    using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "arp-little.pcap"));
    if (PcapAnalysisReader.Open(stream) is not PcapAnalysisReader reader)
        throw new InvalidOperationException("Could not open the PCAP sample.");

    if (reader.ReadNext() is not AnalyzedPacket packet)
        throw new InvalidOperationException("Could not read the first packet.");

    if (packet.Decoding is not ProtocolDecodeResult.EthernetArp parsed || parsed.Arp is not ArpPacket)
        throw new InvalidOperationException("The first packet did not decode to an ARP packet.");

    Console.WriteLine("PASS: Native AOT read and decoded an ARP packet.");
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    return 1;
}
