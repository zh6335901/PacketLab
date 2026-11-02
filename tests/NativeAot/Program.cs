using System.Runtime.CompilerServices;
using PacketLab.Analysis;
using PacketLab.Protocols.Ethernet;

try
{
    if (RuntimeFeature.IsDynamicCodeSupported)
        throw new InvalidOperationException("Run the published Native AOT executable.");

    using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "ethernet-little.pcap"));
    if (PcapAnalysisReader.Open(stream) is not PcapAnalysisReader reader)
        throw new InvalidOperationException("Could not open the PCAP sample.");

    if (reader.ReadNext() is not AnalyzedPacket packet)
        throw new InvalidOperationException("Could not read the first packet.");

    if (packet.Decoding is not EthernetParseResult parsed || parsed is not EthernetFrame)
        throw new InvalidOperationException("The first packet did not decode to an Ethernet frame.");

    Console.WriteLine("PASS: Native AOT read and decoded an Ethernet frame.");
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    return 1;
}
