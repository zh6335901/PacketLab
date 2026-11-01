using System.Runtime.CompilerServices;
using PacketLab.Ethernet;
using PacketLab.Pcap;

try
{
    Check(!RuntimeFeature.IsDynamicCodeSupported, "Run the published Native AOT executable.");

    using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "samples", "multiple.pcap"));
    var reader = Open(stream);

    Check(reader.Header is { MajorVersion: 2, MinorVersion: 4, LinkType: 1 }, "Unexpected PCAP header.");

    string[] payloads = ["DEADBE", "AABB", ""];
    foreach (var payload in payloads)
    {
        var packet = ReadPacket(reader);
        Check(Convert.ToHexString(packet.Data.Span) == payload, "Unexpected packet data.");
    }

    Check(reader.ReadNext() is PcapEndOfFile, "Expected end of file after three packets.");
    Console.WriteLine("PASS: Native AOT PCAP reading (header, three packets, and end of file).");

    using var ethernetStream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "samples", "ethernet-little.pcap"));
    var ethernetReader = Open(ethernetStream);
    Check(ethernetReader.Header.LinkType == 1, "Expected Ethernet link type.");
    var parsed = EthernetParser.Parse(ReadPacket(ethernetReader).Data);
    Check(parsed is EthernetFrame { EtherType: 0x0806 } frame &&
        frame.Source.ToString() == "02:00:00:00:00:01" && frame.Destination.ToString() == "FF:FF:FF:FF:FF:FF" &&
        frame.RemainingBytes.IsEmpty, "Unexpected Ethernet II header.");
    Console.WriteLine("PASS: Native AOT Ethernet II inspection (ARP header).");
    return 0;
}
catch (Exception error)
{
    Console.Error.WriteLine(error);
    return 1;
}

static PcapReader Open(Stream stream) => PcapReader.Open(stream) switch
{
    PcapReader opened => opened,
    PcapError error => throw new InvalidOperationException($"Open failed at byte {error.Offset}: {error.Message}"),
    null => throw new InvalidOperationException("Open returned no result.")
};

static PcapPacket ReadPacket(PcapReader reader) => reader.ReadNext() switch
{
    PcapPacket read => read,
    PcapError error => throw new InvalidOperationException($"Read failed at byte {error.Offset}: {error.Message}"),
    PcapEndOfFile => throw new InvalidOperationException("Unexpected end of file."),
    null => throw new InvalidOperationException("Read returned no result.")
};

static void Check(bool condition, string message)
{
    if (!condition)
        throw new InvalidOperationException(message);
}
