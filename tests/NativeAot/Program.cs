using System.Runtime.CompilerServices;
using PacketLab.Analysis;
using PacketLab.Protocols.Ethernet;
using PacketLab.Pcap;

try
{
    Check(!RuntimeFeature.IsDynamicCodeSupported, "Run the published Native AOT executable.");

    using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "multiple.pcap"));
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

    using var ethernetStream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "ethernet-little.pcap"));
    var ethernetReader = PcapAnalysisReader.Open(ethernetStream) is PcapAnalysisReader analysis
        ? analysis : throw new InvalidOperationException("Expected an analysis reader.");
    var analysisPacket = ethernetReader.ReadNext() is AnalyzedPacket analyzed
        ? analyzed : throw new InvalidOperationException("Expected an analyzed packet.");
    Check(analysisPacket.RecordNumber == 1 && analysisPacket.Packet.Timestamp == PcapTimestamp.FromMicroseconds(1, 0) &&
        analysisPacket.Packet.CapturedLength == 14 && analysisPacket.Packet.OriginalLength == 60, "Unexpected analysis metadata.");
    Check(analysisPacket.Decoding is EthernetParseResult parsed && parsed is EthernetFrame { EtherType: 0x0806 } frame &&
        frame.Source.ToString() == "02:00:00:00:00:01" && frame.Destination.ToString() == "FF:FF:FF:FF:FF:FF" &&
        frame.RemainingBytes.IsEmpty, "Unexpected Ethernet II header.");
    for (long number = 2; number <= 5; number++)
        Check(ethernetReader.ReadNext() is AnalyzedPacket next && next.RecordNumber == number,
            "Expected analysis to continue after frame diagnostics.");
    Check(ethernetReader.ReadNext() is PcapEndOfFile, "Expected end of file after five analyzed packets.");
    Console.WriteLine("PASS: Native AOT capture analysis (ARP header, metadata, frame diagnostics, and end of file).");
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
