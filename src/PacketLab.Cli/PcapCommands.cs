using ConsoleAppFramework;
using PacketLab.Analysis;
using PacketLab.Protocols;
using PacketLab.Pcap;

namespace PacketLab.Cli;

internal static class PcapCommands
{
    /// <summary>Read a classic PCAP file and print its metadata and packet count.</summary>
    /// <param name="file">Path to the local PCAP file.</param>
    public static int Read([Argument] string file) => ProcessFile(file, inspect: false);

    /// <summary>Inspect Ethernet II, ARP, IPv4 and IPv6 headers in each classic PCAP record.</summary>
    /// <param name="file">Path to the local PCAP file.</param>
    public static int Inspect([Argument] string file) => ProcessFile(file, inspect: true);

    private static int ProcessFile(string file, bool inspect)
    {
        if (string.IsNullOrWhiteSpace(file))
        {
            Console.Error.WriteLine("The file path must not be empty or whitespace.");
            return 1;
        }

        try
        {
            using var stream = File.OpenRead(file);
            if (inspect)
                return PcapAnalysisReader.Open(stream) switch
                {
                    PcapAnalysisReader reader => InspectFile(reader),
                    PcapError error => PrintError(error),
                    null => throw new InvalidOperationException("Open returned an uninitialized result.")
                };

            return PcapReader.Open(stream) switch
            {
                PcapReader reader => ReadFile(reader),
                PcapError error => PrintError(error),
                null => throw new InvalidOperationException("Open returned an uninitialized result.")
            };
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            Console.Error.WriteLine($"Unable to read '{file}': {exception.Message}");
            return 1;
        }
    }

    private static int InspectFile(PcapAnalysisReader reader)
    {
        using var lifetime = reader;
        if (reader.LinkLayer == LinkLayerProtocol.Unsupported)
        {
            Console.Error.WriteLine($"Unsupported link type {reader.Header.LinkType}. Ethernet inspection requires LinkType 1.");
            return 1;
        }

        while (true)
        {
            var result = reader.ReadNext();
            switch (result)
            {
                case AnalyzedPacket packet:
                    PrintFrame(packet);
                    PrintReassembly(reader);
                    break;
                case PcapEndOfFile:
                    PrintReassembly(reader);
                    return 0;
                case PcapError error:
                    PrintReassembly(reader);
                    return PrintError(error);
                default:
                    throw new InvalidOperationException("ReadNext returned an uninitialized result.");
            }
        }
    }

    private static void PrintReassembly(PcapAnalysisReader reader)
    {
        foreach (var item in reader.ReassemblyEvents)
        {
            Console.WriteLine($"  Reassembly {item.DatagramNumber}: IPv{item.IpVersion} id={item.Identification} {item.Status}; records=[{string.Join(",", item.RecordNumbers)}]; {item.Message}");
            if (item.Packet is { } packet)
                Console.WriteLine($"    Reassembled: {ProtocolFormatter.Describe(packet.Decoding)}");
        }
    }

    private static int ReadFile(PcapReader reader)
    {
        long count = 0;
        while (true)
        {
            switch (reader.ReadNext())
            {
                case PcapPacket:
                    count++;
                    break;
                case PcapEndOfFile:
                    return PrintSummary(reader.Header, count);
                case PcapError error:
                    return PrintError(error);
                default:
                    throw new InvalidOperationException("ReadNext returned an uninitialized result.");
            }
        }
    }

    private static void PrintFrame(AnalyzedPacket packet)
    {
        Console.WriteLine($"Record {packet.RecordNumber}: {ProtocolFormatter.Describe(packet.Decoding)}");
    }

    private static int PrintSummary(PcapFileHeader header, long count)
    {
        Console.WriteLine($"PCAP {header.MajorVersion}.{header.MinorVersion}");
        Console.WriteLine($"Byte order: {header.ByteOrder}");
        Console.WriteLine($"Timestamp precision: {header.TimestampPrecision}");
        Console.WriteLine($"SnapLen: {header.SnapLen}");
        Console.WriteLine($"Link type: {header.LinkType}");
        Console.WriteLine($"Packets: {count}");
        return 0;
    }

    private static int PrintError(PcapError error)
    {
        var record = error.RecordNumber is { } number ? $", record {number}" : "";
        Console.Error.WriteLine($"Error at byte {error.Offset}{record}: {error.Message}");
        return 1;
    }
}
