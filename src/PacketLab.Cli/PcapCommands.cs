using ConsoleAppFramework;
using PacketLab.Analysis.Pcap;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Protocols;
using PacketLab.Pcap;

namespace PacketLab.Cli;

internal static class PcapCommands
{
    /// <summary>Read a PCAP or PCAPNG file and print its metadata and packet count.</summary>
    /// <param name="file">Path to the local capture file.</param>
    public static int Read([Argument] string file) => ProcessFile(file, inspect: false);

    /// <summary>Inspect Ethernet II, ARP, IPv4 and IPv6 headers in each PCAP or PCAPNG record.</summary>
    /// <param name="file">Path to the local capture file.</param>
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

            return CaptureReader.Open(stream) switch
            {
                CaptureReader reader => ReadFile(reader),
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
        if (reader.CaptureHeader is PcapFileHeader && reader.LinkLayer == LinkLayerProtocol.Unsupported)
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
                case AnalyzedPcapNgPacket packet:
                    PrintNgFrame(packet);
                    PrintReassembly(reader);
                    break;
                case PcapEndOfFile:
                    PrintNgMetadata(reader.Sections, reader.Interfaces);
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
            Console.WriteLine($"  Reassembly {item.DatagramNumber}: IPv{item.IpVersion} id={item.Identification} {DescribeReassemblyStatus(item)}; records=[{string.Join(",", item.RecordNumbers)}]; {DescribeReassemblyMessage(item)}");
            if (item.Packet is { } packet)
                Console.WriteLine($"    Reassembled: {ProtocolFormatter.Describe(packet.Decoding)}");
        }
    }

    private static string DescribeReassemblyStatus(IpReassemblyEvent item) => item.Reason switch
    {
        IpReassemblyAnalysisReason.EndOfCapture => "IncompleteAtEndOfFile",
        IpReassemblyAnalysisReason.EndOfSection => "IncompleteAtEndOfSection",
        IpReassemblyAnalysisReason.Aborted => "Aborted",
        IpReassemblyAnalysisReason.RecordAssociationLimit => "ResourceLimit",
        _ => item.Status.ToString()
    };

    private static string DescribeReassemblyMessage(IpReassemblyEvent item) => item.Reason switch
    {
        IpReassemblyAnalysisReason.EndOfCapture => "EOF with missing fragments",
        IpReassemblyAnalysisReason.EndOfSection => "section ended with missing fragments",
        IpReassemblyAnalysisReason.Aborted => "analysis ended before reassembly completed",
        IpReassemblyAnalysisReason.RecordAgeLimit => "record age limit reached",
        IpReassemblyAnalysisReason.RecordAssociationLimit => "record association limit reached",
        _ => item.Reassembly.Message
    };

    private static int ReadFile(CaptureReader reader)
    {
        long count = 0;
        while (true)
        {
            switch (reader.ReadNext())
            {
                case PcapPacket:
                case PcapNgPacket:
                    count++;
                    break;
                case PcapEndOfFile:
                    if (reader.Header is PcapFileHeader classic)
                        return PrintSummary(classic, count);

                    Console.WriteLine("PCAPNG");
                    PrintNgMetadata(reader.Sections, reader.Interfaces);
                    Console.WriteLine($"Packets: {count}");

                    return 0;
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

    private static void PrintNgFrame(AnalyzedPcapNgPacket analyzed)
    {
        var packet = analyzed.Packet;
        var captureInterface = packet.Interface;
        Console.WriteLine($"Record {analyzed.RecordNumber}: section={captureInterface.Section.Number}, interface={captureInterface.Id}, link type={captureInterface.LinkType}");
        Console.WriteLine($"  Timestamp: {packet.Timestamp?.ToString() ?? "unknown"}; captured={packet.CapturedLength}; original={packet.OriginalLength}");
        Console.WriteLine($"  Data: {Convert.ToHexString(packet.Data.Span)}");
        foreach (var comment in packet.Comments)
            Console.WriteLine($"  Comment: {comment}");
        foreach (var option in packet.Options.Where(option => option.Code != 1))
            Console.WriteLine($"  Packet option {option.Code}: {Convert.ToHexString(option.Value.Span)}");
        if (packet.Details is PcapNgPacketDetails.Obsolete obsolete)
            Console.WriteLine($"  Drops count: {obsolete.DropsCount}");
        var description = captureInterface.LinkType == 1 ? ProtocolFormatter.Describe(analyzed.Decoding)
            : $"Unsupported link type {captureInterface.LinkType}; packet retained without protocol decoding.";
        Console.WriteLine($"  {description}");
    }

    private static void PrintNgMetadata(IReadOnlyList<PcapNgSection> sections, IReadOnlyList<PcapNgInterface> interfaces)
    {
        foreach (var section in sections)
        {
            Console.WriteLine($"Section {section.Number}: PCAPNG {section.MajorVersion}.{section.MinorVersion}; {section.ByteOrder}");
            foreach (var option in section.Options)
            {
                var value = option.Code is >= 1 and <= 4 ? option.Text : Convert.ToHexString(option.Value.Span);
                Console.WriteLine($"  Section option {option.Code}: {value}");
            }
        }
        foreach (var captureInterface in interfaces)
        {
            Console.WriteLine($"Interface {captureInterface.Section.Number}/{captureInterface.Id}: link type={captureInterface.LinkType}; SnapLen={captureInterface.SnapLen}; name={captureInterface.Name}; description={captureInterface.Description}");
            Console.WriteLine($"  Timestamp resolution: 0x{captureInterface.TimestampResolution:X2}; offset={captureInterface.TimestampOffsetSeconds} s");
            foreach (var option in captureInterface.Options)
                Console.WriteLine($"  Interface option {option.Code}: {Convert.ToHexString(option.Value.Span)}");
        }
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
