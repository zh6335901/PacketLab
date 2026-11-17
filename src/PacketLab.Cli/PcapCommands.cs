using System.Collections.Immutable;
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

            return Capture.Open(stream) switch
            {
                PcapReader reader => inspect ? InspectFile(reader) : ReadFile(reader),
                PcapNgReader reader => inspect ? InspectFile(reader) : ReadFile(reader),
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

    private static int InspectFile(PcapReader reader)
    {
        if (PcapAnalysis.GetLinkLayer(reader.Header) == LinkLayerProtocol.Unsupported)
        {
            Console.Error.WriteLine($"Unsupported link type {reader.Header.LinkType}. Ethernet inspection requires LinkType 1.");

            return 1;
        }

        using var inspection = new PacketInspection();
        long recordNumber = 0;
        foreach (var result in reader.ReadPackets())
        {
            switch (result)
            {
                case PcapPacket packet:
                    var decoding = PcapAnalysis.Decode(reader.Header, packet);
                    var analyzed = new AnalyzedPacket(++recordNumber, packet, decoding);
                    PrintFrame(analyzed);
                    inspection.AdvanceTime(PcapAnalysis.GetTimestampNanoseconds(packet.Timestamp));
                    PrintReassembly(inspection.Expire(recordNumber));
                    PrintReassembly(inspection.AnalyzePacket(recordNumber, decoding));
                    break;
                case PcapError error:
                    PrintReassembly(inspection.Finish(IpReassemblyAnalysisReason.Aborted));

                    return PrintError(error);
            }
        }
        PrintReassembly(inspection.Finish(IpReassemblyAnalysisReason.EndOfCapture));

        return 0;
    }

    private static int InspectFile(PcapNgReader reader)
    {
        using var inspection = new PcapNgInspection();
        long recordNumber = 0;
        foreach (var result in reader.ReadPackets())
        {
            // ReadPackets also consumes empty sections before yielding a packet or error.
            inspection.EnterSection(reader.Sections.LastOrDefault());
            switch (result)
            {
                case PcapNgPacket packet:
                    var decoding = PcapAnalysis.Decode(packet);
                    var analyzed = new AnalyzedPcapNgPacket(++recordNumber, packet, decoding);
                    PrintNgFrame(analyzed);
                    inspection.AnalyzePacket(analyzed);
                    break;
                case PcapError error:
                    inspection.Finish(IpReassemblyAnalysisReason.Aborted);

                    return PrintError(error);
            }
        }
        inspection.EnterSection(reader.Sections.LastOrDefault());
        PrintNgMetadata(reader.Sections, reader.Interfaces);
        inspection.Finish(IpReassemblyAnalysisReason.EndOfCapture);

        return 0;
    }

    private sealed class PcapNgInspection : IDisposable
    {
        private readonly Dictionary<PcapNgInterface, PacketInspection> interfaces = [];
        private PcapNgSection? section;

        internal void EnterSection(PcapNgSection? current)
        {
            if (section == current)
                return;

            Finish(IpReassemblyAnalysisReason.EndOfSection);
            section = current;
        }

        internal void AnalyzePacket(AnalyzedPcapNgPacket analyzed)
        {
            var packet = analyzed.Packet;
            if (!interfaces.TryGetValue(packet.Interface, out var inspection))
            {
                inspection = new PacketInspection();
                interfaces.Add(packet.Interface, inspection);
            }
            inspection.AdvanceTime(packet.Timestamp?.GetNanoseconds());
            PrintReassembly(inspection.Expire(analyzed.RecordNumber));
            PrintReassembly(inspection.AnalyzePacket(analyzed.RecordNumber, analyzed.Decoding));
        }

        internal void Finish(IpReassemblyAnalysisReason reason)
        {
            foreach (var inspection in interfaces.Values)
            {
                PrintReassembly(inspection.Finish(reason));
                inspection.Dispose();
            }
            interfaces.Clear();
        }

        public void Dispose()
        {
            foreach (var inspection in interfaces.Values)
                inspection.Dispose();
            interfaces.Clear();
        }
    }

    private static void PrintReassembly(ImmutableArray<IpReassemblyEvent> events)
    {
        foreach (var item in events)
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

    private static int ReadFile(PcapReader reader)
    {
        long count = 0;
        foreach (var result in reader.ReadPackets())
        {
            if (result is PcapError error)
                return PrintError(error);

            count++;
        }

        return PrintSummary(reader.Header, count);
    }

    private static int ReadFile(PcapNgReader reader)
    {
        long count = 0;
        foreach (var result in reader.ReadPackets())
        {
            if (result is PcapError error)
                return PrintError(error);

            count++;
        }
        Console.WriteLine("PCAPNG");
        PrintNgMetadata(reader.Sections, reader.Interfaces);
        Console.WriteLine($"Packets: {count}");

        return 0;
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
