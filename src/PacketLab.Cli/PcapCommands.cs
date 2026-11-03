using ConsoleAppFramework;
using PacketLab.Protocols.Arp;
using PacketLab.Analysis;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using PacketLab.Pcap;

namespace PacketLab.Cli;

internal static class PcapCommands
{
    /// <summary>Read a classic PCAP file and print its metadata and packet count.</summary>
    /// <param name="file">Path to the local PCAP file.</param>
    public static int Read([Argument] string file) => ProcessFile(file, inspect: false);

    /// <summary>Inspect the outer Ethernet II header of each classic PCAP record.</summary>
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
        if (reader.LinkLayer == LinkLayerProtocol.Unsupported)
        {
            Console.Error.WriteLine($"Unsupported link type {reader.Header.LinkType}. Ethernet inspection requires LinkType 1.");
            return 1;
        }

        while (true)
        {
            switch (reader.ReadNext())
            {
                case AnalyzedPacket packet:
                    PrintFrame(packet);
                    break;
                case PcapEndOfFile:
                    return 0;
                case PcapError error:
                    return PrintError(error);
                default:
                    throw new InvalidOperationException("ReadNext returned an uninitialized result.");
            }
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
        var description = packet.Decoding switch
        {
            ProtocolDecodeResult.EthernetArp arp => $"{DescribeEthernet(arp.Ethernet)}; {DescribeArp(arp.Arp)}",
            EthernetParseResult ethernet => DescribeEthernet(ethernet),
            ProtocolDecodeResult.UnsupportedLinkLayer => "Unsupported link layer.",
            null => throw new InvalidOperationException("Uninitialized protocol decode result.")
        };
        Console.WriteLine($"Record {packet.RecordNumber}: {description}");
    }

    private static string DescribeEthernet(EthernetParseResult result) => result switch
    {
        EthernetFrame frame => $"src {frame.Source} dst {frame.Destination} EtherType 0x{frame.EtherType:X4}{TypeName(frame.EtherType)}",
        EthernetParseResult.IncompleteHeader shortHeader => $"Incomplete Ethernet header: expected 14 bytes, captured {shortHeader.CapturedLength}.",
        EthernetParseResult.Ieee8023Length field => $"Unsupported IEEE 802.3 length encapsulation (length {field.Length}).",
        EthernetParseResult.InvalidLengthOrType field => $"Invalid Length/Type field: 0x{field.Value:X4}.",
        null => throw new InvalidOperationException("Uninitialized Ethernet parse result.")
    };

    private static string DescribeArp(ArpParseResult result) => result switch
    {
        ArpPacket arp => $"ARP {OperationName(arp.Operation)} sender hardware {HardwareAddress(arp, arp.SenderHardwareAddress)} protocol {ProtocolAddress(arp, arp.SenderProtocolAddress)} target hardware {HardwareAddress(arp, arp.TargetHardwareAddress)} protocol {ProtocolAddress(arp, arp.TargetProtocolAddress)}",
        ArpParseResult.IncompleteHeader incomplete => $"Incomplete ARP header: expected {incomplete.RequiredLength} bytes, captured {incomplete.CapturedLength}.",
        null => throw new InvalidOperationException("Uninitialized ARP parse result.")
    };

    private static string OperationName(ushort operation) => operation switch
    {
        1 => "Request",
        2 => "Reply",
        _ => operation.ToString(System.Globalization.CultureInfo.InvariantCulture)
    };

    private static string HardwareAddress(ArpPacket arp, ReadOnlyMemory<byte> address) =>
        arp.HardwareType == 1 && arp.HardwareAddressLength == 6
            ? string.Join(":", address.ToArray().Select(value => value.ToString("X2")))
            : Convert.ToHexString(address.Span);

    private static string ProtocolAddress(ArpPacket arp, ReadOnlyMemory<byte> address) =>
        arp.ProtocolType == 0x0800 && arp.ProtocolAddressLength == 4
            ? $"{address.Span[0]}.{address.Span[1]}.{address.Span[2]}.{address.Span[3]}"
            : Convert.ToHexString(address.Span);

    private static string TypeName(ushort etherType) => etherType switch
    {
        0x0800 => " (IPv4)",
        0x0806 => " (ARP)",
        0x86DD => " (IPv6)",
        _ => ""
    };

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
