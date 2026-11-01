using ConsoleAppFramework;
using PacketLab.Ethernet;
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
            return PcapReader.Open(stream) switch
            {
                PcapReader reader => ReadFile(reader, inspect),
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

    private static int ReadFile(PcapReader reader, bool inspect)
    {
        if (inspect && reader.Header.LinkType != 1)
        {
            Console.Error.WriteLine($"Unsupported link type {reader.Header.LinkType}. Ethernet inspection requires LinkType 1.");
            return 1;
        }

        long count = 0;
        while (true)
        {
            switch (reader.ReadNext())
            {
                case PcapPacket packet:
                    count++;
                    if (inspect)
                        PrintFrame(count, packet.Data);
                    break;
                case PcapEndOfFile:
                    return inspect ? 0 : PrintSummary(reader.Header, count);
                case PcapError error:
                    return PrintError(error);
                default:
                    throw new InvalidOperationException("ReadNext returned an uninitialized result.");
            }
        }
    }

    private static void PrintFrame(long recordNumber, ReadOnlyMemory<byte> bytes)
    {
        var description = EthernetParser.Parse(bytes) switch
        {
            EthernetFrame frame => $"src {frame.Source} dst {frame.Destination} EtherType 0x{frame.EtherType:X4}{TypeName(frame.EtherType)}",
            EthernetParseResult.IncompleteHeader shortHeader => $"帧头不完整（捕获 {shortHeader.CapturedLength} 字节）",
            EthernetParseResult.Ieee8023Length field => $"暂不支持 IEEE 802.3 长度封装（长度 {field.Length}）",
            EthernetParseResult.InvalidLengthOrType field => $"无效的 Length/Type 字段 0x{field.Value:X4}",
            null => throw new InvalidOperationException("Uninitialized Ethernet parse result.")
        };
        Console.WriteLine($"Record {recordNumber}: {description}");
    }

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
