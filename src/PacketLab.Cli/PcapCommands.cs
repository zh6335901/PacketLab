using ConsoleAppFramework;
using PacketLab.Pcap;

namespace PacketLab.Cli;

internal static class PcapCommands
{
    /// <summary>Read a classic PCAP file and print its metadata and packet count.</summary>
    /// <param name="file">Path to the local PCAP file.</param>
    public static int Read([Argument] string file)
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

    private static int ReadFile(PcapReader reader)
    {
        long count = 0;
        while (true)
        {
            int? exitCode = reader.ReadNext() switch
            {
                PcapPacket => null,
                PcapEndOfFile => PrintSummary(reader.Header, count),
                PcapError error => PrintError(error),
                null => throw new InvalidOperationException("ReadNext returned an uninitialized result.")
            };
            if (exitCode is { } code)
                return code;
            count++;
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
