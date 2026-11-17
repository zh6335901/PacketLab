using System.Buffers.Binary;

namespace PacketLab.Pcap;

public static class Capture
{
    // Detection does not seek, and the caller retains ownership of the stream.
    public static CaptureOpenResult Open(Stream stream)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
            throw new ArgumentException("The stream must be readable.", nameof(stream));

        var input = new PcapInput(stream);
        Span<byte> magic = stackalloc byte[4];
        if (input.ReadBlock(magic) is BlockReadResult.Incomplete partial)
            return (PcapError)new PcapError.IncompleteFileHeader(partial.ReadBytes);

        if (BinaryPrimitives.ReadUInt32BigEndian(magic) == 0x0a0d0d0a)
            return PcapNgReader.Open(input, PcapNgReaderOptions.Default, magic) switch
            {
                PcapNgReader reader => reader,
                PcapError error => error,
                null => throw new InvalidOperationException("Uninitialized PCAPNG open result.")
            };

        return PcapReader.Open(input, PcapReaderOptions.Default, magic) switch
        {
            PcapReader reader => reader,
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized PCAP open result.")
        };
    }
}

public union CaptureOpenResult(PcapReader, PcapNgReader, PcapError);
