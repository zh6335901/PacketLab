using System.Buffers.Binary;

namespace PacketLab.Pcap;

public sealed class CaptureReader
{
    private readonly Reader reader;

    private CaptureReader(PcapReader reader) => this.reader = reader;
    private CaptureReader(PcapNgReader reader) => this.reader = reader;

    public CaptureHeader Header => reader switch
    {
        PcapReader classic => classic.Header,
        PcapNgReader ng => ng.Sections[0],
        null => throw new InvalidOperationException("Uninitialized capture reader.")
    };

    public IReadOnlyList<PcapNgSection> Sections => reader is PcapNgReader ng ? ng.Sections : [];
    public IReadOnlyList<PcapNgInterface> Interfaces => reader is PcapNgReader ng ? ng.Interfaces : [];

    // Detection does not seek, and the caller retains ownership of the stream.
    public static CaptureOpenResult Open(Stream stream, CaptureReaderOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
            throw new ArgumentException("The stream must be readable.", nameof(stream));

        var input = new PcapInput(stream);
        Span<byte> magic = stackalloc byte[4];
        if (input.ReadBlock(magic) is BlockReadResult.Incomplete partial)
            return (PcapError)new PcapError.IncompleteFileHeader(partial.ReadBytes);

        var settings = options ?? CaptureReaderOptions.Default;
        if (BinaryPrimitives.ReadUInt32BigEndian(magic) == 0x0a0d0d0a)
        {
            var ng = new PcapNgReader(input, settings);
            if (ng.OpenSection(magic) is { } error)
                return error;

            return new CaptureReader(ng);
        }

        return PcapReader.Open(input, settings, magic) switch
        {
            PcapReader classic => new CaptureReader(classic),
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized PCAP open result.")
        };
    }

    public CaptureReadResult ReadNext() => reader switch
    {
        PcapReader classic => classic.ReadNext() switch
        {
            PcapPacket packet => packet,
            PcapEndOfFile eof => eof,
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized PCAP read result.")
        },
        PcapNgReader ng => ng.ReadNext(),
        null => throw new InvalidOperationException("Uninitialized capture reader.")
    };

    private union Reader(PcapReader, PcapNgReader);
}

public union CaptureHeader(PcapFileHeader, PcapNgSection);
public union CaptureOpenResult(CaptureReader, PcapError);
public union CaptureReadResult(PcapPacket, PcapNgPacket, PcapEndOfFile, PcapError);
