using System.Buffers.Binary;
using System.Diagnostics;
using System.Runtime.ExceptionServices;

namespace PacketLab.Pcap;

public sealed class PcapNgReader
{
    private readonly PcapInput input;
    private readonly PcapNgReaderOptions options;
    private readonly List<PcapNgSection> sections = [];
    private readonly List<PcapNgInterface> interfaces = [];
    private readonly List<PcapNgInterface> sectionInterfaces = [];
    private ReaderState state = new Reading();
    private PcapByteOrder order;
    private SectionBoundary sectionBoundary = new UnspecifiedLength();
    private long metadataBytes;
    private long recordNumber = 1;

    private PcapNgReader(PcapInput input, PcapNgReaderOptions options)
    {
        this.input = input;
        this.options = options;
    }

    public static PcapNgOpenResult Open(Stream stream, PcapNgReaderOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
            throw new ArgumentException("The stream must be readable.", nameof(stream));

        var input = new PcapInput(stream);
        Span<byte> magic = stackalloc byte[4];
        if (input.ReadBlock(magic) is BlockReadResult.Incomplete)
            return Error(0, input.Offset, "Truncated section block type; expected 4 bytes.");

        return Open(input, options ?? PcapNgReaderOptions.Default, magic);
    }

    internal static PcapNgOpenResult Open(PcapInput input, PcapNgReaderOptions options, ReadOnlySpan<byte> magic)
    {
        if (BinaryPrimitives.ReadUInt32BigEndian(magic) != 0x0a0d0d0a)
            return Error(0, 0, "Expected a PCAPNG Section Header Block.");

        var reader = new PcapNgReader(input, options);
        if (reader.OpenSection(magic) is { } error)
            return error;

        return reader;
    }

    // These views contain metadata encountered so far; later reads can append to them.
    public IReadOnlyList<PcapNgSection> Sections => sections.AsReadOnly();
    public IReadOnlyList<PcapNgInterface> Interfaces => interfaces.AsReadOnly();

    private PcapError? OpenSection(ReadOnlySpan<byte> magic) => ReadBlock(magic) switch
    {
        PcapNgBlock block => AddSection(block),
        PcapError error => error,
        _ => throw new InvalidOperationException("Missing initial section header.")
    };

    public PcapNgReadResult ReadNext()
    {
        switch (state)
        {
            case PcapError error: return error;
            case PcapEndOfFile eof: return eof;
            case ExceptionDispatchInfo failure:
                failure.Throw();
                throw new UnreachableException();
            case Reading:
                try { return ReadPacket(); }
                catch (Exception exception)
                {
                    state = ExceptionDispatchInfo.Capture(exception);
                    throw;
                }
            default: throw new InvalidOperationException("Uninitialized reader state.");
        }
    }

    private PcapNgReadResult ReadPacket()
    {
        while (true)
        {
            switch (ReadBlock([]))
            {
                case PcapNgBlock block:
                    var result = ProcessBlock(block);
                    if (result is PcapNgPacket packet)
                    {
                        recordNumber++;

                        return packet;
                    }
                    if (result is PcapError failure)
                        return Fail(failure);

                    break;
                case PcapError error: return Fail(error);
                case PcapEndOfFile eof:
                    state = eof;

                    return eof;
                default: throw new InvalidOperationException("Uninitialized block result.");
            }
        }
    }

    private ProcessResult ProcessBlock(PcapNgBlock block)
    {
        if (block.Type == 0x0a0d0d0a)
            return AddSection(block) is { } error ? error : new Skipped();
        if (block.Type == 1)
            return AddInterface(block) is { } error ? error : new Skipped();
        if (block.Type is 2 or 3 or 6)
            return PcapNgParser.Packet(block, sectionInterfaces, options.MaxPacketBytes, options.MaxOptionsPerBlock) switch
            {
                PcapNgPacket packet => packet,
                PcapError error => error,
                null => throw new InvalidOperationException("Uninitialized packet result.")
            };

        return new Skipped();
    }

    private PcapError? AddSection(PcapNgBlock block)
    {
        var result = PcapNgParser.Section(block, sections.Count, options.MaxOptionsPerBlock);
        if (result is PcapError error)
            return error;
        if (result is not PcapNgSection section)
            throw new InvalidOperationException("Uninitialized section result.");
        if (section.Length > long.MaxValue - input.Offset)
            return block.Error(8, "Section length exceeds the supported stream offset range.");

        if (RetainMetadata(block, section.Options.Length) is { } limit)
            return limit;

        sections.Add(section);
        sectionInterfaces.Clear();
        order = block.Order;
        sectionBoundary = section.Length < 0 ? new UnspecifiedLength() : new KnownEnd(input.Offset + section.Length);

        return null;
    }

    private PcapError? AddInterface(PcapNgBlock block)
    {
        var result = PcapNgParser.Interface(block, sections[^1], (uint)sectionInterfaces.Count, options.MaxOptionsPerBlock);
        if (result is PcapError error)
            return error;
        if (result is not PcapNgInterface captureInterface)
            throw new InvalidOperationException("Uninitialized interface result.");

        if (RetainMetadata(block, captureInterface.Options.Length) is { } limit)
            return limit;

        sectionInterfaces.Add(captureInterface);
        interfaces.Add(captureInterface);

        return null;
    }

    private PcapError? RetainMetadata(PcapNgBlock block, int optionCount)
    {
        // Include object overhead so a flood of empty sections/interfaces is bounded too.
        metadataBytes += block.Body.Length + 256L + optionCount * 64L;

        return metadataBytes > options.MaxMetadataBytes
            ? block.Error(0, $"Section/interface metadata exceeds the configured limit {options.MaxMetadataBytes} bytes.") : (PcapError?)null;
    }

    private BlockResult ReadBlock(ReadOnlySpan<byte> prefix)
    {
        long offset = input.Offset - prefix.Length;
        Span<byte> header = stackalloc byte[12];
        prefix.CopyTo(header);
        if (input.ReadBlock(header[prefix.Length..8]) is BlockReadResult.Incomplete partial)
            return EndOrTruncated(offset, prefix.Length + partial.ReadBytes);

        bool section = BinaryPrimitives.ReadUInt32BigEndian(header) == 0x0a0d0d0a;
        var blockOrder = order;
        int read = 8;
        if (section)
        {
            if (input.ReadBlock(header[8..]) is BlockReadResult.Incomplete)
                return Error(offset, input.Offset, "Truncated section byte-order magic.");

            uint magic = BinaryPrimitives.ReadUInt32BigEndian(header[8..]);
            if (magic is not (0x1a2b3c4d or 0x4d3c2b1a))
                return Error(offset, offset + 8, $"Invalid byte-order magic 0x{magic:X8}.");

            blockOrder = magic == 0x1a2b3c4d ? PcapByteOrder.BigEndian : PcapByteOrder.LittleEndian;
            read = 12;
        }
        uint length = PcapNgParser.UInt32(header[4..], blockOrder);
        if (ValidateBlockLength(offset, length, section) is { } error)
            return error;

        var bytes = new byte[(int)length - 8];
        header[8..read].CopyTo(bytes);
        if (input.ReadBlock(bytes.AsSpan(read - 8)) is BlockReadResult.Incomplete)
            return Error(offset, input.Offset, $"Truncated block; expected {length} bytes.");
        if (PcapNgParser.UInt32(bytes.AsSpan(bytes.Length - 4), blockOrder) != length)
            return Error(offset, offset + length - 4, "Trailing block length does not match its header.");

        return new PcapNgBlock(offset,
            PcapNgParser.UInt32(header, blockOrder), blockOrder,
            bytes.AsMemory(0, bytes.Length - 4));
    }

    private PcapError? ValidateBlockLength(long offset, uint length, bool section)
    {
        if (length < (section ? 28 : 12) || length % 4 != 0)
            return Error(offset, offset + 4, $"Invalid block length {length}; expected an aligned length of at least {(section ? 28 : 12)}.");
        if (length > options.MaxBlockBytes)
            return Error(offset, offset + 4, $"Block length {length} exceeds the configured limit {options.MaxBlockBytes} bytes.");
        if (sectionBoundary is KnownEnd(var end) && (section ? offset != end : offset >= end || length > end - offset))
            return Error(offset, offset, "Block boundary does not match the declared section length.");

        return null;
    }

    private BlockResult EndOrTruncated(long offset, int received)
    {
        if (received != 0)
            return Error(offset, input.Offset, "Truncated block header.");
        if (sectionBoundary is KnownEnd(var end) && input.Offset != end)
            return Error(offset, input.Offset, "EOF before the declared end of the section.");

        return new PcapEndOfFile();
    }

    private static PcapError Error(long blockOffset, long offset, string detail) =>
        new PcapError.InvalidPcapNg(blockOffset, offset, null, detail);

    private PcapNgReadResult Fail(PcapError error)
    {
        if (error is PcapError.InvalidPcapNg ng)
            error = ng with { PacketNumber = recordNumber };
        state = error;

        return error;
    }

    private union SectionBoundary(UnspecifiedLength, KnownEnd);
    private sealed record UnspecifiedLength;
    private sealed record KnownEnd(long Offset);
    private union ReaderState(Reading, PcapEndOfFile, PcapError, ExceptionDispatchInfo);
    private sealed record Reading;
    private union BlockResult(PcapNgBlock, PcapEndOfFile, PcapError);
    private union ProcessResult(PcapNgPacket, Skipped, PcapError);
    private sealed record Skipped;
}
