using System.Diagnostics;
using System.Runtime.ExceptionServices;

namespace PacketLab.Pcap;

public sealed class PcapReader
{
    private readonly PcapInput input;
    private readonly PcapReaderOptions options;
    private long recordNumber = 1;
    private ReaderState state = new Reading();

    private PcapReader(PcapInput input, PcapFileHeader header, PcapReaderOptions options)
    {
        this.input = input;
        Header = header;
        this.options = options;
    }

    public PcapFileHeader Header { get; }

    // The caller retains stream ownership even when opening fails.
    public static PcapOpenResult Open(Stream stream, PcapReaderOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(stream);
        if (!stream.CanRead)
            throw new ArgumentException("The stream must be readable.", nameof(stream));

        var input = new PcapInput(stream);
        var settings = options ?? PcapReaderOptions.Default;
        Span<byte> bytes = stackalloc byte[24];
        return input.ReadBlock(bytes) switch
        {
            BlockReadResult.Complete => PcapParser.ParseHeader(bytes) switch
            {
                PcapFileHeader header => new PcapReader(input, header, settings),
                PcapError error => error,
                null => throw new InvalidOperationException("Uninitialized header parse result.")
            },
            BlockReadResult.Incomplete partial => (PcapError)new PcapError.IncompleteFileHeader(partial.ReadBytes),
            null => throw new InvalidOperationException("Uninitialized block read result.")
        };
    }

    public PcapReadResult ReadNext()
    {
        switch (state)
        {
            case Reading:
                try
                {
                    return ReadRecord();
                }
                catch (Exception exception)
                {
                    // A partial read cannot be resumed at the next record boundary.
                    state = ExceptionDispatchInfo.Capture(exception);
                    throw;
                }
            case PcapEndOfFile eof:
                return eof;
            case PcapError error:
                return error;
            case ExceptionDispatchInfo failure:
                failure.Throw();
                throw new UnreachableException();
            default:
                throw new InvalidOperationException("Uninitialized reader state.");
        }
    }

    private PcapReadResult ReadRecord()
    {
        var recordOffset = input.Offset;
        Span<byte> bytes = stackalloc byte[16];
        return input.ReadBlock(bytes) switch
        {
            BlockReadResult.Complete => PcapParser.ValidatedPacketHeader.Parse(bytes, Header, recordOffset, recordNumber, options) switch
            {
                PcapParser.ValidatedPacketHeader packet => ReadPayload(packet),
                PcapError error => Fail(error),
                null => throw new InvalidOperationException("Uninitialized record parse result.")
            },
            BlockReadResult.Incomplete { ReadBytes: 0 } => End(),
            BlockReadResult.Incomplete partial => Fail(new PcapError.IncompleteRecordHeader(recordOffset, recordNumber, partial.ReadBytes)),
            null => throw new InvalidOperationException("Uninitialized block read result.")
        };
    }

    private PcapReadResult ReadPayload(PcapParser.ValidatedPacketHeader packet)
    {
        var dataOffset = input.Offset;
        var data = new byte[packet.CapturedLength];
        return input.ReadBlock(data) switch
        {
            BlockReadResult.Complete => FinishPacket(packet, data),
            BlockReadResult.Incomplete partial => Fail(new PcapError.IncompletePacketData(
                dataOffset, recordNumber, data.Length, partial.ReadBytes)),
            null => throw new InvalidOperationException("Uninitialized block read result.")
        };
    }

    private PcapReadResult FinishPacket(PcapParser.ValidatedPacketHeader packet, byte[] data)
    {
        recordNumber++;
        return new PcapPacket(packet.Timestamp, packet.OriginalLength, data);
    }

    private PcapReadResult Fail(PcapError error)
    {
        state = error;
        return error;
    }

    private PcapReadResult End()
    {
        var eof = new PcapEndOfFile();
        state = eof;
        return eof;
    }

    private union ReaderState(Reading, PcapEndOfFile, PcapError, ExceptionDispatchInfo);
    private sealed record Reading;
}
