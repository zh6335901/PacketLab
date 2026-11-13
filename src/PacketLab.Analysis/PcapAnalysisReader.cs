using System.Collections.Immutable;
using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis;

public sealed record AnalyzedPacket(long RecordNumber, PcapPacket Packet, ProtocolDecodeResult Decoding);

public union PcapAnalysisOpenResult(PcapAnalysisReader, PcapError);

public union PcapAnalysisReadResult(AnalyzedPacket, PcapEndOfFile, PcapError);

public sealed class PcapAnalysisReader : IDisposable
{
    private readonly PcapReader reader;
    private long recordNumber;
    private readonly IpFragmentReassembler reassembler;
    private bool disposed;

    // Events from the most recent read, including expiry, EOF, and PCAP failures.
    public ImmutableArray<IpReassemblyEvent> ReassemblyEvents { get; private set; } = [];

    private PcapAnalysisReader(PcapReader reader, IpReassemblyOptions? reassemblyOptions)
    {
        this.reader = reader;
        reassembler = new(reassemblyOptions ?? new());
    }

    public PcapFileHeader Header => reader.Header;
    public LinkLayerProtocol LinkLayer => PcapAnalysis.GetLinkLayer(Header);

    public static PcapAnalysisOpenResult Open(Stream stream, PcapReaderOptions? options = null,
        IpReassemblyOptions? reassemblyOptions = null) =>
        PcapReader.Open(stream, options) switch
        {
            PcapReader reader => new PcapAnalysisReader(reader, reassemblyOptions),
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized PCAP open result.")
        };

    public PcapAnalysisReadResult ReadNext()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ReassemblyEvents = [];
        try
        {
            switch (reader.ReadNext())
            {
                case PcapPacket packet:
                    var analyzed = new AnalyzedPacket(++recordNumber, packet, PcapAnalysis.Decode(Header, packet));
                    ReassemblyEvents = reassembler.Process(analyzed);
                    return analyzed;
                case PcapEndOfFile eof:
                    ReassemblyEvents = reassembler.Finish(IpReassemblyStatus.IncompleteAtEndOfFile);
                    return eof;
                case PcapError error:
                    ReassemblyEvents = reassembler.Finish(IpReassemblyStatus.Aborted);
                    return error;
                default:
                    throw new InvalidOperationException("Uninitialized PCAP read result.");
            }
        }
        catch
        {
            ReassemblyEvents = reassembler.Finish(IpReassemblyStatus.Aborted);
            throw;
        }
    }

    // The stream remains owned by the caller; disposal only releases reassembly state.
    public void Dispose()
    {
        if (disposed) return;
        ReassemblyEvents = reassembler.Finish(IpReassemblyStatus.Aborted);
        disposed = true;
    }
}
