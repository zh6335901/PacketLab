using System.Collections.Immutable;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis.Pcap;

public sealed class PcapAnalysisReader : IDisposable
{
    private readonly PcapReader reader;
    private long recordNumber;
    private readonly IpReassemblyAnalyzer reassemblyAnalyzer;
    private bool disposed;

    // Events from the most recent read, including expiry, EOF, and PCAP failures.
    public ImmutableArray<IpReassemblyEvent> ReassemblyEvents { get; private set; } = [];

    private PcapAnalysisReader(PcapReader reader, IpReassemblyAnalysisOptions? reassemblyOptions)
    {
        this.reader = reader;
        reassemblyAnalyzer = new(reassemblyOptions ?? new());
    }

    public PcapFileHeader Header => reader.Header;
    public LinkLayerProtocol LinkLayer => PcapAnalysis.GetLinkLayer(Header);

    public static PcapAnalysisOpenResult Open(Stream stream, PcapReaderOptions? options = null,
        IpReassemblyAnalysisOptions? reassemblyOptions = null) =>
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
                    ReassemblyEvents = reassemblyAnalyzer.Process(analyzed.RecordNumber,
                        PcapAnalysis.GetTimestampNanoseconds(packet.Timestamp), analyzed.Decoding);
                    return analyzed;
                case PcapEndOfFile eof:
                    ReassemblyEvents = reassemblyAnalyzer.Finish(IpReassemblyAnalysisReason.EndOfCapture);
                    return eof;
                case PcapError error:
                    ReassemblyEvents = reassemblyAnalyzer.Finish(IpReassemblyAnalysisReason.Aborted);
                    return error;
                default:
                    throw new InvalidOperationException("Uninitialized PCAP read result.");
            }
        }
        catch
        {
            ReassemblyEvents = reassemblyAnalyzer.Finish(IpReassemblyAnalysisReason.Aborted);
            throw;
        }
    }

    // The stream remains owned by the caller; disposal only releases reassembly state.
    public void Dispose()
    {
        if (disposed) return;
        ReassemblyEvents = reassemblyAnalyzer.Finish(IpReassemblyAnalysisReason.Aborted);
        reassemblyAnalyzer.Dispose();
        disposed = true;
    }
}
