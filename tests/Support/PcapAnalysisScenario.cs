using System.Collections.Immutable;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Pcap;
using PacketLab.Protocols;

using PacketLab.Analysis.Pcap;

namespace PacketLab.Testing;

public sealed class PcapAnalysisScenario : IDisposable
{
    private readonly PcapReader reader;
    private long recordNumber;
    private readonly IpReassemblyAnalyzer reassemblyAnalyzer;
    private bool disposed;

    // Events from the most recent read, including expiry, EOF, and PCAP failures.
    public ImmutableArray<IpReassemblyEvent> ReassemblyEvents { get; private set; } = [];

    public PcapAnalysisScenario(PcapReader reader, IpReassemblyAnalysisOptions? reassemblyOptions = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        this.reader = reader;
        reassemblyAnalyzer = new(reassemblyOptions ?? new());
    }

    public PcapFileHeader Header => reader.Header;
    public LinkLayerProtocol LinkLayer => PcapAnalysis.GetLinkLayer(Header);

    public static PcapScenarioOpenResult Open(Stream stream, PcapReaderOptions? options = null,
        IpReassemblyAnalysisOptions? reassemblyOptions = null) =>
        PcapReader.Open(stream, options) switch
        {
            PcapReader reader => new PcapAnalysisScenario(reader, reassemblyOptions),
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized PCAP open result.")
        };

    public PcapScenarioReadResult ReadNext()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ReassemblyEvents = [];
        switch (reader.ReadNext())
        {
            case PcapPacket packet:
                var analyzed = new AnalyzedPacket(++recordNumber, packet, PcapAnalysis.Decode(Header, packet));
                ReassemblyEvents = ReassemblySteps.Process(reassemblyAnalyzer, analyzed.RecordNumber,
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

    // The stream remains owned by the caller; disposal only releases reassembly state.
    public void Dispose()
    {
        if (disposed)
            return;

        ReassemblyEvents = [];
        reassemblyAnalyzer.Dispose();
        disposed = true;
    }
}

public union PcapScenarioOpenResult(PcapAnalysisScenario, PcapError);
public union PcapScenarioReadResult(AnalyzedPacket, PcapEndOfFile, PcapError);
