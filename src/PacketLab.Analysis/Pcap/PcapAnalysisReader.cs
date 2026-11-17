using System.Collections.Immutable;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis.Pcap;

public sealed class PcapAnalysisReader : IDisposable
{
    private readonly CaptureReader reader;
    private readonly IpReassemblyAnalysisOptions reassemblyOptions;
    private readonly Dictionary<PcapNgInterface, IpReassemblyAnalyzer> interfaceAnalyzers = [];
    private long recordNumber;
    private readonly IpReassemblyAnalyzer reassemblyAnalyzer;
    private bool disposed;

    // Events from the most recent read, including expiry, EOF, and PCAP failures.
    public ImmutableArray<IpReassemblyEvent> ReassemblyEvents { get; private set; } = [];

    private PcapAnalysisReader(CaptureReader reader, IpReassemblyAnalysisOptions? reassemblyOptions)
    {
        this.reader = reader;
        this.reassemblyOptions = reassemblyOptions ?? new();
        reassemblyAnalyzer = new(this.reassemblyOptions);
    }

    public CaptureHeader CaptureHeader => reader.Header;
    public IReadOnlyList<PcapNgSection> Sections => reader.Sections;
    public IReadOnlyList<PcapNgInterface> Interfaces => reader.Interfaces;
    public PcapFileHeader Header => CaptureHeader is PcapFileHeader classic ? classic
        : throw new InvalidOperationException("PCAPNG has per-interface headers; use CaptureHeader and packet.Interface.");
    public LinkLayerProtocol LinkLayer => CaptureHeader is PcapFileHeader classic ? PcapAnalysis.GetLinkLayer(classic) : LinkLayerProtocol.Unsupported;

    public static PcapAnalysisOpenResult Open(Stream stream, PcapReaderOptions? options = null,
        IpReassemblyAnalysisOptions? reassemblyOptions = null, PcapNgReaderOptions? pcapNgOptions = null) =>
        CaptureReader.Open(stream, options, pcapNgOptions) switch
        {
            CaptureReader reader => new PcapAnalysisReader(reader, reassemblyOptions),
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
                case PcapNgPacket packet:
                    return Analyze(packet);
                case PcapEndOfFile eof:
                    ReassemblyEvents = Finish(IpReassemblyAnalysisReason.EndOfCapture);

                    return eof;
                case PcapError error:
                    ReassemblyEvents = Finish(IpReassemblyAnalysisReason.Aborted);

                    return error;
                default:
                    throw new InvalidOperationException("Uninitialized PCAP read result.");
            }
        }
        catch
        {
            ReassemblyEvents = Finish(IpReassemblyAnalysisReason.Aborted);
            throw;
        }
    }

    private AnalyzedPcapNgPacket Analyze(PcapNgPacket packet)
    {
        var analyzed = new AnalyzedPcapNgPacket(++recordNumber, packet, PcapAnalysis.Decode(packet));
        var events = ImmutableArray.CreateBuilder<IpReassemblyEvent>();
        if (interfaceAnalyzers.Keys.FirstOrDefault() is { } previous && previous.Section.Number != packet.Interface.Section.Number)
            events.AddRange(FinishInterfaces(IpReassemblyAnalysisReason.EndOfSection));
        if (!interfaceAnalyzers.TryGetValue(packet.Interface, out var analyzer))
        {
            analyzer = new IpReassemblyAnalyzer(reassemblyOptions);
            interfaceAnalyzers.Add(packet.Interface, analyzer);
        }
        events.AddRange(analyzer.Process(analyzed.RecordNumber, packet.Timestamp?.GetNanoseconds(), analyzed.Decoding));
        ReassemblyEvents = events.ToImmutable();

        return analyzed;
    }

    private ImmutableArray<IpReassemblyEvent> Finish(IpReassemblyAnalysisReason reason)
    {
        var events = ImmutableArray.CreateBuilder<IpReassemblyEvent>();
        events.AddRange(reassemblyAnalyzer.Finish(reason));
        events.AddRange(FinishInterfaces(reason));

        return events.ToImmutable();
    }

    private ImmutableArray<IpReassemblyEvent> FinishInterfaces(IpReassemblyAnalysisReason reason)
    {
        var events = ImmutableArray.CreateBuilder<IpReassemblyEvent>();
        foreach (var analyzer in interfaceAnalyzers.Values)
        {
            events.AddRange(analyzer.Finish(reason));
            analyzer.Dispose();
        }
        interfaceAnalyzers.Clear();

        return events.ToImmutable();
    }

    // The stream remains owned by the caller; disposal only releases reassembly state.
    public void Dispose()
    {
        if (disposed)
            return;

        ReassemblyEvents = Finish(IpReassemblyAnalysisReason.Aborted);
        reassemblyAnalyzer.Dispose();
        disposed = true;
    }
}
