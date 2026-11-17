using System.Collections.Immutable;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis.Pcap;

public sealed class PcapNgAnalysisReader : IDisposable
{
    private readonly PcapNgReader reader;
    private readonly IpReassemblyAnalysisOptions reassemblyOptions;
    private readonly Dictionary<PcapNgInterface, IpReassemblyAnalyzer> interfaceAnalyzers = [];
    private long recordNumber;
    private bool disposed;

    public PcapNgAnalysisReader(PcapNgReader reader, IpReassemblyAnalysisOptions? reassemblyOptions = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        this.reader = reader;
        this.reassemblyOptions = reassemblyOptions ?? new();
    }

    public IReadOnlyList<PcapNgSection> Sections => reader.Sections;
    public IReadOnlyList<PcapNgInterface> Interfaces => reader.Interfaces;
    public ImmutableArray<IpReassemblyEvent> ReassemblyEvents { get; private set; } = [];

    public static PcapNgAnalysisOpenResult Open(Stream stream, PcapNgReaderOptions? options = null,
        IpReassemblyAnalysisOptions? reassemblyOptions = null) =>
        PcapNgReader.Open(stream, options) switch
        {
            PcapNgReader reader => new PcapNgAnalysisReader(reader, reassemblyOptions),
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized PCAPNG open result.")
        };

    public PcapNgAnalysisReadResult ReadNext()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ReassemblyEvents = [];
        try
        {
            switch (reader.ReadNext())
            {
                case PcapNgPacket packet:
                    return Analyze(packet);
                case PcapEndOfFile eof:
                    ReassemblyEvents = Finish(IpReassemblyAnalysisReason.EndOfCapture);

                    return eof;
                case PcapError error:
                    ReassemblyEvents = Finish(IpReassemblyAnalysisReason.Aborted);

                    return error;
                default:
                    throw new InvalidOperationException("Uninitialized PCAPNG read result.");
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
        var linkLayer = packet.Interface.LinkType == 1 ? LinkLayerProtocol.Ethernet : LinkLayerProtocol.Unsupported;
        var decoding = ProtocolDecoder.Decode(packet.Data, linkLayer);
        var analyzed = new AnalyzedPcapNgPacket(++recordNumber, packet, decoding);
        var events = ImmutableArray.CreateBuilder<IpReassemblyEvent>();
        if (interfaceAnalyzers.Keys.FirstOrDefault() is { } previous && previous.Section.Number != packet.Interface.Section.Number)
            events.AddRange(Finish(IpReassemblyAnalysisReason.EndOfSection));
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
        disposed = true;
    }
}
