using System.Collections.Immutable;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Pcap;
using PacketLab.Protocols;

using PacketLab.Analysis.Pcap;

namespace PacketLab.Testing;

public sealed class PcapNgAnalysisScenario : IDisposable
{
    private readonly PcapNgReader reader;
    private readonly IpReassemblyAnalysisOptions reassemblyOptions;
    private readonly Dictionary<PcapNgInterface, IpReassemblyAnalyzer> interfaceAnalyzers = [];
    private long recordNumber;
    private bool disposed;

    public PcapNgAnalysisScenario(PcapNgReader reader, IpReassemblyAnalysisOptions? reassemblyOptions = null)
    {
        ArgumentNullException.ThrowIfNull(reader);
        this.reader = reader;
        this.reassemblyOptions = reassemblyOptions ?? new();
    }

    public IReadOnlyList<PcapNgSection> Sections => reader.Sections;
    public IReadOnlyList<PcapNgInterface> Interfaces => reader.Interfaces;
    public ImmutableArray<IpReassemblyEvent> ReassemblyEvents { get; private set; } = [];

    public static PcapNgScenarioOpenResult Open(Stream stream, PcapNgReaderOptions? options = null,
        IpReassemblyAnalysisOptions? reassemblyOptions = null) =>
        PcapNgReader.Open(stream, options) switch
        {
            PcapNgReader reader => new PcapNgAnalysisScenario(reader, reassemblyOptions),
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized PCAPNG open result.")
        };

    public PcapNgScenarioReadResult ReadNext()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        ReassemblyEvents = [];
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
        events.AddRange(ReassemblySteps.Process(analyzer, analyzed.RecordNumber, packet.Timestamp?.GetNanoseconds(), analyzed.Decoding));
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

        foreach (var analyzer in interfaceAnalyzers.Values)
            analyzer.Dispose();
        interfaceAnalyzers.Clear();
        ReassemblyEvents = [];
        disposed = true;
    }
}

public union PcapNgScenarioOpenResult(PcapNgAnalysisScenario, PcapError);
public union PcapNgScenarioReadResult(AnalyzedPcapNgPacket, PcapEndOfFile, PcapError);
