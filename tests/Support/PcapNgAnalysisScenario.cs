using PacketLab.Pcap;
using PacketLab.Analysis.Pcap;

namespace PacketLab.Testing;

internal sealed class PcapNgAnalysisScenario
{
    private readonly PcapNgReader reader;
    private long recordNumber;

    internal PcapNgAnalysisScenario(PcapNgReader reader) => this.reader = reader;

    public IReadOnlyList<PcapNgSection> Sections => reader.Sections;
    public IReadOnlyList<PcapNgInterface> Interfaces => reader.Interfaces;

    public static PcapNgScenarioOpenResult Open(Stream stream, PcapNgReaderOptions? options = null) =>
        PcapNgReader.Open(stream, options) switch
        {
            PcapNgReader reader => new PcapNgAnalysisScenario(reader),
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized PCAPNG open result.")
        };

    public PcapNgScenarioReadResult ReadNext() => reader.ReadNext() switch
    {
        PcapNgPacket packet => new AnalyzedPcapNgPacket(++recordNumber, packet, PcapAnalysis.Decode(packet)),
        PcapEndOfFile eof => eof,
        PcapError error => error,
        null => throw new InvalidOperationException("Uninitialized read result.")
    };
}

internal union PcapNgScenarioOpenResult(PcapNgAnalysisScenario, PcapError);
internal union PcapNgScenarioReadResult(AnalyzedPcapNgPacket, PcapEndOfFile, PcapError);
