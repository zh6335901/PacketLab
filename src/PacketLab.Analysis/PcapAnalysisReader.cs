using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis;

public sealed record AnalyzedPacket(long RecordNumber, PcapPacket Packet, ProtocolDecodeResult Decoding);

public union PcapAnalysisOpenResult(PcapAnalysisReader, PcapError);

public union PcapAnalysisReadResult(AnalyzedPacket, PcapEndOfFile, PcapError);

public sealed class PcapAnalysisReader
{
    private readonly PcapReader reader;
    private long recordNumber;

    private PcapAnalysisReader(PcapReader reader)
    {
        this.reader = reader;
    }

    public PcapFileHeader Header => reader.Header;
    public LinkLayerProtocol LinkLayer => PcapAnalysis.GetLinkLayer(Header);

    public static PcapAnalysisOpenResult Open(Stream stream, PcapReaderOptions? options = null) =>
        PcapReader.Open(stream, options) switch
        {
            PcapReader reader => new PcapAnalysisReader(reader),
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized PCAP open result.")
        };

    public PcapAnalysisReadResult ReadNext() => reader.ReadNext() switch
    {
        PcapPacket packet => new AnalyzedPacket(++recordNumber, packet, PcapAnalysis.Decode(Header, packet)),
        PcapEndOfFile eof => eof,
        PcapError error => error,
        null => throw new InvalidOperationException("Uninitialized PCAP read result.")
    };
}
