using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis.Pcap;

public sealed record AnalyzedPcapNgPacket(long RecordNumber, PcapNgPacket Packet, ProtocolDecodeResult Decoding);

public union PcapNgAnalysisOpenResult(PcapNgAnalysisReader, PcapError);
public union PcapNgAnalysisReadResult(AnalyzedPcapNgPacket, PcapEndOfFile, PcapError);
