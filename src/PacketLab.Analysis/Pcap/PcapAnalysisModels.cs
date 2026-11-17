using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis.Pcap;

public sealed record AnalyzedPacket(long RecordNumber, PcapPacket Packet, ProtocolDecodeResult Decoding);

public sealed record AnalyzedPcapNgPacket(long RecordNumber, PcapNgPacket Packet, ProtocolDecodeResult Decoding);

public union PcapAnalysisOpenResult(PcapAnalysisReader, PcapError);

public union PcapAnalysisReadResult(AnalyzedPacket, AnalyzedPcapNgPacket, PcapEndOfFile, PcapError);
