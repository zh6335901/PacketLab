using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis.Pcap;

public sealed record AnalyzedPcapNgPacket(long RecordNumber, PcapNgPacket Packet, ProtocolDecodeResult Decoding);
