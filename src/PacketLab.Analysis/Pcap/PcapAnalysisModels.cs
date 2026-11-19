using PacketLab.Pcap;
using PacketLab.Protocols;

namespace PacketLab.Analysis.Pcap;

public sealed record AnalyzedPacket(long RecordNumber, PcapPacket Packet, ProtocolDecodeResult Decoding);
