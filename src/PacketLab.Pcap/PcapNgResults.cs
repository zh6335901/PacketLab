namespace PacketLab.Pcap;

public union PcapNgOpenResult(PcapNgReader, PcapError);
public union PcapNgReadResult(PcapNgPacket, PcapEndOfFile, PcapError);
