using PacketLab.Analyzers.Annotations;
using PacketLab.Pcap;

namespace PacketLab.Desktop.Models.PacketExplorer;

[TransportModel]
internal sealed record CaptureSnapshot(int Count, int Groups, int Diagnostics, string Format, PcapFileHeader? Header,
    IReadOnlyList<PcapNgSection> Sections, IReadOnlyList<PcapNgInterface> Interfaces, CaptureTime FirstTime,
    CaptureTime LastTime, int TimedRecords, string? Error);
