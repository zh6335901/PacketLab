using PacketLab.Analyzers.Annotations;
using PacketLab.Desktop.Localization;
using PacketLab.Pcap;

namespace PacketLab.Desktop.Models.PacketExplorer;

[TransportModel]
internal readonly record struct CaptureRecord(long DataOffset, int Length, uint OriginalLength, CaptureTime Time,
    PacketSummary Summary, PcapNgInterface? Interface, PcapNgPacketKind? Kind, FragmentSlice? Fragment)
{
    internal ushort LinkType(PcapFileHeader? header) => Interface?.LinkType ?? header?.LinkType ?? 0;
    internal string Context => Interface is { } item ? $"S{item.Section.Number} / I{item.Id}" : Strings.Global;
    internal string Block => Kind switch
    {
        PcapNgPacketKind.Enhanced => Strings.PcapNgEnhancedPacketBlock,
        PcapNgPacketKind.Simple => Strings.PcapNgSimplePacketBlock,
        PcapNgPacketKind.Obsolete => Strings.PcapNgPacketBlock,
        _ => Strings.PcapRecord
    };
}
