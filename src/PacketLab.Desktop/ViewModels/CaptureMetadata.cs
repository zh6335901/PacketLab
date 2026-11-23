using PacketLab.Pcap;
using PacketLab.Analyzers.Annotations;

namespace PacketLab.Desktop;

internal sealed record MetadataFact(string Name, string Value);
internal sealed record InterfaceCard(string Id, string Name, string Description, string Link, string Order,
    string Resolution, string SnapLength, string Extra);

[TransportModel]
internal sealed record CaptureMetadata(IReadOnlyList<MetadataFact> CaptureFacts, IReadOnlyList<InterfaceCard> Interfaces,
    IReadOnlyList<MetadataFact> SectionsWithoutInterfaces, string? RecordTitle, IReadOnlyList<MetadataFact> RecordFacts, string Path)
{
    public bool HasInterfaces => Interfaces.Count > 0;
    public bool HasRecord => RecordTitle is not null;

    internal static CaptureMetadata Create(CaptureIndex index, CaptureSnapshot snapshot, IndexedRow? selected)
    {
        var file = $"{System.IO.Path.GetFileName(index.Path)} · {snapshot.Format}";
        var time = snapshot.TimedRecords == 0 ? "未提供" :
            $"{snapshot.FirstTime.Format(date: true)} – {snapshot.LastTime.Format(date: true)}（{snapshot.TimedRecords:N0} 条有时间）";
        var structure = snapshot.Header is not null ? "全局链路信息 · Section 不适用" :
            $"{snapshot.Sections.Count} 个 Section · {snapshot.Interfaces.Count} 个接口";
        var interfaces = snapshot.Header is { } header ? [GlobalInterface(header)] : snapshot.Interfaces.Select(Interface).ToArray();
        var sections = snapshot.Interfaces.Select(item => item.Section.Number).ToHashSet();
        var missing = snapshot.Sections.Where(section => !sections.Contains(section.Number)).Select(Section).ToArray();
        var recordTitle = selected is { } row ? $"当前记录 {RecordStatus.Number(row.Index)}" : null;
        var recordFacts = selected is { } active ? RecordMetadata(index, active) : [];

        return new([new("文件与格式", file), new("捕获时间", time), new("捕获结构", $"{snapshot.Count:N0} 条记录 · {structure}")],
            interfaces, missing, recordTitle, recordFacts, index.Path);
    }

    private static InterfaceCard GlobalInterface(PcapFileHeader header)
    {
        var precision = header.TimestampPrecision == PcapTimestampPrecision.Microseconds ? "1 μs" : "1 ns";
        var fcs = header.FcsLengthBytes is { } length ? $"{length} B" : "未提供";
        var link = LinkName(header.LinkType);

        return new("全局", "不适用", "接口名未提供", link, OrderName(header.ByteOrder),
            precision, SnapLength(header.SnapLen), $"FCS {fcs}");
    }

    private static InterfaceCard Interface(PcapNgInterface item)
    {
        var id = $"S{item.Section.Number} / I{item.Id}";
        var version = $"Section {item.Section.MajorVersion}.{item.Section.MinorVersion}";

        return new(id, item.Name ?? "未提供",
            item.Description ?? "描述未提供",
            LinkName(item.LinkType),
            OrderName(item.Section.ByteOrder),
            ResolutionName(item.TimestampResolution),
            SnapLength(item.SnapLen), $"{version} · 时间偏移 {item.TimestampOffsetSeconds} s");
    }

    private static MetadataFact Section(PcapNgSection section)
    {
        var detail = $"PCAPNG {section.MajorVersion}.{section.MinorVersion} · {OrderName(section.ByteOrder)} · 未提供接口";

        return new($"Section S{section.Number}", detail);
    }

    private static MetadataFact[] RecordMetadata(CaptureIndex index, IndexedRow selected)
    {
        var record = selected.Record;
        var source = $"{System.IO.Path.GetFileName(index.Path)} · 文件偏移 0x{record.DataOffset:X}";

        return
        [
            new("捕获上下文", $"{record.Block} · {record.Context} · {record.Time.Format(date: true)}"),
            new("记录注释", index.Comment(selected.Index)),
            new("报文字节来源", source)
        ];
    }

    private static string ResolutionName(byte resolution) => resolution switch
    {
        6 => "1 μs", 9 => "1 ns", 0 => "1 s",
        _ => $"{((resolution & 0x80) == 0 ? 10 : 2)}⁻^({resolution & 0x7f}) s"
    };

    private static string LinkName(ushort link) => link switch
    {
        1 => "Ethernet · 1", 101 => "Raw IP · 101", _ => $"类型 {link} · 未支持"
    };

    private static string OrderName(PcapByteOrder order) => order == PcapByteOrder.LittleEndian ? "小端" : "大端";
    private static string SnapLength(uint snap) => snap == 0 ? "无上限 · 0" : $"{snap} B";
}
