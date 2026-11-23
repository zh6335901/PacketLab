using PacketLab.Desktop.Localization;
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
        var time = snapshot.TimedRecords == 0 ? Strings.NotProvided :
            UiText.Format(Strings.TimedRecordRange,
                snapshot.FirstTime.Format(date: true),
                snapshot.LastTime.Format(date: true),
                snapshot.TimedRecords);
        var structure = snapshot.Header is not null ? Strings.GlobalLinkNoSection :
            UiText.Format(Strings.SectionsAndInterfaces, snapshot.Sections.Count, snapshot.Interfaces.Count);
        var interfaces = snapshot.Header is { } header ? [GlobalInterface(header)] : snapshot.Interfaces.Select(Interface).ToArray();
        var sections = snapshot.Interfaces.Select(item => item.Section.Number).ToHashSet();
        var missing = snapshot.Sections.Where(section => !sections.Contains(section.Number)).Select(Section).ToArray();
        var recordTitle = selected is { } row ? UiText.Format(Strings.CurrentRecord, RecordStatus.Number(row.Index)) : null;
        var recordFacts = selected is { } active ? RecordMetadata(index, active) : [];

        return new([new(Strings.FileAndFormat, file), new(Strings.CaptureTime, time), new(Strings.CaptureStructure, UiText.Format(Strings.CaptureRecordStructure, snapshot.Count, structure))],
            interfaces, missing, recordTitle, recordFacts, index.Path);
    }

    private static InterfaceCard GlobalInterface(PcapFileHeader header)
    {
        var precision = header.TimestampPrecision == PcapTimestampPrecision.Microseconds ? "1 μs" : "1 ns";
        var fcs = header.FcsLengthBytes is { } length ? $"{length} B" : Strings.NotProvided;
        var link = LinkName(header.LinkType);

        return new(Strings.Global, Strings.NotApplicable, Strings.NoInterfaceName, link, OrderName(header.ByteOrder),
            precision, SnapLength(header.SnapLen), $"FCS {fcs}");
    }

    private static InterfaceCard Interface(PcapNgInterface item)
    {
        var id = $"S{item.Section.Number} / I{item.Id}";
        var version = $"Section {item.Section.MajorVersion}.{item.Section.MinorVersion}";
        var timeOffset = UiText.Format(Strings.SectionTimestampOffset, version, item.TimestampOffsetSeconds);

        return new(id, item.Name ?? Strings.NotProvided,
            item.Description ?? Strings.NoDescription,
            LinkName(item.LinkType),
            OrderName(item.Section.ByteOrder),
            ResolutionName(item.TimestampResolution),
            SnapLength(item.SnapLen), timeOffset);
    }

    private static MetadataFact Section(PcapNgSection section)
    {
        var detail = UiText.Format(Strings.SectionWithoutInterfaces, section.MajorVersion, section.MinorVersion, OrderName(section.ByteOrder));

        return new($"Section S{section.Number}", detail);
    }

    private static MetadataFact[] RecordMetadata(CaptureIndex index, IndexedRow selected)
    {
        var record = selected.Record;
        var source = UiText.Format(Strings.SourceFileOffset, System.IO.Path.GetFileName(index.Path), record.DataOffset);

        return
        [
            new(Strings.CaptureContext, $"{record.Block} · {record.Context} · {record.Time.Format(date: true)}"),
            new(Strings.RecordComment, index.Comment(selected.Index)),
            new(Strings.PacketBytesSource, source)
        ];
    }

    private static string ResolutionName(byte resolution) => resolution switch
    {
        6 => "1 μs", 9 => "1 ns", 0 => "1 s",
        _ => $"{((resolution & 0x80) == 0 ? 10 : 2)}⁻^({resolution & 0x7f}) s"
    };

    private static string LinkName(ushort link) => link switch
    {
        1 => "Ethernet · 1", 101 => "Raw IP · 101", _ => UiText.Format(Strings.UnsupportedType, link)
    };

    private static string OrderName(PcapByteOrder order) => order == PcapByteOrder.LittleEndian ? Strings.LittleEndian : Strings.BigEndian;
    private static string SnapLength(uint snap) => snap == 0 ? Strings.Unlimited : $"{snap} B";
}
