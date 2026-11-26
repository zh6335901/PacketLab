using PacketLab.Analyzers.Annotations;

namespace PacketLab.Desktop.Models.PacketExplorer;

internal sealed record MetadataFact(string Name, string Value);
internal sealed record InterfaceCard(string Id, string Name, string Description, string Link, string Order,
    string Resolution, string SnapLength, string Extra);

[TransportModel]
internal sealed record CaptureMetadata(IReadOnlyList<MetadataFact> CaptureFacts, IReadOnlyList<InterfaceCard> Interfaces,
    IReadOnlyList<MetadataFact> SectionsWithoutInterfaces, string? RecordTitle, IReadOnlyList<MetadataFact> RecordFacts, string Path)
{
    public bool HasInterfaces => Interfaces.Count > 0;
    public bool HasRecord => RecordTitle is not null;
}
