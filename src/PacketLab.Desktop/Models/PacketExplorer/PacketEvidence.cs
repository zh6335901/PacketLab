namespace PacketLab.Desktop.Models.PacketExplorer;

internal readonly record struct ByteRange(int Start, int Length)
{
    internal int End => Start + Length - 1;
    internal bool Contains(int offset) => offset >= Start && offset <= End;
    internal string Label => Start == End ? $"{Start:X4}" : $"{Start:X4}–{End:X4}";
}

internal sealed record PacketField(string Layer, string Name, string Value, ByteRange? Range);
internal sealed record PacketEvidence(byte[] Bytes, PacketSummary Summary, IReadOnlyList<PacketField> Fields);
