namespace PacketLab.Desktop.Models.PacketExplorer;

internal readonly record struct IndexedRow(int Index, CaptureRecord Record, FragmentGroup? Group);
