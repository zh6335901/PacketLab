using PacketLab.Desktop.Localization;
using PacketLab.Desktop.Models.PacketExplorer;

namespace PacketLab.Desktop.Services.PacketExplorer;

internal static class FragmentCoverageReader
{
    private const int MaxMappedBytes = 65_576;

    internal static CoverageData Load(CaptureIndex capture, FragmentGroup group, int selected)
    {
        var lanes = new List<CoverageLane>();
        var members = group.Records.Contains(selected) ? group.Records : group.Records.Add(selected);
        foreach (var index in members)
        {
            var record = capture.ReadRecord(index);
            if (record.Fragment is { } slice)
            {
                var flag = group.Version == 4 ? "MF" : "M";
                var range = slice.Length > 0 ? $"{slice.Offset}–{slice.End - 1} B" : UIText.Format(Strings.OffsetNoCapturedBytes, slice.Offset);
                var scope = $"{range} · {flag} {(slice.More ? 1 : 0)}";
                var bytes = capture.ReadFragment(record, MaxMappedBytes);
                lanes.Add(new(index, slice, bytes, scope));
            }
        }
        if (group.DerivedSlice is { } derived)
        {
            var raw = capture.ReadDerived(group);
            var payload = raw.AsSpan(derived.Start, derived.Length).ToArray();
            lanes.Add(new(-1, derived, payload, $"{group.DerivedLength} B · {group.DerivedSummary.Name}"));
        }

        return new(lanes);
    }
}
