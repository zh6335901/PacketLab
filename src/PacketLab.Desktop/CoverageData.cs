namespace PacketLab.Desktop;

internal sealed record CoverageLane(int Record, FragmentSlice Slice, byte[] Bytes, string Scope)
{
    internal bool Derived => Record < 0;
    internal string Label => Derived ? "重组 IP" : RecordStatus.Number(Record);
    internal int RawIndex(int offset) => Slice.Start + offset - Slice.Offset;
    internal int PayloadOffset(int raw) => Slice.Offset + raw - Slice.Start;
    internal bool Covers(int offset) => offset >= Slice.Offset && offset < Slice.Offset + Bytes.Length;
}

internal sealed class CoverageData
{
    internal const int MaxMappedBytes = 65_576;
    internal IReadOnlyList<CoverageLane> Lanes { get; }
    internal int FirstOffset { get; }
    internal int Bands { get; }
    internal int[] Owners { get; }
    internal int[] FirstOwner { get; }
    internal IReadOnlyList<ByteRange> Overlap { get; }
    internal bool Identical { get; }

    internal CoverageData(IReadOnlyList<CoverageLane> lanes)
    {
        Lanes = lanes;
        var max = lanes.Count == 0 ? 0 : lanes.Max(lane => lane.Slice.Offset + lane.Bytes.Length);
        FirstOffset = 0;
        var bandCount = (max - FirstOffset + 7) / 8;
        Bands = Math.Max(1, bandCount);
        Owners = new int[Bands * 8];
        FirstOwner = new int[Owners.Length];
        var identical = true;
        for (var laneIndex = 0; laneIndex < lanes.Count; laneIndex++)
        {
            var lane = lanes[laneIndex];
            if (lane.Derived)
                continue;

            var start = lane.Slice.Offset - FirstOffset;
            for (var b = 0; b < lane.Bytes.Length; b++)
            {
                var offset = start + b;
                if (Owners[offset]++ == 0)
                    FirstOwner[offset] = laneIndex;
                else
                {
                    var first = lanes[FirstOwner[offset]];
                    var firstIndex = offset + FirstOffset - first.Slice.Offset;
                    identical &= lane.Bytes[b] == first.Bytes[firstIndex];
                }
            }
        }
        Overlap = FindOverlap(Owners);
        Identical = identical;
    }

    private static List<ByteRange> FindOverlap(int[] owners)
    {
        var ranges = new List<ByteRange>();
        var offset = 0;
        while (offset < owners.Length)
        {
            if (owners[offset] <= 1)
            {
                offset++;
                continue;
            }

            var start = offset++;
            while (offset < owners.Length && owners[offset] > 1)
                offset++;
            ranges.Add(new(start, offset - start));
        }

        return ranges;
    }

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
                var range = slice.Length > 0 ? $"{slice.Offset}–{slice.End - 1} B" : $"{slice.Offset} B · 无捕获字节";
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
