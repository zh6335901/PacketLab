using PacketLab.Desktop.Models.PacketExplorer;

namespace PacketLab.Desktop.Services.PacketExplorer;

internal static class RecordSearch
{
    internal static int[] Find(CaptureIndex capture, int count, RecordFilter filter, string query, CancellationToken token)
    {
        var matches = new List<int>();
        var numberSearch = query.Length > 1 && query[0] == '#' && query.AsSpan(1).IndexOfAnyExceptInRange('0', '9') < 0;
        for (var i = 0; i < count; i++)
        {
            if (i % 512 == 0)
                token.ThrowIfCancellationRequested();

            if (numberSearch && !MatchesNumber(i + 1, query.AsSpan(1)))
                continue;

            var record = capture.ReadRecord(i);
            var group = record.Fragment is null ? null : capture.Group(i);
            if (filter == RecordFilter.Fragments && !record.Fragment.HasValue)
                continue;
            if (filter == RecordFilter.Diagnostics && !RecordStatus.IsDiagnostic(record, group, i))
                continue;
            if (!numberSearch && query.Length > 0 && !Matches(record, group, i, query))
                continue;

            matches.Add(i);
        }

        return matches.ToArray();
    }

    private static bool MatchesNumber(int number, ReadOnlySpan<char> prefix)
    {
        Span<char> formatted = stackalloc char[10];
        number.TryFormat(formatted, out var written, "000");

        return formatted[..written].StartsWith(prefix, StringComparison.Ordinal);
    }

    private static bool Matches(CaptureRecord record, FragmentGroup? group, int index, string query)
    {
        var text = string.Join(' ', RecordStatus.Number(index),
            (index + 1).ToString(), record.Summary.Name,
            RecordStatus.Title(record, group, index).Text, record.Context, record.Summary.SourceAddress, record.Summary.DestinationAddress,
            RecordStatus.ForRecord(record, group, index).Label, group?.Identity);

        return text.Contains(query, StringComparison.OrdinalIgnoreCase) ||
            (query.Contains(':') && record.Time.Format(date: false).Contains(query, StringComparison.OrdinalIgnoreCase));
    }
}
