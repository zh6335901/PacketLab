using PacketLab.Desktop.Localization;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PacketLab.Analyzers.Annotations;
using PacketLab.Protocols.IP.Reassembly;
using static PacketLab.Desktop.RecordStatus;

namespace PacketLab.Desktop.ViewModels;

[SuppressMessage("Design", "PL0001", Justification = "Evidence, coverage and the optional expanded comparison load independently for the selected record.")]
internal sealed class RecordInspectorViewModel : ObservableObject
{
    private const int FullPageSize = 3;
    private readonly SemaphoreSlim detailReads = new(1);
    private CaptureIndex? capture;
    private int recordRevision;
    private int evidenceRevision;
    private int fullRevision;
    private int fullPage;
    private bool fullOpen;
    private int? exact;
    private PacketField? field;

    internal RecordInspectorViewModel()
    {
        ChooseFieldCommand = new RelayCommand<PacketField>(ChooseField);
        ChooseSourceCommand = new RelayCommand<int>(record => ChooseEvidence(record, null));
        PickByteCommand = new RelayCommand<int>(offset => ChooseEvidence(Evidence?.Record ?? 0, offset));
        ToggleFullCommand = new RelayCommand(ToggleFull);
        PreviousPageCommand = new RelayCommand(() => ChangeFullPage(-1));
        NextPageCommand = new RelayCommand(() => ChangeFullPage(1));
    }

    public IRelayCommand<PacketField> ChooseFieldCommand { get; }
    public IRelayCommand<int> ChooseSourceCommand { get; }
    public IRelayCommand<int> PickByteCommand { get; }
    public IRelayCommand ToggleFullCommand { get; }
    public IRelayCommand PreviousPageCommand { get; }
    public IRelayCommand NextPageCommand { get; }
    public IndexedRow? Record { get; private set; }
    public EvidenceSource? Evidence { get; private set; }
    public FragmentCoverage? Coverage { get; private set; }
    public FullBytePage? FullPage { get; private set; }
    public ByteSelection Selection { get; private set; } = new(null, null, null, "", "", "", "", null);
    public string EvidenceMessage { get; private set; } = Strings.ReadingProtocolFields;
    public string? CoverageError { get; private set; }
    public string FullMessage { get; private set; } = "";
    public bool FullOpen => fullOpen;
    public string ToggleLabel => fullOpen ? Strings.HideFullBytes : Strings.ShowFullBytes;

    internal void Clear(bool resetFullBytes = false)
    {
        capture = null;
        Reset(null);
        if (resetFullBytes)
            SetFullOpen(false);
    }

    internal void Inspect(CaptureIndex capture, IndexedRow row)
    {
        this.capture = capture;
        Reset(row);
        _ = LoadEvidenceAsync(capture, row.Index, null);
        if (row.Group is { } group)
            _ = LoadCoverageAsync(capture, group, row.Index);
    }

    private void Reset(IndexedRow? row)
    {
        recordRevision++;
        evidenceRevision++;
        fullRevision++;
        fullPage = 0;
        Record = row;
        Evidence = null;
        Coverage = null;
        FullPage = null;
        field = null;
        exact = null;
        EvidenceMessage = Strings.ReadingProtocolFields;
        CoverageError = null;
        FullMessage = "";
        OnPropertyChanged(nameof(Record));
        UpdateSelection();
    }

    private async Task LoadEvidenceAsync(CaptureIndex current, int record, int? rawByte)
    {
        var revision = ++evidenceRevision;
        var group = Record?.Group;
        await detailReads.WaitAsync();
        try
        {
            if (revision != evidenceRevision || current != capture)
                return;

            var data = await Task.Run(() => ReadEvidence(current, record, group));
            if (revision != evidenceRevision || current != capture)
                return;

            Evidence = new(record, data);
            exact = rawByte;
            field = rawByte is { } offset ? FieldAt(data, offset) : DefaultField(data, record, group);
            OnPropertyChanged(nameof(Evidence));
            UpdateSelection();
        }
        catch (Exception exception) when (IsReadFailure(exception))
        {
            if (revision == evidenceRevision && current == capture)
            {
                Evidence = null;
                field = null;
                exact = null;
                var error = CaptureDiagnostics.ReadFailure(exception);
                EvidenceMessage = UiText.Format(Strings.CannotReadRecordBytes, error);
                OnPropertyChanged(nameof(Evidence));
                UpdateSelection();
            }
        }
        finally
        {
            detailReads.Release();
        }
    }

    private static PacketEvidence ReadEvidence(CaptureIndex current, int record, FragmentGroup? group)
    {
        if (record < 0 && group is not null)
            return PacketFields.Reassembled(current, group);

        return PacketFields.Original(current, current.ReadRecord(record));
    }

    private static PacketField DefaultField(PacketEvidence view, int record, FragmentGroup? group)
    {
        var name = (record, group, view.Summary) switch
        {
            (< 0, _, _) => Strings.DestinationPort,
            (_, not null, _) => Strings.Identification,
            (_, _, { Protocol: Protocol.Arp }) => Strings.TargetIp,
            (_, _, { Issue: var issue }) when issue.HasFlag(PacketIssue.Mismatch) => Strings.Checksum,
            (_, _, { Issue: var issue }) when issue.HasFlag(PacketIssue.Invalid) => Strings.UdpLength,
            _ => Strings.DestinationPort
        };

        return view.Fields.FirstOrDefault(item => item.Name == name)
            ?? view.Fields.FirstOrDefault(item => item.Name == Strings.DestinationPort)
            ?? view.Fields[0];
    }

    private static PacketField? FieldAt(PacketEvidence view, int offset) =>
        view.Fields.Where(candidate => candidate.Range?.Contains(offset) == true)
            .MinBy(candidate => candidate.Range!.Value.Length);

    private void ChooseField(PacketField? item)
    {
        if (item is null)
            return;

        field = item;
        exact = null;
        UpdateSelection();
    }

    internal void ChooseEvidence(int record, int? offset)
    {
        if (capture is not { } current)
            return;

        if (Evidence is not { } source || record != source.Record)
        {
            _ = LoadEvidenceAsync(current, record, offset);

            return;
        }

        evidenceRevision++;
        exact = offset;
        field = offset is { } index ? FieldAt(source.Data, index) : DefaultField(source.Data, record, Record?.Group);
        UpdateSelection();
    }

    private void UpdateSelection()
    {
        var range = field?.Range;
        var name = field is not null ? $"{field.Layer} / {field.Name}" : Strings.RawBytes;
        var bytes = Evidence?.Data.Bytes ?? [];
        (var rangeText, var raw) = (range, exact) switch
        {
            ({ } span, _) => ($"0x{span.Label} · {span.Length} B", PacketFields.Raw(bytes.AsSpan(span.Start, span.Length))),
            (null, { } index) => ($"0x{index:X4} · 1 B", bytes[index].ToString("X2")),
            _ => (Strings.UnknownBytePosition, "—")
        };
        var payload = PayloadOffset();
        var location = MakeLocation(payload);

        Selection = new(field, exact, payload, name, rangeText, raw, field?.Value ?? Strings.UnknownField, location);
        OnPropertyChanged(nameof(Selection));
    }

    private int? PayloadOffset()
    {
        if (exact is not { } index || Evidence is not { } source || Coverage?.Data.Lanes.FirstOrDefault(lane => lane.Record == source.Record) is not { } lane)
            return null;

        var offset = lane.PayloadOffset(index);

        return lane.Covers(offset) ? offset : null;
    }

    private string? MakeLocation(int? payload)
    {
        if (exact is not { } index || Evidence is not { } view || Coverage is not { } data)
            return null;

        var raw = view.Data.Bytes[index].ToString("X2");
        if (payload is { } offset)
        {
            var sources = data.Data.Lanes.Where(lane => lane.Covers(offset)).Select(lane =>
                $"{(lane.Derived ? lane.Label : UiText.Format(Strings.NamedFrame, lane.Label))} 0x{lane.RawIndex(offset):X4}");
            var labels = string.Join(" ↔ ", sources.Take(8));

            return UiText.Format(Strings.PayloadLocation, offset, labels, raw);
        }

        var source = view.Record < 0 ? Strings.ReassembledIp : UiText.Format(Strings.NamedFrame, Number(view.Record));

        return $"{source} 0x{index:X4}  ｜  {raw}";
    }

    internal int? FullByteOffset(CoverageLane lane)
    {
        if (Selection.Payload is { } offset && lane.Covers(offset))
            return lane.RawIndex(offset);

        return lane.Record == Evidence?.Record ? Selection.Exact : null;
    }

    private async Task LoadCoverageAsync(CaptureIndex current, FragmentGroup group, int record)
    {
        var revision = recordRevision;
        try
        {
            var data = await Task.Run(() => CoverageData.Load(current, group, record));
            if (revision != recordRevision || current != capture)
                return;

            Coverage = new(group, data, Summarize(group, data));
            OnPropertyChanged(nameof(Coverage));
            UpdateSelection();
            if (fullOpen)
                _ = LoadFullPageAsync(0);
        }
        catch (Exception exception) when (IsReadFailure(exception))
        {
            if (revision == recordRevision && current == capture)
            {
                var error = CaptureDiagnostics.ReadFailure(exception);
                CoverageError = UiText.Format(Strings.CannotReadFragmentBytes, error);
                OnPropertyChanged(nameof(Coverage));
            }
        }
    }

    private static CoverageSummary Summarize(FragmentGroup group, CoverageData data)
    {
        if (group.HasResult && group.DerivedSlice is { } slice)
            return new(UiText.Format(Strings.CompleteCoverage, slice.Length), UiText.Format(Strings.ReassembledDatagramSummary, group.DerivedLength, group.DerivedSummary.Transport), RecordTone.Good);
        if (group.Status == IpReassemblyStatus.Conflict && data.Overlap.Count > 0)
        {
            var same = data.Identical ? Strings.OverlapIdenticalBytes : Strings.OverlapDifferentBytes;
            var reason = group.Version == 6 ? Strings.Ipv6OverlapDiscarded : GroupDiagnostic(group);
            var ranges = data.Overlap.Take(4).Select(range => range.Length == 1 ? $"{range.Start}" : $"{range.Start}–{range.End}");
            var label = string.Join(Strings.ListSeparator, ranges);
            if (data.Overlap.Count > 4)
                label += UiText.Format(Strings.ReferenceGroupsSuffix, data.Overlap.Count);

            return new(Strings.ReassemblyDiscarded, UiText.Format(Strings.OverlapSummary, label, same, reason), RecordTone.Bad);
        }

        return new(Strings.NoReassembledDatagram, GroupDiagnostic(group), RecordTone.Warn);
    }

    private void ToggleFull()
    {
        SetFullOpen(!fullOpen);
        if (fullOpen && FullPage is null && Coverage is not null)
            _ = LoadFullPageAsync(fullPage);
    }

    private void SetFullOpen(bool value)
    {
        if (SetProperty(ref fullOpen, value, nameof(FullOpen)))
            OnPropertyChanged(nameof(ToggleLabel));
    }

    private void ChangeFullPage(int delta)
    {
        if (Coverage is { } item)
        {
            var page = Math.Clamp(fullPage + delta, 0, CountPages(item.Data.Lanes.Count) - 1);
            if (page != fullPage)
                _ = LoadFullPageAsync(page);
        }
    }

    private async Task LoadFullPageAsync(int page)
    {
        if (capture is not { } current || Coverage is not { } coverage)
            return;

        var revision = ++fullRevision;
        fullPage = page;
        FullPage = null;
        FullMessage = Strings.ReadingFullBytes;
        OnPropertyChanged(nameof(FullPage));
        try
        {
            var lanes = coverage.Data.Lanes.Skip(page * FullPageSize).Take(FullPageSize).ToArray();
            var dumps = await Task.Run(() => ReadLaneBytes(current, coverage.Group, lanes));
            if (revision != fullRevision)
                return;

            var pageCount = CountPages(coverage.Data.Lanes.Count);
            var firstIndex = page * FullPageSize;
            FullPage = new(lanes, dumps, firstIndex, $"{page + 1} / {pageCount}", pageCount > 1);
            OnPropertyChanged(nameof(FullPage));
        }
        catch (Exception exception) when (IsReadFailure(exception))
        {
            if (revision == fullRevision)
            {
                var error = CaptureDiagnostics.ReadFailure(exception);
                FullMessage = UiText.Format(Strings.CannotReadFullBytes, error);
                OnPropertyChanged(nameof(FullPage));
            }
        }
    }

    private static int CountPages(int lanes)
    {
        var pages = (lanes + FullPageSize - 1) / FullPageSize;

        return Math.Max(1, pages);
    }

    private static byte[][] ReadLaneBytes(CaptureIndex index, FragmentGroup group, IEnumerable<CoverageLane> lanes) =>
        lanes.Select(lane => lane.Derived ? index.ReadDerived(group) : index.ReadBytes(index.ReadRecord(lane.Record))).ToArray();

    private static bool IsReadFailure(Exception exception) => exception is IOException or UnauthorizedAccessException or ObjectDisposedException;
}

internal sealed record EvidenceSource(int Record, PacketEvidence Data)
{
    public string Origin => Record < 0 ? Strings.ReassembledIpDatagram : UiText.Format(Strings.OriginalRecord, Number(Record));
    public string Coordinates => Record < 0 ? Strings.ReassembledIpOrigin : Strings.FrameOrigin;
}

internal sealed record FragmentCoverage(FragmentGroup Group, CoverageData Data, CoverageSummary Summary);
internal sealed record CoverageSummary(string Title, string Message, RecordTone Tone);
internal sealed record FullBytePage(CoverageLane[] Lanes, byte[][] Dumps, int FirstIndex, string Caption, bool HasPages);

[TransportModel]
internal sealed record ByteSelection(PacketField? Field, int? Exact, int? Payload, string Name, string Range, string Raw,
    string Value, string? Location);
