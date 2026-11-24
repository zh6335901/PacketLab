using PacketLab.Desktop.Localization;
using System.Diagnostics.CodeAnalysis;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PacketLab.Analyzers.Annotations;
using PacketLab.Desktop.Models.PacketExplorer;
using PacketLab.Desktop.Services.PacketExplorer;
using PacketLab.Desktop.ViewModels.Shell;

namespace PacketLab.Desktop.ViewModels.PacketExplorer;

[SuppressMessage("Design", "PL0001", Justification = "The active capture, pending operations and metadata popup have independent lifetimes.")]
internal sealed class ExplorerViewModel : ObservableObject, IDisposable
{
    private readonly Func<Task<string?>> chooseFile;
    private readonly CancellationTokenSource lifetime = new();
    private CaptureSnapshot snapshot = new(0, 0, 0, "—", null, [], [], default, default, 0, null);
    private CaptureIndex? capture;
    private CancellationTokenSource? filterCancellation;
    private RecordFilter filter;
    private string query = "";
    private int selected = -1;
    private bool loading;
    private bool updatingItems;
    private bool disposed;
    private int loadRevision;
    private string? openError;
    private RecordItems items = new(0, filtered: null);
    private CaptureMetadata? metadata;

    internal ExplorerViewModel(Func<Task<string?>> chooseFile)
    {
        this.chooseFile = chooseFile;
        Header = BuildHeader();
        ChooseFileCommand = new AsyncRelayCommand(PickFileAsync, () => !loading);
        SetFilterCommand = new RelayCommand<RecordFilter>(SetFilter);
        ClearFilterCommand = new RelayCommand(ClearFilter);
        ShowMetadataCommand = new RelayCommand(ShowMetadata);
        CloseMetadataCommand = new RelayCommand(() => Metadata = null, () => HasMetadata);
    }

    public IAsyncRelayCommand ChooseFileCommand { get; }
    public IRelayCommand<RecordFilter> SetFilterCommand { get; }
    public IRelayCommand ClearFilterCommand { get; }
    public IRelayCommand ShowMetadataCommand { get; }
    public IRelayCommand CloseMetadataCommand { get; }
    public ToolNavigationViewModel Navigation { get; } = new();
    public RecordInspectorViewModel Inspector { get; } = new();
    public ExplorerHeader Header { get; private set; }
    public RecordItems Items => items;
    public string ListCount => $"{items.Count:N0} / {snapshot.Count:N0}";
    public string FooterCount => UIText.Format(Strings.DisplayedRecordCount, ListCount);
    public bool NoMatches => snapshot.Count > 0 && items.Count == 0;
    public bool AllSelected => filter == RecordFilter.All;
    public bool DiagnosticsSelected => filter == RecordFilter.Diagnostics;
    public bool FragmentsSelected => filter == RecordFilter.Fragments;
    public object? SelectedItem
    {
        get => items.Contains(selected) ? selected : null;
        set
        {
            if (!updatingItems && value is int index && index != selected)
                SelectRecord(index);
        }
    }


    public CaptureMetadata? Metadata
    {
        get => metadata;
        private set
        {
            if (SetProperty(ref metadata, value))
            {
                OnPropertyChanged(nameof(HasMetadata));
                CloseMetadataCommand.NotifyCanExecuteChanged();
            }
        }
    }

    public bool HasMetadata => Metadata is not null;

    public string Query
    {
        get => query;
        set
        {
            if (SetProperty(ref query, value))
                _ = RefreshAsync(debounce: true, refreshSelection: false);
        }
    }

    internal IndexedRow ReadRow(int index) => new(index, capture!.ReadRecord(index), capture.Group(index));
    internal int SelectedRecord => selected;
    internal FragmentGroup? SelectedGroup => Inspector.Record?.Group;

    private async Task PickFileAsync()
    {
        if (loading || disposed)
            return;

        try
        {
            if (await chooseFile() is { } path)
                await OpenAsync(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            if (!disposed)
            {
                openError = Strings.FilePickerError;
                UpdateHeader();
            }
        }
    }

    internal async Task OpenAsync(string path)
    {
        if (loading || disposed)
            return;

        Metadata = null;
        Navigation.CloseDrawerCommand.Execute(null);
        var token = lifetime.Token;
        var revision = ++loadRevision;
        SetLoading(true);
        openError = null;
        UpdateHeader();
        CaptureIndex? candidate = null;
        try
        {
            var current = new CaptureIndex(path);
            candidate = current;
            IProgress<CaptureSnapshot> progress = new Progress<CaptureSnapshot>(partial =>
            {
                if (revision == loadRevision && loading && !token.IsCancellationRequested && partial.Count > 0)
                    _ = PublishAsync(current, partial);
            });
            var complete = await Task.Run(() => current.Scan(progress.Report, token), token);
            token.ThrowIfCancellationRequested();
            SetLoading(false);
            if (complete.Format == "—")
                ShowOpenError(path, complete.Error ?? Strings.UnrecognizedCapture);
            else
                await PublishAsync(current, complete);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            if (!token.IsCancellationRequested)
            {
                SetLoading(false);
                ShowOpenError(path, CaptureDiagnostics.ReadFailure(exception));
            }
        }
        finally
        {
            if (candidate != capture)
                candidate?.Dispose();
            if (token.IsCancellationRequested)
                capture?.Dispose();
        }
    }

    private void SetLoading(bool value)
    {
        loading = value;
        ChooseFileCommand.NotifyCanExecuteChanged();
    }

    private Task PublishAsync(CaptureIndex current, CaptureSnapshot next)
    {
        if (current != capture)
        {
            Metadata = null;
            filterCancellation?.Cancel();
            Inspector.Clear(resetFullBytes: true);
            selected = -1;
            SetProperty(ref query, "", nameof(Query));
            filter = RecordFilter.All;
            NotifyFilter();
            var previous = capture;
            capture = current;
            previous?.Dispose();
        }
        snapshot = next;
        UpdateHeader();
        if (!loading || filter == RecordFilter.All && string.IsNullOrWhiteSpace(query))
            return RefreshAsync(refreshSelection: !loading, debounce: false);

        return Task.CompletedTask;
    }

    private void ShowOpenError(string path, string message)
    {
        openError = UIText.Format(Strings.FileErrorForName, Path.GetFileName(path), message);
        UpdateHeader();
    }

    private void UpdateHeader()
    {
        Header = BuildHeader();
        OnPropertyChanged(nameof(Header));
    }

    private ExplorerHeader BuildHeader()
    {
        var path = capture?.Path;
        var name = Path.GetFileName(path) ?? "";
        var (title, hint, action) = (loading, path) switch
        {
            (true, _) => (Strings.ReadingCapture, Strings.ReadingLocalFile, Strings.Reading),
            (false, not null) => (Strings.NoPreviewableRecords, UIText.Format(Strings.EmptyCapture, name), Strings.ChooseAnotherFile),
            _ => (Strings.OpenCapture, Strings.ChooseCaptureHint, Strings.ChooseFile)
        };
        var footer = loading ? Strings.IndexingCapture : path ?? "";
        var error = openError ?? snapshot.Error;
        var count = snapshot.Count.ToString("00");
        var groups = snapshot.Groups.ToString("00");
        var diagnostics = snapshot.Diagnostics.ToString("00");

        return new(snapshot.Count > 0, name, snapshot.Format, count, groups, diagnostics, footer, error, title, hint, action);
    }

    private void SetFilter(RecordFilter requested)
    {
        filter = requested;
        NotifyFilter();
        _ = RefreshAsync(debounce: false, refreshSelection: false);
    }

    private void ClearFilter()
    {
        filter = RecordFilter.All;
        SetProperty(ref query, "", nameof(Query));
        NotifyFilter();
        _ = RefreshAsync(debounce: false, refreshSelection: false);
    }

    private void NotifyFilter()
    {
        OnPropertyChanged(nameof(AllSelected));
        OnPropertyChanged(nameof(DiagnosticsSelected));
        OnPropertyChanged(nameof(FragmentsSelected));
    }

    private async Task RefreshAsync(bool debounce, bool refreshSelection)
    {
        filterCancellation?.Cancel();
        using var cancellation = new CancellationTokenSource();
        filterCancellation = cancellation;
        var token = cancellation.Token;
        var current = capture;
        var count = snapshot.Count;
        var text = query.Trim();
        var mode = filter;
        try
        {
            if (mode == RecordFilter.All && text.Length == 0 || current is null)
                ApplyItems(new RecordItems(count, filtered: null), refreshSelection);
            else
            {
                if (debounce)
                    await Task.Delay(125, token);

                var matches = await Task.Run(() => RecordSearch.Find(current, count, mode, text, token), token);
                if (filterCancellation == cancellation && !token.IsCancellationRequested)
                    ApplyItems(new RecordItems(count, matches), refreshSelection);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        finally
        {
            if (filterCancellation == cancellation)
                filterCancellation = null;
        }
    }

    private void ApplyItems(RecordItems next, bool refreshSelection)
    {
        var first = next.Count > 0 ? next.RecordAt(0) : -1;
        var index = next.Contains(selected) ? selected : first;
        updatingItems = true;
        items = next;
        OnPropertyChanged(nameof(Items));
        OnPropertyChanged(nameof(ListCount));
        OnPropertyChanged(nameof(FooterCount));
        OnPropertyChanged(nameof(NoMatches));
        if (index < 0)
            Inspector.Clear(resetFullBytes: false);
        else if (index != selected || refreshSelection || Inspector.Record is null)
            SelectRecord(index);

        OnPropertyChanged(nameof(SelectedItem));
        updatingItems = false;
    }

    private void SelectRecord(int index)
    {
        if (capture is not { } current)
            return;

        selected = index;
        Inspector.Inspect(current, ReadRow(index));
        if (!updatingItems)
            OnPropertyChanged(nameof(SelectedItem));
    }

    private void ShowMetadata()
    {
        if (capture is { } current)
        {
            var row = selected >= 0 ? ReadRow(selected) : (IndexedRow?)null;
            Metadata = CaptureMetadataBuilder.Create(current, snapshot, row);
        }
    }

    public void Dispose()
    {
        if (disposed)
            return;

        disposed = true;
        filterCancellation?.Cancel();
        Inspector.Clear(resetFullBytes: true);
        lifetime.Cancel();
        lifetime.Dispose();
        if (!loading)
            capture?.Dispose();
    }
}

[TransportModel]
internal sealed record ExplorerHeader(bool HasRecords, string File, string Format, string Count, string Groups,
    string Diagnostics, string Footer, string? Error, string LandingTitle, string LandingHint, string LandingAction)
{
    public bool HasError => Error is not null;
}
