using System.Diagnostics.CodeAnalysis;
using System.Globalization;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using static PacketLab.Desktop.ViewStyle;
using static PacketLab.Desktop.RecordStatus;

namespace PacketLab.Desktop;

[SuppressMessage("Design", "PL0001", Justification = "Avalonia view references are populated by the window and inspector lifecycles. Capture results have their own models.")]
internal sealed partial class ExplorerWindow : Window
{
    private const string FileGlyph = "M6 3H14L18 7V21H6Z M14 3V8H18 M9 12H15 M9 16H15";
    private readonly string? preferencesPath;
    private readonly Func<FilePickerOpenOptions, Task<string?>> chooseFile;
    private readonly ColumnDefinition listColumn = new(348, GridUnitType.Pixel) { MinWidth = 246 };
    private readonly TextBlock fileLabel = Label("打开抓包文件", 13, mono: true, weight: Demi);
    private readonly TextBlock formatLabel = Label("—", 12, Muted, mono: true);
    private readonly TextBlock countLabel = Counter();
    private readonly TextBlock groupLabel = Counter();
    private readonly TextBlock diagnosticLabel = Counter(Warn);
    private readonly TextBlock listCount = Label("0 / 0", 10, Muted, mono: true);
    private readonly TextBlock footerLabel = Label("本地捕获文件", 11, Soft);
    private readonly TextBlock footerCount = Label("显示 0 / 0 条", 11, Soft);
    private readonly TextBlock errorLabel = Label("", 12, Bad);
    private readonly TextBox search = new() { PlaceholderText = "搜索序号、地址或协议", Classes = { "explorer" } };
    private readonly ListBox recordList = new() { Classes = { "records" } };
    private readonly ScrollViewer inspector = new() { HorizontalScrollBarVisibility = Avalonia.Controls.Primitives.ScrollBarVisibility.Disabled };
    private readonly ContentControl emptyList = new() { VerticalAlignment = VerticalAlignment.Top };
    private readonly Button[] filters;
    private readonly Grid overlay = new() { IsVisible = false, Background = Brush("#8F080D13") };
    private readonly Button metadataButton;
    private readonly Border errorBar;
    private readonly Grid workspace;
    private readonly Grid body;
    private readonly Border heading;
    private readonly Button fileButton;
    private CaptureSnapshot snapshot = new(0, 0, 0, "—", null, [], [], default, default, 0, null);
    private CaptureIndex? capture;
    private CaptureRecord anchor;
    private FragmentGroup? anchorGroup;
    private CancellationTokenSource? loadCancellation;
    private CancellationTokenSource? filterCancellation;
    private RecordFilter filter;
    private int selected = -1;
    private int selectionRevision;
    private int evidenceRevision;
    private bool updatingRecords;
    private bool loading;
    private bool pickingFile;
    private string? openError;
    private bool fullBytes;
    private double? savedListWidth;

    internal ExplorerWindow(string? file, string? preferencesPath = null,
        Func<FilePickerOpenOptions, Task<string?>>? chooseFile = null)
    {
        this.preferencesPath = preferencesPath;
        this.chooseFile = chooseFile ?? PickFromStorageAsync;
        savedListWidth = ReadWidth(preferencesPath);
        Title = "PacketLab · Packet Explorer";
        Width = 1440;
        Height = 950;
        MinWidth = 700;
        MinHeight = 530;
        Background = Bg;
        Foreground = Text;
        FontFamily = Body;
        WindowStartupLocation = WindowStartupLocation.CenterScreen;

        filters = [FilterButton("全部", RecordFilter.All), FilterButton("诊断", RecordFilter.Diagnostics), FilterButton("分片", RecordFilter.Fragments)];
        filters[0].Classes.Add("selected");
        var fileMark = Icon(FileGlyph);
        var chevron = Icon("M2 3L6 7L10 3", 10, Muted);
        var fileContent = Horizontal(8, fileMark, fileLabel, chevron);
        fileButton = Button(fileContent, () => _ = PickLocalFileAsync(), "选择其他抓包文件");
        var metadataIcon = Icon("M2 4H20V18H2Z M8 4V18 M11 8H17 M11 12H16", 16, Muted);
        var metadataContent = Horizontal(7, metadataIcon, Label("捕获元数据", 12, Muted));
        metadataButton = Button(metadataContent, ShowMetadata, "捕获元数据");
        metadataButton.IsEnabled = false;
        errorLabel.TextWrapping = TextWrapping.Wrap;
        errorBar = new Border
        {
            Background = BadBackground, BorderBrush = Bad, BorderThickness = new Thickness(1),
            Child = Horizontal(12, Label("× 文件读取错误", 12, Bad, weight: Demi), errorLabel),
            Padding = new Thickness(10, 7), IsVisible = false, Margin = new Thickness(0, 0, 0, 8)
        };

        workspace = new Grid { ColumnDefinitions = new ColumnDefinitions { listColumn, new(16, GridUnitType.Pixel), new(1, GridUnitType.Star) } };
        var grip = MakeGrip();
        var recordsPanel = MakeRecords();
        Grid.SetColumn(grip, 1);
        Grid.SetColumn(inspector, 2);
        inspector.Margin = new Thickness(0, 0, 4, 0);
        workspace.Children.Add(recordsPanel);
        workspace.Children.Add(grip);
        workspace.Children.Add(inspector);

        heading = MakeHeading();
        body = new Grid { RowDefinitions = new RowDefinitions("Auto,Auto,*,22"), MaxWidth = 1730 };
        AddRow(body, heading, 0);
        AddRow(body, errorBar, 1);
        AddRow(body, workspace, 2);
        AddRow(body, MakeFooter(), 3);
        var shell = new Grid { RowDefinitions = new RowDefinitions("56,*") };
        AddRow(shell, MakeBrand(), 0);
        AddRow(shell, body, 1);
        landing = MakeLanding();
        AddRow(shell, landing, 1);
        UpdateHeader();
        var root = new Grid();
        root.Children.Add(shell);
        root.Children.Add(overlay);
        Content = root;

        search.TextChanged += (_, _) =>
        {
            if (!updatingRecords)
                _ = RefreshFilterAsync(debounce: true);
        };
        recordList.SelectionChanged += (_, _) =>
        {
            if (!updatingRecords && recordList.SelectedItem is int index)
                SelectRecord(index);
        };
        SizeChanged += (_, _) => ApplyWidth(Bounds.Width);
        KeyDown += HandleShortcuts;
        overlay.PointerPressed += (_, e) =>
        {
            if (e.Source == overlay)
                CloseOverlay();
        };
        Opened += (_, _) =>
        {
            ApplyWidth(Bounds.Width);
            if (file is not null)
                _ = OpenAsync(file);
        };
        Closed += (_, _) =>
        {
            filterCancellation?.Cancel();
            selectionRevision++;
            evidenceRevision++;
            if (loadCancellation is { } request)
                request.Cancel();
            else
                capture?.Dispose();
        };
    }

    private static TextBlock Counter(IBrush? brush = null)
    {
        var count = Label("00", 27, brush, weight: Demi);
        count.FontFamily = Display;
        count.LineHeight = 30;

        return count;
    }

    private Control MakeBrand()
    {
        var logo = new Avalonia.Controls.Shapes.Path
        {
            Fill = Accent, Data = Geometry.Parse("M2 9L15 2L28 9L15 16Z M2 13L15 20L28 13V17L15 24L2 17Z M2 21L15 28L28 21V25L15 32L2 25Z"),
            Width = 30, Height = 30, Stretch = Stretch.Uniform
        };
        var mark = Label("PacketLab", 21, weight: FontWeight.Bold);
        mark.FontFamily = Display;
        var lockup = Horizontal(11, logo, mark, Separator(18),
            Label("Packet Explorer", 13, Muted));
        var border = LineBelow(lockup, default);
        border.Background = Top;
        border.SizeChanged += (_, _) => border.Padding = new Thickness(PageMargin(border.Bounds.Width), 0);

        return border;
    }

    private Border MakeHeading()
    {
        var eyebrow = Horizontal(9, new Border { Width = 20, Height = 2, Background = Accent }, Eyebrow("PACKET EXPLORER"));
        var title = Label("记录工作台", 31, weight: FontWeight.Bold);
        title.FontFamily = Display;
        var headingText = Vertical(2, eyebrow, title);
        var stats = Horizontal(0, Metric(countLabel, "记录"),
            Metric(groupLabel, "分片组"),
                Metric(diagnosticLabel, "诊断记录"));
        stats.HorizontalAlignment = HorizontalAlignment.Right;
        var summary = LayoutGrid("*,Auto", headingText, stats);

        var fileRow = LayoutGrid("Auto,Auto,*,Auto", fileButton, Separator(15), formatLabel, metadataButton);
        fileRow.ColumnSpacing = 10;
        var fileBar = new Border
        {
            Background = PanelBrush, BorderBrush = Line, BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(6), Padding = new Thickness(9, 5), Child = fileRow,
            MinHeight = 41, VerticalAlignment = VerticalAlignment.Center
        };
        var area = LayoutGrid("1.15*,0.85*", summary, fileBar);
        area.ColumnSpacing = 26;

        return new Border { Child = area, Padding = new Thickness(0, 16, 0, 12) };
    }

    private static Control Metric(TextBlock value, string name) => new Border
    {
        BorderBrush = Line, BorderThickness = new Thickness(1, 0, 0, 0),
        Padding = new Thickness(15, 0), Child = Vertical(0, value, Label(name, 11, Muted))
    };

    private static Border Separator(double height) => new()
    {
        Background = Line, Width = 1, Height = height, VerticalAlignment = VerticalAlignment.Center
    };

    private static TextBlock Eyebrow(string value)
    {
        var label = Label(value, 10, Accent, mono: true, weight: Demi);
        label.LetterSpacing = 1.8;

        return label;
    }

    private Control MakeRecords()
    {
        var chips = new Border
        {
            Child = Horizontal(2, filters), BorderBrush = Line, BorderThickness = new Thickness(1),
            Padding = new Thickness(2), CornerRadius = new CornerRadius(4), Background = Bg
        };
        var listHeading = Horizontal(6, Label("捕获记录", 15, weight: Demi), listCount);
        var top = LayoutGrid("*,Auto", listHeading, chips);
        AutomationProperties.SetName(search, "搜索记录");
        var searchIcon = Icon("M12 12L17 17 M14 8A6 6 0 1 1 2 8A6 6 0 0 1 14 8", 13, Muted);
        searchIcon.Margin = new Thickness(9, 0, 3, 0);
        search.InnerLeftContent = searchIcon;
        var toolbar = LineBelow(Vertical(9, top, search), new Thickness(10, 9, 10, 13));
        recordList.ItemTemplate = new FuncDataTemplate<int>((index, _) =>
            capture is { } current ? new RecordRow(current, index, selected, anchorGroup) : null, supportsRecycling: false);
        AutomationProperties.SetName(recordList, "捕获记录列表");
        recordList.ItemsPanel = new FuncTemplate<Panel?>(() => new VirtualizingStackPanel());

        var list = new Grid();
        list.Children.Add(recordList);
        list.Children.Add(emptyList);
        var content = new Grid { RowDefinitions = new RowDefinitions("Auto,*") };
        AddRow(content, toolbar, 0);
        AddRow(content, list, 1);

        return Card(content);
    }

    private Control MakeFooter() => new Border
    {
        BorderThickness = new Thickness(0, 1, 0, 0), BorderBrush = Line,
        Child = LayoutGrid("*,Auto", footerLabel, footerCount), Margin = new Thickness(0, 8, 0, 0)
    };

    private Button FilterButton(string name, RecordFilter value)
    {
        var button = Button(Label(name, 11, Muted), () =>
        {
            filter = value;
            _ = RefreshFilterAsync();
        }, name);
        button.Padding = new Thickness(6, 2);
        button.MinHeight = 22;

        return button;
    }

    private static void AddRow(Grid grid, Control control, int row)
    {
        Grid.SetRow(control, row);
        grid.Children.Add(control);
    }

    private static double PageMargin(double width) => Math.Clamp(width * .034, 19, 52);

    private void ApplyWidth(double width)
    {
        var margin = PageMargin(width);
        body.Margin = new Thickness(margin, 0, margin, 0);
        var contentWidth = width - 2 * margin;
        var availableListWidth = contentWidth - 16 - 350;
        var max = Math.Max(246, availableListWidth);
        var initial = Math.Clamp(contentWidth * .26, 275, 360);
        listColumn.MaxWidth = max;
        listColumn.Width = new GridLength(Math.Clamp(savedListWidth ?? initial, 246, max));
        fileLabel.MaxWidth = Math.Max(95, contentWidth * .36 - 153);
        heading.Padding = new Thickness(0, 16, 0, 12);
        landing.Padding = new Thickness(20, 28, 20, Math.Clamp(Bounds.Height * .11, 28, 100));
    }

    private Control MakeGrip()
    {
        var grip = new Grid { Background = Brushes.Transparent, Focusable = true, Cursor = new Cursor(StandardCursorType.SizeWestEast) };
        var rule = new Border { Width = 1, Background = Line, HorizontalAlignment = HorizontalAlignment.Center };
        var handle = new Border
        {
            Width = 3, Height = 32, Background = Muted, CornerRadius = new CornerRadius(3),
            VerticalAlignment = VerticalAlignment.Center, HorizontalAlignment = HorizontalAlignment.Center
        };
        grip.Children.Add(rule);
        grip.Children.Add(handle);
        const string hint = "拖动调整宽度 · 方向键微调 · 双击或按 Enter 复位";
        AutomationProperties.SetName(grip, "调整捕获记录列表宽度");
        ToolTip.SetTip(grip, hint);
        double? start = null;
        double? before = null;
        var startWidth = 0d;
        grip.PointerEntered += (_, _) => handle.Background = Accent;
        grip.PointerExited += (_, _) => handle.Background = grip.IsFocused ? Accent : Muted;
        grip.GotFocus += (_, _) => handle.Background = Accent;
        grip.LostFocus += (_, _) => handle.Background = Muted;
        grip.PointerPressed += (_, e) =>
        {
            if (!e.GetCurrentPoint(grip).Properties.IsLeftButtonPressed)
                return;

            grip.Focus();
            if (e.ClickCount == 2)
            {
                SetWidth(null);
                SaveWidth();

                return;
            }

            start = e.GetPosition(workspace).X;
            before = savedListWidth;
            startWidth = listColumn.ActualWidth;
            e.Pointer.Capture(grip);
            e.Handled = true;
        };
        grip.PointerMoved += (_, e) =>
        {
            if (start is { } x)
                SetWidth(startWidth + e.GetPosition(workspace).X - x);
        };
        grip.PointerReleased += (_, e) =>
        {
            if (start.HasValue)
                SaveWidth();

            start = null;
            e.Pointer.Capture(null);
        };
        grip.PointerCaptureLost += (_, _) =>
        {
            if (start.HasValue)
                SetWidth(before);
            start = null;
        };
        grip.KeyDown += (_, e) =>
        {
            var step = e.KeyModifiers.HasFlag(KeyModifiers.Shift) ? 48 : 12;
            switch (e.Key)
            {
                case Key.Left: SetWidth(listColumn.ActualWidth - step); break;

                case Key.Right: SetWidth(listColumn.ActualWidth + step); break;

                case Key.Home: SetWidth(listColumn.MinWidth); break;

                case Key.End: SetWidth(listColumn.MaxWidth); break;

                case Key.Enter: SetWidth(null); break;

                default: return;
            }
            SaveWidth();
            e.Handled = true;
        };

        return grip;
    }

    private void SetWidth(double? width)
    {
        savedListWidth = width is { } requested ? Math.Clamp(requested, listColumn.MinWidth, listColumn.MaxWidth) : null;
        ApplyWidth(Bounds.Width);
    }

    private static double? ReadWidth(string? path)
    {
        if (path is null || !File.Exists(path))
            return null;

        try
        {
            var stored = File.ReadAllText(path);

            return double.TryParse(stored, CultureInfo.InvariantCulture, out var width) && double.IsFinite(width) && width > 0
                ? width : null;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return null;
        }
    }

    private void SaveWidth()
    {
        if (preferencesPath is null)
            return;

        try
        {
            var parent = Path.GetDirectoryName(preferencesPath)!;
            Directory.CreateDirectory(parent);
            var width = savedListWidth?.ToString(CultureInfo.InvariantCulture) ?? "";
            File.WriteAllText(preferencesPath, width);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private void HandleShortcuts(object? sender, KeyEventArgs e)
    {
        if (e.Key == Key.Escape && overlay.IsVisible)
        {
            CloseOverlay();
            e.Handled = true;
        }
        if (e.Key == Key.O && e.KeyModifiers.HasFlag(KeyModifiers.Control))
        {
            _ = PickLocalFileAsync();
            e.Handled = true;
        }
    }

    private async Task OpenAsync(string path)
    {
        if (loading)
            return;

        CloseOverlay();
        using var cancellation = new CancellationTokenSource();
        var token = cancellation.Token;
        loadCancellation = cancellation;
        loading = true;
        openError = null;
        UpdateHeader();
        CaptureIndex? candidate = null;
        try
        {
            var current = new CaptureIndex(path);
            candidate = current;
            var complete = await Task.Run(() => current.Scan(partial => Dispatcher.UIThread.Post(() =>
            {
                if (loadCancellation == cancellation && !token.IsCancellationRequested && partial.Count > 0)
                    PublishCapture(current, partial);
            }, DispatcherPriority.Background), token), token);

            token.ThrowIfCancellationRequested();
            loading = false;
            if (complete.Format == "—")
                ShowOpenError(path, complete.Error ?? "无法识别抓包格式。");
            else
                PublishCapture(current, complete);
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ArgumentException or NotSupportedException)
        {
            if (!token.IsCancellationRequested)
            {
                loading = false;
                ShowOpenError(path, exception.Message);
            }
        }
        finally
        {
            loadCancellation = null;
            if (candidate != capture)
                candidate?.Dispose();
            if (token.IsCancellationRequested)
                capture?.Dispose();
        }
    }

    private void PublishCapture(CaptureIndex current, CaptureSnapshot next)
    {
        if (current != capture)
        {
            CloseOverlay();
            filterCancellation?.Cancel();
            var previous = capture;
            updatingRecords = true;
            search.Text = "";
            updatingRecords = false;
            filter = RecordFilter.All;
            selected = -1;
            anchorGroup = null;
            evidence = null;
            fullBytes = false;
            selectionRevision++;
            evidenceRevision++;
            inspector.Offset = default;
            capture = current;
            fileLabel.Text = Path.GetFileName(current.Path);
            previous?.Dispose();
        }

        ApplySnapshot(next);
    }

    private void ShowOpenError(string path, string message)
    {
        openError = $"{Path.GetFileName(path)}：{message}";
        UpdateHeader();
    }

    private void ApplySnapshot(CaptureSnapshot value)
    {
        snapshot = value;
        UpdateHeader();
        if (!loading || filter == RecordFilter.All && string.IsNullOrWhiteSpace(search.Text))
            _ = RefreshFilterAsync(refreshSelection: !loading);
    }

    private void UpdateHeader()
    {
        countLabel.Text = snapshot.Count.ToString("00");
        groupLabel.Text = snapshot.Groups.ToString("00");
        diagnosticLabel.Text = snapshot.Diagnostics.ToString("00");
        formatLabel.Text = snapshot.Format;
        var error = openError ?? snapshot.Error;
        errorLabel.Text = error;
        errorBar.IsVisible = error is not null;
        footerLabel.Text = loading ? "正在索引捕获记录…" : capture?.Path ?? "";
        body.IsVisible = snapshot.Count > 0;
        metadataButton.IsEnabled = body.IsVisible;
        fileButton.IsEnabled = !loading;
        landing.IsVisible = !body.IsVisible;
        UpdateLanding(error);
    }

    private async Task RefreshFilterAsync(bool debounce = false, bool refreshSelection = false)
    {
        foreach (var (button, index) in filters.Select((item, index) => (item, index)))
            button.Classes.Set("selected", index == (int)filter);
        filterCancellation?.Cancel();
        var cancellation = new CancellationTokenSource();
        filterCancellation = cancellation;
        var token = cancellation.Token;
        var current = capture;
        var count = snapshot.Count;
        var query = (search.Text ?? "").Trim();
        var mode = filter;
        try
        {
            if (mode == RecordFilter.All && query.Length == 0 || current is null)
                ReplaceItems(new RecordItems(count), refreshSelection);
            else
            {
                if (debounce)
                    await Task.Delay(125, token);
                var matches = await Task.Run(() => RecordItems.Search(current, count, mode, query, token), token);
                if (filterCancellation == cancellation)
                    ReplaceItems(new RecordItems(count, matches), refreshSelection);
            }
        }
        catch (OperationCanceledException) when (token.IsCancellationRequested)
        {
        }
        finally
        {
            if (filterCancellation == cancellation)
                filterCancellation = null;
            cancellation.Dispose();
        }
    }

    private void ReplaceItems(RecordItems items, bool refreshSelection = false)
    {
        var previous = selected;
        updatingRecords = true;
        recordList.ItemsSource = items;
        var next = items.IndexOf(previous);
        if (next < 0 && items.Count > 0)
            next = 0;
        recordList.SelectedIndex = next;
        if (next >= 0)
            recordList.ScrollIntoView(next);
        updatingRecords = false;
        listCount.Text = $"{items.Count:N0} / {snapshot.Count:N0}";
        footerCount.Text = $"显示 {listCount.Text} 条";
        emptyList.Content = null;
        if (next < 0)
        {
            selectionRevision++;
            evidenceRevision++;
            ShowEmpty();
        }
        else
        {
            var index = items.RecordAt(next);
            if (index != previous || refreshSelection || inspector.Content != inspectionContent)
                SelectRecord(index);
        }
    }

    private void ShowEmpty()
    {
        if (!body.IsVisible)
        {
            inspector.Content = null;

            return;
        }

        var clear = Button(Label("清除筛选", 12, Accent), () =>
        {
            filter = RecordFilter.All;
            search.Text = "";
            _ = RefreshFilterAsync();
        });
        emptyList.Content = Horizontal(2, Notice("没有匹配的记录。"), clear);
        inspector.Content = Notice("当前筛选下没有可查看的记录。");
    }

    private static TextBlock Notice(string text)
    {
        var label = Label(text, 12, Muted);
        label.TextWrapping = TextWrapping.Wrap;
        label.Margin = new Thickness(12);

        return label;
    }

    private void SelectRecord(int index)
    {
        if (capture is not { } current)
            return;

        var changed = selected != index;
        selected = index;
        anchor = current.ReadRecord(index);
        anchorGroup = current.Group(index);
        selectionRevision++;
        if (changed)
            inspector.Offset = default;
        foreach (var row in recordList.GetVisualDescendants().OfType<RecordRow>())
            row.Refresh(selected, anchorGroup);

        BeginInspection(current, index);
    }

    private async Task PickLocalFileAsync()
    {
        if (loading || pickingFile)
            return;

        pickingFile = true;
        try
        {
            var options = new FilePickerOpenOptions
            {
                Title = "打开抓包文件", AllowMultiple = false,
                FileTypeFilter = [new FilePickerFileType("捕获文件") { Patterns = ["*.pcap", "*.pcapng", "*.cap"] }, FilePickerFileTypes.All]
            };
            if (await chooseFile(options) is { } path && IsVisible)
                await OpenAsync(path);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            if (IsVisible)
            {
                openError = exception.Message;
                UpdateHeader();
            }
        }
        finally
        {
            pickingFile = false;
        }
    }

    private async Task<string?> PickFromStorageAsync(FilePickerOpenOptions options)
    {
        var result = await StorageProvider.OpenFilePickerAsync(options);

        return result.FirstOrDefault()?.TryGetLocalPath();
    }
}
