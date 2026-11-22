using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Input;
using Avalonia.Layout;
using Avalonia.Media;
using PacketLab.Protocols.IP.Reassembly;
using static PacketLab.Desktop.ViewStyle;
using static PacketLab.Desktop.RecordStatus;

namespace PacketLab.Desktop;

internal sealed partial class ExplorerWindow
{
    private readonly StackPanel inspectionContent = new() { Spacing = 9, Margin = new Thickness(0, 0, 0, 12) };
    private readonly ContentControl coverageSlot = new() { Margin = new Thickness(0, 0, 0, 4) };
    private readonly ContentControl evidenceSlot = new();
    private readonly ContentControl fullSlot = new();
    private Border? coverageCard;
    private readonly TextBlock locationLabel = Label("", 11, mono: true);
    private readonly SemaphoreSlim detailReads = new(1);
    private readonly List<(int Record, HexView View)> fullViews = [];
    private readonly List<(PacketField Field, Border Row)> fieldRows = [];
    private CoverageData? coverage;
    private CoverageMatrix? matrix;
    private PacketEvidence? evidence;
    private PacketField? field;
    private HexView? hexView;
    private StackPanel? fieldList;
    private WrapPanel? layerTabs;
    private TextBlock? selectionLabel;
    private TextBlock? rangeLabel;
    private TextBlock? rawLabel;
    private TextBlock? valueLabel;
    private int activeEvidence;
    private int? exact;
    private int fullPage;

    private void BeginInspection(CaptureIndex current, int index)
    {
        activeEvidence = index;
        evidence = null;
        exact = null;
        coverage = null;
        matrix = null;
        hexView = null;
        fullViews.Clear();
        fullPage = 0;
        inspectionContent.Children.Clear();
        inspectionContent.Children.Add(MakeRecordHeading());
        var status = ForRecord(anchor, anchorGroup, index);
        var why = Label(Describe(anchor, anchorGroup), 12, Muted);
        why.TextWrapping = TextWrapping.Wrap;
        var explanation = LayoutGrid("Auto,*", Badge(status.Label, status.Foreground, status.Background), why);
        explanation.ColumnSpacing = 9;
        explanation.VerticalAlignment = VerticalAlignment.Top;
        inspectionContent.Children.Add(explanation);
        if (coverageCard?.Child is StackPanel oldCoverage)
            oldCoverage.Children.Clear();
        coverageCard = null;
        coverageSlot.Content = null;
        inspectionContent.Children.Add(coverageSlot);
        coverageSlot.IsVisible = anchorGroup is not null;
        evidenceSlot.Content = Notice("正在读取协议字段…");
        inspectionContent.Children.Add(evidenceSlot);
        inspector.Content = inspectionContent;

        _ = LoadEvidenceAsync(current, index, null);
        if (anchorGroup is { } group)
            _ = LoadCoverageAsync(current, group);
    }

    private Control MakeRecordHeading()
    {
        var summary = anchor.Summary;
        var name = Label(RecordStatus.Title(anchor, anchorGroup, selected), 20, weight: Demi);
        name.FontFamily = Display;
        name.LineHeight = 28;
        var details = Label($"{anchor.Time.Format()} · {anchor.Context} · 捕获 {anchor.Length} B / 原始 {anchor.OriginalLength} B",
            11, Muted, mono: true);
        details.LineHeight = 16;
        ToolTip.SetTip(details, $"{anchor.Time.Format(date: true)} · {anchor.Block} · 文件偏移 0x{anchor.DataOffset:X}");
        var marker = Eyebrow($"RECORD {Number(selected)}");
        marker.LineHeight = 16;
        var main = Vertical(5, marker, name, details);
        var ends = Horizontal(10, Endpoint("源地址", summary.SourceAddress),
            Label("→", 14, Muted),
            Endpoint("目的地址", summary.DestinationAddress));
        ends.HorizontalAlignment = HorizontalAlignment.Right;
        var grid = new Grid();
        grid.Children.Add(main);
        grid.Children.Add(ends);
        grid.SizeChanged += (_, _) =>
        {
            var narrow = grid.Bounds.Width <= 744;
            grid.ColumnDefinitions = narrow ? new ColumnDefinitions("*") : new ColumnDefinitions("*,Auto");
            grid.RowDefinitions = narrow ? new RowDefinitions("Auto,Auto") : new RowDefinitions("Auto");
            Grid.SetColumn(ends, narrow ? 0 : 1);
            Grid.SetRow(ends, narrow ? 1 : 0);
            ends.HorizontalAlignment = narrow ? HorizontalAlignment.Left : HorizontalAlignment.Right;
            ends.Margin = narrow ? new Thickness(0, 8, 0, 0) : new Thickness(9, 0, 0, 0);
        };

        return new Border
        {
            Background = PanelBrush, BorderBrush = Accent, BorderThickness = new Thickness(0, 2, 0, 0),
            Child = LineBelow(grid, new Thickness(13, 12, 13, 14))
        };
    }

    private static Control Endpoint(string name, string value) =>
        Vertical(1, Label(name, 10, Muted), Label(value, 12, mono: true));

    private async Task LoadEvidenceAsync(CaptureIndex current, int record, int? rawByte)
    {
        var revision = ++evidenceRevision;
        var group = anchorGroup;
        await detailReads.WaitAsync();
        try
        {
            if (evidenceRevision != revision || current != capture)
                return;


            var loaded = await Task.Run(() => record < 0 && group is not null
                ? PacketFields.Reassembled(current, group)
                : PacketFields.Original(current, current.ReadRecord(record)));
            if (evidenceRevision != revision || current != capture)
                return;

            activeEvidence = record;
            evidence = loaded;
            exact = rawByte;
            field = rawByte is { } offset ? FieldAt(loaded, offset) : DefaultField(loaded, record);
            BuildEvidence(loaded);
            UpdateHighlight(reveal: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            if (evidenceRevision == revision && current == capture)
                evidenceSlot.Content = Notice($"无法读取记录字节 · {exception.Message}");
        }
        finally
        {
            detailReads.Release();
        }
    }

    private PacketField DefaultField(PacketEvidence view, int record)
    {
        var names = new List<string>();
        if (record < 0)
            names.Add("目的端口");
        else if (anchorGroup is not null)
            names.Add("标识符");
        else if (view.Summary.Protocol == Protocol.Arp)
            names.Add("目标 IP");
        else if (view.Summary.Issue.HasFlag(PacketIssue.Mismatch))
            names.Add("校验和");
        else if (view.Summary.Issue.HasFlag(PacketIssue.Invalid))
            names.Add("UDP 长度");
        names.Add("目的端口");

        return names.Select(name => view.Fields.FirstOrDefault(item => item.Name == name)).FirstOrDefault(item => item is not null)
            ?? view.Fields.First();
    }

    private static PacketField? FieldAt(PacketEvidence view, int offset) =>
        view.Fields.Where(candidate => candidate.Range?.Contains(offset) == true)
            .OrderBy(candidate => candidate.Range!.Value.Length).FirstOrDefault();

    private void BuildEvidence(PacketEvidence view)
    {
        var origin = activeEvidence < 0 ? "重组 IP 数据报" : $"原始记录 {Number(activeEvidence)}";
        var coordinates = activeEvidence < 0 ? "重组 IP 起点" : "帧起点";
        var fieldHeader = PanelHeading("M5 2V17Q5 21 9 21H14 M5 8H14 M14 5H20V11H14Z M14 17H20V23H14Z", "协议字段", origin);
        layerTabs = new WrapPanel { Margin = new Thickness(9, 5), ItemSpacing = 4 };
        foreach (var layer in view.Fields.Select(item => item.Layer).Distinct())
        {
            var button = Button(Label(layer, 11, Muted, mono: true), () => SelectField(view.Fields.First(item => item.Layer == layer)), layer);
            button.Classes.Add("layer");
            button.Padding = new Thickness(7, 3);
            button.MinHeight = 24;
            layerTabs.Children.Add(button);
        }
        fieldList = new StackPanel();
        var fieldScroll = new ScrollViewer { MaxHeight = 200, Content = fieldList };
        AutomationProperties.SetName(fieldScroll, "当前协议字段");

        var tabBorder = LineBelow(layerTabs, default);
        var fieldContent = Vertical(0, fieldHeader, tabBorder, fieldScroll);
        var fieldCard = Card(fieldContent);
        fieldCard.VerticalAlignment = VerticalAlignment.Top;
        var bytesHeader = PanelHeading("M8 3L2 10L8 17 M16 3L22 10L16 17 M14 1L10 19", $"{origin}字节", $"{view.Bytes.Length} B · {coordinates}");
        hexView = new HexView(view.Bytes, compact: false, PickHex)
        {
            Margin = new Thickness(12, 7, 12, 7),
            MinWidth = 354
        };
        var hexScroll = new ScrollViewer
        {
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Content = hexView
        };
        selectionLabel = Label("", 12, Accent, mono: true);
        rangeLabel = Label("", 11, Accent, mono: true, weight: Demi);
        rawLabel = Label("", 11, Muted, mono: true);
        valueLabel = Label("", 11, Text, mono: true, weight: Demi);
        valueLabel.TextWrapping = TextWrapping.Wrap;
        var selectionRow = LayoutGrid("*,Auto", selectionLabel, rangeLabel);
        selectionRow.ColumnSpacing = 8;
        selectionRow.Margin = new Thickness(12, 8, 12, 2);
        var valueRow = LayoutGrid("Auto,Auto,*", rawLabel, Label("→", 11, Muted), valueLabel);
        valueRow.ColumnSpacing = 8;
        valueRow.Margin = new Thickness(12, 2, 12, 9);
        var selectionInfo = new Border
        {
            BorderBrush = Line, BorderThickness = new Thickness(0, 1, 0, 0),
            Child = Vertical(0, selectionRow, valueRow)
        };
        var byteCard = Card(Vertical(0, bytesHeader, hexScroll, selectionInfo));
        var panels = new Grid { ColumnSpacing = 10, RowSpacing = 10 };
        panels.Children.Add(fieldCard);
        panels.Children.Add(byteCard);
        panels.SizeChanged += (_, _) => ResizePanels();
        evidenceSlot.Content = panels;
        ResizePanels();
        ShowFieldLayer(field?.Layer ?? view.Fields[0].Layer);

        void ResizePanels()
        {
            var width = panels.Bounds.Width > 0 ? panels.Bounds.Width : workspace.Bounds.Width - listColumn.ActualWidth - 20;
            var narrow = width <= 770;
            if (panels.ColumnDefinitions.Count == (narrow ? 1 : 2))
                return;

            panels.ColumnDefinitions = narrow ? new ColumnDefinitions("*") : new ColumnDefinitions(".82*,1.18*");
            panels.RowDefinitions = narrow ? new RowDefinitions("Auto,Auto") : new RowDefinitions("Auto");
            Grid.SetColumn(byteCard, narrow ? 0 : 1);
            Grid.SetRow(byteCard, narrow ? 1 : 0);
            fieldCard.VerticalAlignment = narrow ? VerticalAlignment.Top : VerticalAlignment.Stretch;
            fieldScroll.MaxHeight = narrow ? 150 : 200;
        }
    }

    private static Control PanelHeading(string glyph, string name, string hint)
    {
        var heading = Horizontal(8, Icon(glyph), Label(name, 14, weight: Demi));
        var bar = LayoutGrid("*,Auto", heading, Label(hint, 10, Muted, mono: true));
        bar.ColumnSpacing = 6;
        bar.MinHeight = 38;

        return LineBelow(bar, new Thickness(12, 0));
    }

    private void ShowFieldLayer(string layer)
    {
        if (fieldList is null || layerTabs is null || evidence is null)
            return;

        fieldRows.Clear();
        fieldList.Children.Clear();
        foreach (var button in layerTabs.Children.OfType<Button>())
            button.Classes.Set("selected", (button.Content as TextBlock)?.Text == layer);
        foreach (var item in evidence.Fields.Where(item => item.Layer == layer))
        {
            var name = Label(item.Name, 12);
            name.TextWrapping = TextWrapping.Wrap;
            var value = Label(item.Value, 12, mono: true);
            value.TextWrapping = TextWrapping.Wrap;
            var range = Label(item.Range?.Label ?? "—", 10, Soft, mono: true);
            range.TextAlignment = TextAlignment.Right;
            var cells = LayoutGrid("1*,1.7*,70", name, value, range);
            cells.ColumnSpacing = 7;
            var button = Button(cells, () => SelectField(item), $"{item.Name} · {item.Value} · {item.Range?.Label ?? "无确定偏移"}");
            button.HorizontalAlignment = HorizontalAlignment.Stretch;
            button.HorizontalContentAlignment = HorizontalAlignment.Stretch;
            button.Padding = new Thickness(12, 3, 10, 3);
            button.MinHeight = 25;
            button.CornerRadius = default;
            var row = LineBelow(button, default);
            fieldList.Children.Add(row);
            fieldRows.Add((item, row));
        }
    }

    private void SelectField(PacketField item)
    {
        var previousLayer = field?.Layer;
        field = item;
        exact = null;
        if (previousLayer != item.Layer)
            ShowFieldLayer(item.Layer);

        UpdateHighlight(reveal: true);
    }

    private void PickHex(int offset) => ChooseEvidence(activeEvidence, offset);

    private void ChooseEvidence(int record, int? offset)
    {
        if (capture is not { } current)
            return;
        if (record != activeEvidence || evidence is null)
        {
            _ = LoadEvidenceAsync(current, record, offset);

            return;
        }

        evidenceRevision++;
        var previousLayer = field?.Layer;
        var item = offset is { } index ? FieldAt(evidence, index) : DefaultField(evidence, record);
        exact = offset;
        field = item;
        if (item is not null && item.Layer != previousLayer)
            ShowFieldLayer(item.Layer);

        UpdateHighlight(reveal: true);
    }

    private void UpdateHighlight(bool reveal)
    {
        var range = field?.Range;
        hexView?.SetSelection(range, exact, reveal);
        HighlightFieldRows();
        UpdateRangeLabels();
        var payloadOffset = PayloadOffset(exact);
        matrix?.SetSelection(activeEvidence, payloadOffset);
        UpdateFullHighlights(payloadOffset, reveal);
        UpdateLocation(payloadOffset);
    }

    private void HighlightFieldRows()
    {
        foreach (var (item, row) in fieldRows)
        {
            var focused = item == field;
            row.Background = focused ? Selected : null;
            row.BorderThickness = focused ? new Thickness(3, 0, 0, 1) : new Thickness(0, 0, 0, 1);
            row.BorderBrush = focused ? Accent : Line;
            if (row.Child is Button { Content: Grid cells } button)
            {
                button.Padding = new Thickness(focused ? 9 : 12, 3, 10, 3);
                ((TextBlock)cells.Children[0]).Foreground = focused ? Accent : Text;
                ((TextBlock)cells.Children[1]).Foreground = focused ? Accent : Text;
            }
        }
    }

    private void UpdateRangeLabels()
    {
        if (selectionLabel is null || valueLabel is null || rangeLabel is null || rawLabel is null || evidence is not { } view)
            return;

        selectionLabel.Text = field is not null ? $"{field.Layer} / {field.Name}" : "原始字节";
        (rangeLabel.Text, rawLabel.Text) = (field?.Range, exact) switch
        {
            ({ } span, _) => ($"0x{span.Label} · {span.Length} B", PacketFields.Raw(view.Bytes.AsSpan(span.Start, span.Length))),
            (null, { } index) => ($"0x{index:X4} · 1 B", view.Bytes[index].ToString("X2")),
            _ => ("位置未确认", "—")
        };
        valueLabel.Text = field?.Value ?? "字段无法确认";
    }

    private void UpdateFullHighlights(int? payloadOffset, bool reveal)
    {
        foreach (var (record, fullView) in fullViews)
        {
            var lane = coverage?.Lanes.FirstOrDefault(item => item.Record == record);
            var mapped = payloadOffset is { } p && lane?.Covers(p) == true ? lane.RawIndex(p) : (int?)null;
            var isActive = record == activeEvidence;
            var raw = mapped ?? (isActive ? exact : null);
            fullView.SetSelection(null, raw, reveal);
        }
    }

    private int? PayloadOffset(int? raw)
    {
        if (raw is not { } index || coverage?.Lanes.FirstOrDefault(item => item.Record == activeEvidence) is not { } lane)
            return null;

        var offset = lane.Slice.Offset + index - lane.Slice.Start;

        return lane.Covers(offset) ? offset : null;
    }

    private void UpdateLocation(int? payload)
    {
        locationLabel.IsVisible = exact.HasValue && coverage is not null;
        if (!locationLabel.IsVisible || exact is not { } index || evidence is not { } view)
            return;

        var raw = view.Bytes[index].ToString("X2");
        if (payload is { } p && coverage is { } data)
        {
            var sources = data.Lanes.Where(lane => lane.Covers(p)).Select(lane =>
                $"{(lane.Derived ? lane.Label : lane.Label + " 帧")} 0x{lane.RawIndex(p):X4}");
            locationLabel.Text = $"载荷 +{p} B  ｜  {string.Join(" ↔ ", sources.Take(8))}  ｜  {raw}";
        }
        else
        {
            var source = activeEvidence < 0 ? "重组 IP" : $"{Number(activeEvidence)} 帧";
            locationLabel.Text = $"{source} 0x{index:X4}  ｜  {raw}";
        }
    }

    private async Task LoadCoverageAsync(CaptureIndex current, FragmentGroup group)
    {
        var revision = selectionRevision;
        try
        {
            var index = selected;
            var data = await Task.Run(() => CoverageData.Load(current, group, index));
            if (revision != selectionRevision || current != capture)
                return;

            coverage = data;
            coverageSlot.Content = MakeCoverage(current, group, data);
            UpdateHighlight(reveal: false);
            if (fullBytes)
                _ = LoadFullBytesAsync(current, group, data, fullPage);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            if (revision == selectionRevision && current == capture)
                coverageSlot.Content = Notice($"无法读取分片字节 · {exception.Message}");
        }
    }

    private Control MakeCoverage(CaptureIndex current, FragmentGroup group, CoverageData data)
    {
        var status = ForGroup(group);
        var name = Horizontal(9, Label("分片覆盖图", 16, weight: Demi),
            Label(group.Identity, 12, Muted, mono: true),
            Badge(status.Label, status.Foreground, status.Background));
        var toggleText = fullBytes ? "收起完整字节 ▴" : "并排查看完整字节 ▾";
        var toggle = new Button { Content = Label(toggleText), Classes = { "explorer", "outline" } };
        AutomationProperties.SetName(toggle, toggleText);
        toggle.Click += (_, _) => ToggleFull();
        toggle.Classes.Add("outline");
        var top = LayoutGrid("*,Auto", name, toggle);
        var scroll = new ScrollViewer
        {
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Margin = new Thickness(12, 4, 4, 4), MaxHeight = 288
        };
        var map = new CoverageMatrix(data, ChooseEvidence);
        matrix = map;
        scroll.Content = map;
        scroll.ScrollChanged += (_, _) => map.SetViewport(scroll.Offset, scroll.Viewport);
        scroll.SizeChanged += (_, _) => map.SetViewport(scroll.Offset, scroll.Viewport);
        var (caption, detail, brush) = CoverageSummary(group, data);
        var detailLabel = Label(detail, 12, Muted);
        detailLabel.TextWrapping = TextWrapping.Wrap;
        var summary = LayoutGrid("Auto,*", Label(caption, 12, brush, weight: Demi), detailLabel);
        summary.ColumnSpacing = 12;
        var summaryBorder = new Border { BorderBrush = Line, BorderThickness = new Thickness(0, 1, 0, 0), Child = summary, Padding = new Thickness(12, 6) };
        locationLabel.Margin = new Thickness(12, 5);
        locationLabel.TextWrapping = TextWrapping.Wrap;
        locationLabel.IsVisible = false;
        fullSlot.IsVisible = fullBytes;
        fullSlot.Content = null;

        var header = LineBelow(top, new Thickness(12, 8));
        var content = Vertical(0, header, scroll, summaryBorder, locationLabel, fullSlot);
        coverageCard = Card(content);

        return coverageCard;

        void ToggleFull()
        {
            fullBytes = !fullBytes;
            var label = fullBytes ? "收起完整字节 ▴" : "并排查看完整字节 ▾";
            toggle.Content = Label(label, 12, fullBytes ? Accent : Text);
            toggle.Classes.Set("selected", fullBytes);
            AutomationProperties.SetName(toggle, label);
            fullSlot.IsVisible = fullBytes;
            if (fullBytes && fullSlot.Content is null)
                _ = LoadFullBytesAsync(current, group, data, fullPage);
        }
    }

    private static (string Title, string Message, IBrush Brush) CoverageSummary(FragmentGroup group, CoverageData data)
    {
        if (group.HasResult && group.DerivedSlice is { } slice)
            return ($"完整覆盖 {slice.Length} B", $"重组 IP 数据报 {group.DerivedLength} B · {group.DerivedSummary.Transport}", Good);
        if (group.Status == IpReassemblyStatus.Conflict && data.Overlap.Count > 0)
        {
            var same = data.Identical ? "重叠位置的字节相同。" : "重叠范围存在不同字节。";
            var reason = group.Version == 6 ? "IPv6 重叠分片触发整组丢弃。" : GroupDiagnostic(group);
            var ranges = data.Overlap.Take(4).Select(range => range.Length == 1 ? $"{range.Start}" : $"{range.Start}–{range.End}");
            var label = string.Join("、", ranges);
            if (data.Overlap.Count > 4)
                label += $" 等 {data.Overlap.Count} 段";

            return ("重组已丢弃", $"载荷 {label} B 重叠（斜纹）。{same}{reason}", Bad);
        }

        return ("未生成重组数据报", GroupDiagnostic(group), Warn);
    }

    private async Task LoadFullBytesAsync(CaptureIndex current, FragmentGroup group, CoverageData data, int page)
    {
        const int pageSize = 3;
        var revision = selectionRevision;
        fullPage = page;
        fullSlot.Content = Notice("正在读取完整字节…");
        try
        {
            var lanes = data.Lanes.Skip(page * pageSize).Take(pageSize).ToArray();
            var dumps = await Task.Run(() => ReadLaneBytes(current, group, lanes));
            if (revision != selectionRevision || page != fullPage)
                return;

            fullViews.Clear();
            var cards = new Grid { ColumnSpacing = 9 };
            for (var n = 0; n < lanes.Length; n++)
            {
                var lane = lanes[n];
                var hex = new HexView(dumps[n], compact: true, offset => ChooseEvidence(lane.Record, offset),
                    offset => CoverageMatrix.TintAt(data, lane, offset)) { MinWidth = 230 };
                fullViews.Add((lane.Record, hex));
                var swatch = new Border { Width = 7, Height = 7, Background = CoverageMatrix.Swatch(page * pageSize + n) };
                var heading = Horizontal(8, swatch, Label(lane.Label, 13, mono: true, weight: Demi));
                var title = LayoutGrid("*,Auto", heading, Label($"{dumps[n].Length} B", 10, Muted));
                var button = Button(title, () => ChooseEvidence(lane.Record, null), lane.Label);
                button.HorizontalAlignment = HorizontalAlignment.Stretch;
                button.HorizontalContentAlignment = HorizontalAlignment.Stretch;
                var origin = Label($"{(lane.Derived ? "IP" : "帧")}起点 0x0000 · 分片载荷始于 0x{lane.Slice.Start:X4}", 10, Muted);
                var card = new Border
                {
                    Background = Bg, BorderBrush = Line, BorderThickness = new Thickness(1),
                    CornerRadius = new CornerRadius(4), Padding = new Thickness(8), MinWidth = 248,
                    Child = Vertical(3, button, origin, hex)
                };
                cards.ColumnDefinitions.Add(new ColumnDefinition(1, GridUnitType.Star));
                Grid.SetColumn(card, n);
                cards.Children.Add(card);
            }
            var pages = (data.Lanes.Count + pageSize - 1) / pageSize;
            var pageControls = Horizontal(4,
                Button("上一组", () => _ = LoadFullBytesAsync(current, group, data, Math.Max(0, page - 1))),
                Label($"{page + 1} / {pages}", 11, Muted),
                Button("下一组", () => _ = LoadFullBytesAsync(current, group, data, Math.Min(pages - 1, page + 1))));
            pageControls.IsVisible = pages > 1;
            var scroll = new ScrollViewer { Content = cards, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto };
            var content = Vertical(6, pageControls, scroll);
            content.Margin = new Thickness(12, 8, 12, 12);
            fullSlot.Content = content;
            UpdateHighlight(reveal: true);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or ObjectDisposedException)
        {
            if (revision == selectionRevision && page == fullPage)
                fullSlot.Content = Notice($"无法读取完整字节 · {exception.Message}");
        }
    }
    private static byte[][] ReadLaneBytes(CaptureIndex index, FragmentGroup group, IEnumerable<CoverageLane> lanes)
    {
        return lanes.Select(lane => lane.Derived ? index.ReadDerived(group) : index.ReadBytes(index.ReadRecord(lane.Record))).ToArray();
    }

}
