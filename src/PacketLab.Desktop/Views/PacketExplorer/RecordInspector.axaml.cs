using PacketLab.Desktop.Localization;
using System.ComponentModel;
using System.Diagnostics.CodeAnalysis;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Controls.Templates;
using Avalonia.Layout;
using Avalonia.Media;
using PacketLab.Desktop.Controls.PacketExplorer;
using PacketLab.Desktop.ViewModels.PacketExplorer;
using PacketLab.Desktop.Models.PacketExplorer;
using PacketLab.Desktop.Services.PacketExplorer;
using static PacketLab.Desktop.Controls.PacketExplorer.ViewStyle;
using static PacketLab.Desktop.Services.PacketExplorer.RecordStatus;

namespace PacketLab.Desktop.Views.PacketExplorer;

[SuppressMessage("Design", "PL0001", Justification = "Layout elements exist only for the currently displayed inspector panels.")]
internal sealed partial class RecordInspector : UserControl
{
    private readonly List<(CoverageLane Lane, HexView View)> fullViews = [];
    private readonly List<(PacketField Field, Border Row)> fieldRows = [];
    private RecordInspectorViewModel? model;
    private int lastRecord = -1;
    private TextBlock? locationLabel;
    private ContentControl? fullSlot;
    private Button? toggle;
    private CoverageMatrix? matrix;
    private HexView? hexView;
    private StackPanel? fieldList;
    private WrapPanel? layerTabs;
    private ContentControl? selectionDetails;
    private string? renderedLayer;

    public RecordInspector() => InitializeComponent();

    protected override void OnDataContextChanged(EventArgs e)
    {
        base.OnDataContextChanged(e);
        if (model is not null)
            model.PropertyChanged -= Update;
        model = DataContext as RecordInspectorViewModel;
        if (model is not null)
        {
            model.PropertyChanged += Update;
            RenderRecord();
            RenderEvidence();
            RenderCoverage();
            RenderFullPage();
            RenderSelection();
        }
    }

    private void Update(object? sender, PropertyChangedEventArgs args)
    {
        switch (args.PropertyName)
        {
            case nameof(RecordInspectorViewModel.Record):
                RenderRecord();
                break;

            case nameof(RecordInspectorViewModel.Evidence):
                RenderEvidence();
                break;

            case nameof(RecordInspectorViewModel.Coverage):
                RenderCoverage();
                break;

            case nameof(RecordInspectorViewModel.FullPage):
                RenderFullPage();
                break;

            case nameof(RecordInspectorViewModel.Selection):
                RenderSelection();
                break;

            case nameof(RecordInspectorViewModel.FullOpen):
                RenderExpandedState();
                break;
        }
    }

    private void RenderRecord()
    {
        coverageSlot.Content = null;
        evidenceSlot.Content = null;
        matrix = null;
        hexView = null;
        fullSlot = null;
        toggle = null;
        locationLabel = null;
        fieldList = null;
        selectionDetails = null;
        layerTabs = null;
        fieldRows.Clear();
        fullViews.Clear();
        if (model?.Record is not { } row)
        {
            inspectionContent.IsVisible = false;
            lastRecord = -1;

            return;
        }

        if (lastRecord != row.Index)
            inspector.Offset = default;
        lastRecord = row.Index;
        inspectionContent.IsVisible = true;
        recordHeading.Content = MakeRecordHeading(row);
        var status = ForRecord(row.Record, row.Group, row.Index);
        var why = Label(Describe(row.Record, row.Group), 12, Muted, mono: false, weight: FontWeight.Normal);
        why.TextWrapping = Avalonia.Media.TextWrapping.Wrap;
        var explanation = LayoutGrid("Auto,*", Badge(status, size: 11), why);
        explanation.ColumnSpacing = 9;
        explanation.VerticalAlignment = VerticalAlignment.Top;
        recordExplanation.Content = explanation;
        coverageSlot.IsVisible = row.Group is not null;
        evidenceSlot.Content = Notice(model.EvidenceMessage);
    }

    private void RenderEvidence()
    {
        if (model?.Evidence is { } source)
            BuildEvidence(source);
        else if (model?.Record is not null)
            evidenceSlot.Content = Notice(model.EvidenceMessage);
    }

    private void RenderCoverage()
    {
        if (model?.Coverage is { } coverage)
            coverageSlot.Content = MakeCoverage(coverage);
        else if (model?.CoverageError is { } message)
            coverageSlot.Content = Notice(message);
    }

    private static Control MakeRecordHeading(IndexedRow row)
    {
        var anchor = row.Record;
        var summary = anchor.Summary;
        var name = Label(RecordStatus.Title(anchor, row.Group, row.Index), 20, weight: Demi, brush: null, mono: false);
        name.FontFamily = Display;
        name.LineHeight = 28;
        var detailText = UIText.Format(Strings.RecordDetails, anchor.Time.Format(date: false), anchor.Context, anchor.Length, anchor.OriginalLength);
        var details = Label(detailText, 11, Muted, mono: true, weight: FontWeight.Normal);
        details.LineHeight = 16;
        var fileLocation = UIText.Format(Strings.RecordLocationTooltip, anchor.Time.Format(date: true), anchor.Block, anchor.DataOffset);
        ToolTip.SetTip(details, fileLocation);
        var recordNumber = UIText.Format(Strings.RecordHeading, Number(row.Index));
        var marker = Eyebrow(recordNumber);
        marker.LineHeight = 16;
        var main = Vertical(5, marker, name, details);
        var ends = Horizontal(10, Endpoint(Strings.SourceAddress, summary.SourceAddress),
            Label("→", 14, Muted, mono: false, weight: FontWeight.Normal),
            Endpoint(Strings.DestinationAddress, summary.DestinationAddress));
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
        Vertical(1, Label(name, 10, Muted, mono: false, weight: FontWeight.Normal), Label(value, 12, mono: true, brush: null, weight: FontWeight.Normal));

    private void BuildEvidence(EvidenceSource source)
    {
        var view = source.Data;
        var origin = source.Origin;
        var coordinates = source.Coordinates;
        var fieldHeader = PanelHeading("M5 2V17Q5 21 9 21H14 M5 8H14 M14 5H20V11H14Z M14 17H20V23H14Z", Strings.ProtocolFields, origin);
        layerTabs = new WrapPanel { Margin = new Thickness(9, 5), ItemSpacing = 4 };
        foreach (var layer in view.Fields.Select(item => item.Layer).Distinct())
        {
            var first = view.Fields.First(item => item.Layer == layer);
            var button = CommandButton(Label(layer, 11, Muted, mono: true, weight: FontWeight.Normal), model!.ChooseFieldCommand, layer, first);
            if (layer is "Ethernet" or "ARP" or "IPv4" or "IPv6" or "TCP" or "UDP")
                AutomationProperties.SetAutomationId(button, $"ProtocolLayer-{layer}");

            button.Classes.Add("layer");
            button.Padding = new Thickness(7, 3);
            button.MinHeight = 24;
            layerTabs.Children.Add(button);
        }
        fieldList = new StackPanel();
        AutomationProperties.SetAutomationId(fieldList, "CurrentProtocolFields");
        AutomationProperties.SetName(fieldList, Strings.CurrentProtocolFields);

        var tabBorder = LineBelow(layerTabs, default);
        var fieldContent = Vertical(0, fieldHeader, tabBorder, fieldList);
        var fieldCard = Card(fieldContent);
        var bytesHeader = PanelHeading("M8 3L2 10L8 17 M16 3L22 10L16 17 M14 1L10 19", UIText.Format(Strings.EvidenceBytes, origin), $"{view.Bytes.Length} B · {coordinates}");
        hexView = new HexView(view.Bytes, compact: false, model!.PickByteCommand.Execute, tintAt: null)
        {
            Margin = new Thickness(12, 7, 12, 7),
            MinWidth = 354
        };
        var byteViewId = source.Record < 0 ? "ReassembledEvidenceBytes" : FormattableString.Invariant($"RecordEvidenceBytes-{source.Record + 1}");
        AutomationProperties.SetAutomationId(hexView, byteViewId);
        var hexScroll = new ScrollViewer
        {
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Disabled,
            Content = hexView
        };
        selectionDetails = new ContentControl
        {
            ContentTemplate = (IDataTemplate)Resources["SelectionDetails"]!
        };
        AutomationProperties.SetAutomationId(selectionDetails, "ByteSelectionDetails");
        var byteCard = Card(Vertical(0, bytesHeader, hexScroll, selectionDetails));
        var panels = new Grid { ColumnSpacing = 10, RowSpacing = 10 };
        panels.Children.Add(fieldCard);
        panels.Children.Add(byteCard);
        panels.SizeChanged += (_, _) => ResizePanels();
        evidenceSlot.Content = panels;
        ResizePanels();
        renderedLayer = null;

        void ResizePanels()
        {
            var width = panels.Bounds.Width > 0 ? panels.Bounds.Width : Bounds.Width - 4;
            var narrow = width <= 770;
            if (panels.ColumnDefinitions.Count == (narrow ? 1 : 2))
                return;

            panels.ColumnDefinitions = narrow ? new ColumnDefinitions("*") : new ColumnDefinitions(".82*,1.18*");
            panels.RowDefinitions = narrow ? new RowDefinitions("Auto,Auto") : new RowDefinitions("Auto");
            Grid.SetColumn(byteCard, narrow ? 0 : 1);
            Grid.SetRow(byteCard, narrow ? 1 : 0);
        }
    }

    private static Control PanelHeading(string glyph, string name, string hint)
    {
        var heading = Horizontal(8, Icon(glyph, size: 16, stroke: null), Label(name, 14, weight: Demi, brush: null, mono: false));
        var bar = LayoutGrid("*,Auto", heading, Label(hint, 10, Muted, mono: true, weight: FontWeight.Normal));
        bar.ColumnSpacing = 6;
        bar.MinHeight = 38;

        return LineBelow(bar, new Thickness(12, 0));
    }

    private void ShowFieldLayer(string layer)
    {
        if (fieldList is null || layerTabs is null || model?.Evidence is not { } source)
            return;

        renderedLayer = layer;
        fieldRows.Clear();
        fieldList.Children.Clear();
        foreach (var button in layerTabs.Children.OfType<Button>())
            button.Classes.Set("selected", (button.Content as TextBlock)?.Text == layer);
        foreach (var item in source.Data.Fields.Where(item => item.Layer == layer))
        {
            var name = Label(item.Name, 12, brush: null, mono: false, weight: FontWeight.Normal);
            name.TextWrapping = TextWrapping.Wrap;
            var value = Label(item.Value, 12, mono: true, brush: null, weight: FontWeight.Normal);
            value.TextWrapping = TextWrapping.Wrap;
            var range = Label(item.Range?.Label ?? "—", 10, Soft, mono: true, weight: FontWeight.Normal);
            range.TextAlignment = TextAlignment.Right;
            var cells = LayoutGrid("1*,1.7*,70", name, value, range);
            cells.ColumnSpacing = 7;
            var button = CommandButton(cells, model!.ChooseFieldCommand,
                $"{item.Name} · {item.Value} · {item.Range?.Label ?? Strings.NoKnownOffset}", item);
            button.HorizontalAlignment = HorizontalAlignment.Stretch;
            button.HorizontalContentAlignment = HorizontalAlignment.Stretch;
            button.Padding = new Thickness(12, 3, 10, 3);
            button.MinHeight = 24;
            button.CornerRadius = default;
            var row = LineBelow(button, default);
            fieldList.Children.Add(row);
            fieldRows.Add((item, row));
        }
    }


    private void RenderSelection()
    {
        if (model?.Evidence is not { } source)
            return;

        var selection = model.Selection;
        var layer = selection.Field?.Layer ?? renderedLayer ?? source.Data.Fields[0].Layer;
        if (layer != renderedLayer)
            ShowFieldLayer(layer);

        hexView?.SetSelection(selection.Field?.Range, selection.Exact, reveal: true);
        HighlightFieldRows(selection.Field);
        matrix?.SetSelection(source.Record, selection.Payload);
        foreach (var (lane, view) in fullViews)
            view.SetSelection(null, model.FullByteOffset(lane), reveal: true);

        RenderSelectionLabels(selection);
    }

    private void RenderSelectionLabels(ByteSelection selection)
    {
        if (selectionDetails is not null)
            selectionDetails.Content = selection;
        if (locationLabel is not null)
        {
            locationLabel.IsVisible = selection.Location is not null;
            locationLabel.Text = selection.Location;
        }
    }

    private void HighlightFieldRows(PacketField? field)
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

    private Control MakeCoverage(FragmentCoverage coverage)
    {
        var group = coverage.Group;
        var data = coverage.Data;
        var status = ForGroup(group);
        var name = Horizontal(9, Label(Strings.FragmentCoverage, 16, weight: Demi, brush: null, mono: false),
            Label(group.Identity, 12, Muted, mono: true, weight: FontWeight.Normal),
            Badge(status, size: 11));
        toggle = CommandButton(Label(model!.ToggleLabel, size: 12, brush: null, mono: false, weight: FontWeight.Normal), model.ToggleFullCommand, model.ToggleLabel, parameter: null);
        AutomationProperties.SetAutomationId(toggle, "ToggleFullBytes");
        toggle.Classes.Add("outline");
        var top = LayoutGrid("*,Auto", name, toggle);
        var scroll = new ScrollViewer
        {
            HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, VerticalScrollBarVisibility = ScrollBarVisibility.Auto,
            Margin = new Thickness(12, 4, 4, 4), MaxHeight = 288
        };
        var map = new CoverageMatrix(data, model.ChooseEvidence);
        matrix = map;
        scroll.Content = map;
        scroll.ScrollChanged += (_, _) => map.SetViewport(scroll.Offset, scroll.Viewport);
        scroll.SizeChanged += (_, _) => map.SetViewport(scroll.Offset, scroll.Viewport);
        var summaryData = coverage.Summary;
        var (brush, _) = Palette(summaryData.Tone);
        var detailLabel = Label(summaryData.Message, 12, Muted, mono: false, weight: FontWeight.Normal);
        AutomationProperties.SetAutomationId(detailLabel, "FragmentCoverageSummary");
        detailLabel.TextWrapping = TextWrapping.Wrap;
        var summary = LayoutGrid("Auto,*", Label(summaryData.Title, 12, brush, weight: Demi, mono: false), detailLabel);
        summary.ColumnSpacing = 12;
        var summaryBorder = new Border { BorderBrush = Line, BorderThickness = new Thickness(0, 1, 0, 0), Child = summary, Padding = new Thickness(12, 6) };
        locationLabel = Label("", 11, mono: true, brush: null, weight: FontWeight.Normal);
        AutomationProperties.SetAutomationId(locationLabel, "FragmentByteLocation");
        locationLabel.Margin = new Thickness(12, 5);
        locationLabel.TextWrapping = TextWrapping.Wrap;
        locationLabel.IsVisible = false;
        fullSlot = new ContentControl();
        RenderExpandedState();
        var header = LineBelow(top, new Thickness(12, 8));
        var content = Vertical(0, header, scroll, summaryBorder, locationLabel, fullSlot);

        return Card(content);
    }

    private void RenderExpandedState()
    {
        if (toggle is null || fullSlot is null || model is null)
            return;

        var label = model.ToggleLabel;
        toggle.Content = Label(label, 12, model.FullOpen ? Accent : Text, mono: false, weight: FontWeight.Normal);
        toggle.Classes.Set("selected", model.FullOpen);
        AutomationProperties.SetName(toggle, label);
        fullSlot.IsVisible = model.FullOpen;
    }

    private void RenderFullPage()
    {
        if (fullSlot is null || model?.Coverage is not { } coverage)
            return;

        fullViews.Clear();
        if (model.FullPage is not { } page)
        {
            fullSlot.Content = Notice(model.FullMessage);

            return;
        }

        fullSlot.Content = MakeFullPage(coverage.Data, page);
        RenderSelection();
    }

    private Control MakeFullPage(CoverageData data, FullBytePage page)
    {
        var cards = new Grid { ColumnSpacing = 9 };
        for (var n = 0; n < page.Lanes.Length; n++)
        {
            var card = MakeFullCard(data, page.Lanes[n], page.Dumps[n], page.FirstIndex + n);
            cards.ColumnDefinitions.Add(new ColumnDefinition(1, GridUnitType.Star));
            Grid.SetColumn(card, n);
            cards.Children.Add(card);
        }
        var previous = CommandButton(Label(Strings.PreviousGroup, size: 12, brush: null, mono: false, weight: FontWeight.Normal), model!.PreviousPageCommand, Strings.PreviousGroup, parameter: null);
        var next = CommandButton(Label(Strings.NextGroup, size: 12, brush: null, mono: false, weight: FontWeight.Normal), model.NextPageCommand, Strings.NextGroup, parameter: null);
        var pageControls = Horizontal(4, previous, Label(page.Caption, 11, Muted, mono: false, weight: FontWeight.Normal), next);
        pageControls.IsVisible = page.HasPages;
        var scroll = new ScrollViewer { Content = cards, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto };
        var content = Vertical(6, pageControls, scroll);
        content.Margin = new Thickness(12, 8, 12, 12);

        return content;
    }

    private Control MakeFullCard(CoverageData data, CoverageLane lane, byte[] bytes, int index)
    {
        var hex = new HexView(bytes, compact: true, offset => model!.ChooseEvidence(lane.Record, offset),
            offset => CoverageMatrix.TintAt(data, lane, offset)) { MinWidth = 230 };
        fullViews.Add((lane, hex));
        var swatch = new Border { Width = 7, Height = 7, Background = CoverageMatrix.Swatch(index) };
        var laneLabel = LaneLabel(lane);
        var heading = Horizontal(8, swatch, Label(laneLabel, 13, mono: true, weight: Demi, brush: null));
        var title = LayoutGrid("*,Auto", heading, Label($"{bytes.Length} B", 10, Muted, mono: false, weight: FontWeight.Normal));
        var button = CommandButton(title, model!.ChooseSourceCommand, laneLabel, lane.Record);
        var automationId = lane.Derived ? "ReassembledByteSource" : FormattableString.Invariant($"RecordByteSource-{lane.Record + 1}");
        AutomationProperties.SetAutomationId(button, automationId);
        button.HorizontalAlignment = HorizontalAlignment.Stretch;
        button.HorizontalContentAlignment = HorizontalAlignment.Stretch;
        var origin = Label(UIText.Format(Strings.FragmentStartsAt, (lane.Derived ? "IP" : Strings.Frame), lane.Slice.Start), 10, Muted, mono: false, weight: FontWeight.Normal);

        return new Border
        {
            Background = Bg, BorderBrush = Line, BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(4), Padding = new Thickness(8), MinWidth = 248,
            Child = Vertical(3, button, origin, hex)
        };
    }
}
