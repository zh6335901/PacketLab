using PacketLab.Desktop.Localization;
using System.ComponentModel;
using System.Globalization;
using Avalonia;
using Avalonia.Animation;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Input;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using PacketLab.Desktop.Controls;
using PacketLab.Desktop.ViewModels;
using static PacketLab.Desktop.ViewStyle;

namespace PacketLab.Desktop.Views;

internal sealed partial class ExplorerWindow : Window
{
    private static readonly Geometry MaximizeGlyph = Geometry.Parse("M2.5 1.5H9.5Q10.5 1.5 10.5 2.5V9.5Q10.5 10.5 9.5 10.5H2.5Q1.5 10.5 1.5 9.5V2.5Q1.5 1.5 2.5 1.5Z");
    private static readonly Geometry RestoreGlyph = Geometry.Parse("M3.5 3.5V2Q3.5 1.5 4 1.5H10Q10.5 1.5 10.5 2V8Q10.5 8.5 10 8.5H8.5 M2 3.5H8Q8.5 3.5 8.5 4V10Q8.5 10.5 8 10.5H2Q1.5 10.5 1.5 10V4Q1.5 3.5 2 3.5Z");
    private readonly string preferencesPath;
    private readonly ColumnDefinition listColumn;
    private readonly ExplorerViewModel model;
    private readonly bool animate = NavigationMotion.Enabled;
    private GridLength savedListWidth;

    internal ExplorerWindow(string? file, string? preferencesPath = null,
        Func<FilePickerOpenOptions, Task<string?>>? chooseFile = null)
    {
        this.preferencesPath = preferencesPath ?? "";
        savedListWidth = ReadWidth(preferencesPath) is { } width ? new GridLength(width) : GridLength.Auto;
        InitializeComponent();
        listColumn = Workspace.ColumnDefinitions[0];
        var grip = MakeGrip();
        Grid.SetColumn(grip, 1);
        Workspace.Children.Add(grip);

        var picker = chooseFile ?? PickFromStorageAsync;
        model = new ExplorerViewModel(() => ChooseCaptureAsync(picker));
        RecordList.ItemTemplate = new FuncDataTemplate<int>((index, _) =>
            new RecordRow(model.ReadRow(index), model.SelectedRecord, model.SelectedGroup), supportsRecycling: false);
        DataContext = model;
        model.PropertyChanged += ModelChanged;
        model.Navigation.PropertyChanged += NavigationChanged;
        if (animate)
        {
            DrawerShade.Transitions = [new DoubleTransition
            {
                Property = OpacityProperty, Duration = TimeSpan.FromMilliseconds(200), Easing = NavigationMotion.EasyEase
            }];
        }
        UpdateCaption();

        SizeChanged += (_, _) => ApplyLayout();
        ContentArea.SizeChanged += (_, args) => ApplyWorkspaceLayout(args.NewSize.Width);
        RecordToolbar.SizeChanged += (_, args) => LayoutRecordToolbar(args.NewSize.Width);
        PropertyChanged += (_, args) =>
        {
            if (args.Property == WindowStateProperty)
                UpdateCaption();
        };
        KeyDown += HandleEscape;
        DrawerShade.PointerPressed += (_, args) =>
        {
            model.Navigation.CloseDrawerCommand.Execute(null);
            args.Handled = true;
        };
        Overlay.PointerPressed += (_, args) =>
        {
            if (args.Source == Overlay)
                model.CloseMetadataCommand.Execute(null);
        };
        Opened += (_, _) =>
        {
            ApplyLayout();
            if (file is not null)
                _ = model.OpenAsync(file);
        };
        Closed += (_, _) =>
        {
            model.PropertyChanged -= ModelChanged;
            model.Navigation.PropertyChanged -= NavigationChanged;
            model.Dispose();
        };
    }

    private void ModelChanged(object? sender, PropertyChangedEventArgs args)
    {
        if (args.PropertyName == nameof(ExplorerViewModel.SelectedItem))
        {
            foreach (var row in RecordList.GetVisualDescendants().OfType<RecordRow>())
                row.Refresh(model.SelectedRecord, model.SelectedGroup);
            if (model.SelectedItem is int item)
                RecordList.ScrollIntoView((object)item);
        }
        else if (args.PropertyName == nameof(ExplorerViewModel.HasMetadata))
        {
            Dispatcher.UIThread.Post(() =>
            {
                if (model.HasMetadata)
                    CloseButton.Focus();
                else
                    FileButton.Focus();
            }, DispatcherPriority.Loaded);
        }
    }

    private void ApplyLayout()
    {
        var width = Bounds.Width;
        var narrow = width <= 650;
        Grid.SetColumn(ContentArea, narrow ? 0 : 1);
        Grid.SetColumnSpan(ContentArea, narrow ? 2 : 1);
        Grid.SetColumnSpan(ToolRail, narrow ? 2 : 1);
        TitlePath.Margin = new Thickness(narrow ? 10 : 16, 0, 0, 0);
        TitlePath.Spacing = narrow ? 7 : 12;
        CrumbCategory.IsVisible = !narrow;
        CrumbSeparator.IsVisible = !narrow;
        MinimizeButton.Classes.Set("narrow", narrow);
        SizeButton.Classes.Set("narrow", narrow);
        CloseWindowButton.Classes.Set("narrow", narrow);
        model.Navigation.SetNarrow(narrow);
        ApplyNavigationLayout();
        Landing.Padding = new Thickness(20, 28, 20, Math.Clamp(Bounds.Height * .11, 28, 100));
        MetadataPane.Width = Math.Min(740, width - 36);
        MetadataPane.Margin = new Thickness(0, Math.Clamp(Bounds.Height * .09, 30, 92), 0, 0);
        MetadataScroll.MaxHeight = Math.Max(245, Bounds.Height * .75 - 68);
    }

    private void ApplyWorkspaceLayout(double width)
    {
        if (width <= 0)
            return;

        var narrow = width <= 650;
        var margin = narrow ? 12 : Math.Clamp(width * .034, 24, 52);
        Workbench.Margin = new Thickness(margin, 0, margin, 0);
        var contentWidth = width - 2 * margin;
        var (min, detail, initial) = contentWidth switch
        {
            <= 650 => (146, 226, Math.Clamp(contentWidth * .30, 156, 222)),
            <= 850 => (210, 320, Math.Clamp(contentWidth * .29, 228, 280)),
            _ => (246, 400, Math.Clamp(contentWidth * .26, 275, 360))
        };
        var max = Math.Max(min, contentWidth - 16 - detail);
        listColumn.MinWidth = min;
        listColumn.MaxWidth = max;
        listColumn.Width = new GridLength(Math.Clamp(savedListWidth.IsAuto ? initial : savedListWidth.Value, min, max));
        LayoutCaptureHeading(contentWidth);
    }

    private void LayoutCaptureHeading(double width)
    {
        var stacked = width < 720;
        CaptureHeading.Classes.Set("stacked-heading", stacked);
        CaptureHeading.RowSpacing = stacked ? 9 : 0;
        Grid.SetColumnSpan(CaptureSummary, stacked ? 2 : 1);
        Grid.SetColumn(FileBar, stacked ? 0 : 1);
        Grid.SetRow(FileBar, stacked ? 1 : 0);
        Grid.SetColumnSpan(FileBar, stacked ? 2 : 1);
    }

    private void LayoutRecordToolbar(double width)
    {
        var combinedWidth = RecordListTitle.DesiredSize.Width + RecordListCount.DesiredSize.Width + RecordFilters.DesiredSize.Width + 12;
        var stacked = width < Math.Max(216, combinedWidth);
        Grid.SetColumnSpan(RecordFilters, stacked ? 2 : 1);
        Grid.SetColumn(RecordFilters, stacked ? 0 : 1);
        Grid.SetRow(RecordFilters, stacked ? 1 : 0);
        RecordToolbar.RowSpacing = stacked ? 5 : 0;
    }

    private void NavigationChanged(object? sender, PropertyChangedEventArgs args)
    {
        if (args.PropertyName is not (nameof(ToolNavigationViewModel.IsCompactDesktop) or nameof(ToolNavigationViewModel.DrawerOpen)))
            return;

        ApplyNavigationLayout();
        if (args.PropertyName == nameof(ToolNavigationViewModel.DrawerOpen) &&
            model.Navigation.IsNarrow && !model.Navigation.DrawerOpen)
            Dispatcher.UIThread.Post(() => MobileNavigation.Focus(), DispatcherPriority.Loaded);
    }

    private void ApplyNavigationLayout()
    {
        var navigation = model.Navigation;
        ToolRail.UpdateLayout(Bounds.Width, navigation, animate);
        var showShade = navigation.IsNarrow && navigation.DrawerOpen;
        DrawerShade.Opacity = showShade ? 1 : 0;
        DrawerShade.IsHitTestVisible = showShade;
    }

    private void HandleEscape(object? sender, KeyEventArgs args)
    {
        if (args.Key != Key.Escape)
            return;

        if (model.Navigation.DrawerOpen)
            model.Navigation.CloseDrawerCommand.Execute(null);
        else if (model.HasMetadata)
            model.CloseMetadataCommand.Execute(null);
        else
            return;

        args.Handled = true;
    }

    private void UpdateCaption()
    {
        var maximized = WindowState == WindowState.Maximized;
        var action = maximized ? Strings.RestoreWindow : Strings.MaximizeWindow;
        SizeGlyph.Data = maximized ? RestoreGlyph : MaximizeGlyph;
        AutomationProperties.SetName(SizeButton, action);
        ToolTip.SetTip(SizeButton, action);
    }

    private void MinimizeWindow(object? sender, RoutedEventArgs args) => WindowState = WindowState.Minimized;

    private void ToggleWindowSize(object? sender, RoutedEventArgs args) =>
        WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized;

    private void CloseWindow(object? sender, RoutedEventArgs args) => Close();

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
        var hint = Strings.ResizeRecordListHint;
        AutomationProperties.SetName(grip, Strings.ResizeRecordList);
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

            start = e.GetPosition(Workspace).X;
            before = savedListWidth.IsAuto ? null : savedListWidth.Value;
            startWidth = listColumn.ActualWidth;
            e.Pointer.Capture(grip);
            e.Handled = true;
        };
        grip.PointerMoved += (_, e) =>
        {
            if (start is { } x)
                SetWidth(startWidth + e.GetPosition(Workspace).X - x);
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
        savedListWidth = width is { } requested
            ? new GridLength(Math.Clamp(requested, listColumn.MinWidth, listColumn.MaxWidth)) : GridLength.Auto;
        ApplyWorkspaceLayout(ContentArea.Bounds.Width);
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
        if (preferencesPath.Length == 0)
            return;

        try
        {
            var parent = Path.GetDirectoryName(preferencesPath)!;
            Directory.CreateDirectory(parent);
            var width = savedListWidth.IsAuto ? "" : savedListWidth.Value.ToString(CultureInfo.InvariantCulture);
            File.WriteAllText(preferencesPath, width);
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
        }
    }

    private static Task<string?> ChooseCaptureAsync(Func<FilePickerOpenOptions, Task<string?>> pick)
    {
        var options = new FilePickerOpenOptions
        {
            Title = Strings.OpenCapture,
            AllowMultiple = false,
            FileTypeFilter =
            [
                new FilePickerFileType(Strings.CaptureFiles) { Patterns = ["*.pcap", "*.pcapng", "*.cap"] },
                new FilePickerFileType(Strings.AllFiles) { Patterns = ["*"] }
            ]
        };

        return pick(options);
    }

    private async Task<string?> PickFromStorageAsync(FilePickerOpenOptions options)
    {
        var result = await StorageProvider.OpenFilePickerAsync(options);

        return result.FirstOrDefault()?.TryGetLocalPath();
    }
}
