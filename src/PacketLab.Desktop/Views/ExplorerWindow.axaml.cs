using System.ComponentModel;
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

namespace PacketLab.Desktop;

internal sealed partial class ExplorerWindow : Window
{
    private readonly string preferencesPath;
    private readonly ColumnDefinition listColumn;
    private readonly ExplorerViewModel model;
    private double? savedListWidth;

    internal ExplorerWindow(string? file, string? preferencesPath = null,
        Func<FilePickerOpenOptions, Task<string?>>? chooseFile = null)
    {
        this.preferencesPath = preferencesPath ?? "";
        savedListWidth = ReadWidth(preferencesPath);
        InitializeComponent();
        listColumn = Workspace.ColumnDefinitions[0];
        listColumn.MinWidth = 246;
        var grip = MakeGrip();
        Grid.SetColumn(grip, 1);
        Workspace.Children.Add(grip);

        var picker = chooseFile ?? PickFromStorageAsync;
        model = new ExplorerViewModel(() => ChooseCaptureAsync(picker));
        RecordList.ItemTemplate = new FuncDataTemplate<int>((index, _) =>
            new RecordRow(model.ReadRow(index), model.SelectedRecord, model.SelectedGroup), supportsRecycling: false);
        DataContext = model;
        model.PropertyChanged += ModelChanged;

        SizeChanged += (_, _) => ApplyLayout();
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
        var margin = Math.Clamp(width * .034, 19, 52);
        Brand.Padding = new Thickness(margin, 0);
        Workbench.Margin = new Thickness(margin, 0, margin, 0);
        var contentWidth = width - 2 * margin;
        var availableListWidth = contentWidth - 16 - 350;
        var max = Math.Max(246, availableListWidth);
        var initial = Math.Clamp(contentWidth * .26, 275, 360);
        listColumn.MaxWidth = max;
        listColumn.Width = new GridLength(Math.Clamp(savedListWidth ?? initial, 246, max));
        FileLabel.MaxWidth = Math.Max(95, contentWidth * .36 - 153);
        Landing.Padding = new Thickness(20, 28, 20, Math.Clamp(Bounds.Height * .11, 28, 100));
        MetadataPane.Width = Math.Min(740, width - 36);
        MetadataPane.Margin = new Thickness(0, Math.Clamp(Bounds.Height * .09, 30, 92), 0, 0);
        MetadataScroll.MaxHeight = Math.Max(245, Bounds.Height * .75 - 68);
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

            start = e.GetPosition(Workspace).X;
            before = savedListWidth;
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
        savedListWidth = width is { } requested ? Math.Clamp(requested, listColumn.MinWidth, listColumn.MaxWidth) : null;
        ApplyLayout();
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
            var width = savedListWidth?.ToString(CultureInfo.InvariantCulture) ?? "";
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
            Title = "打开抓包文件",
            AllowMultiple = false,
            FileTypeFilter = [new FilePickerFileType("捕获文件") { Patterns = ["*.pcap", "*.pcapng", "*.cap"] }, FilePickerFileTypes.All]
        };

        return pick(options);
    }

    private async Task<string?> PickFromStorageAsync(FilePickerOpenOptions options)
    {
        var result = await StorageProvider.OpenFilePickerAsync(options);

        return result.FirstOrDefault()?.TryGetLocalPath();
    }
}
