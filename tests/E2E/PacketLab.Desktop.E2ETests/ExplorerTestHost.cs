using System.Globalization;
using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Media.Imaging;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;
using PacketLab.Desktop.Controls.PacketExplorer;
using PacketLab.Desktop.Views.PacketExplorer;
using static PacketLab.Desktop.E2ETests.Fixtures.CaptureFiles;

namespace PacketLab.Desktop.E2ETests;

internal static class ExplorerTestHost
{
    private static readonly HeadlessUnitTestSession Session = HeadlessUnitTestSession.StartNew(typeof(HeadlessApp));

    internal static async Task SelectFixtureFragment(ExplorerWindow window)
    {
        await WaitFor(() => FindRow(window, 5) is not null);
        Click(window, FindRow(window, 5)!);
        await WaitFor(() => IsRecordSelected(window, 5) && FindById<CoverageMatrix>(window, "FragmentCoverage") is not null);
    }

    internal static Task<T> WithExplorer<T>(Func<ExplorerWindow, Task<T>> interact) =>
        WithExplorer(interact, Fixture("record-workbench.pcapng"));

    internal static Task<T> WithExplorer<T>(Func<ExplorerWindow, Task<T>> interact, string? file,
        Func<FilePickerOpenOptions, Task<string?>>? chooseFile = null, string culture = "zh-CN") => Session.Dispatch<T>(async () =>
    {
        var previousCulture = CultureInfo.CurrentUICulture;
        var previousDefaultCulture = CultureInfo.DefaultThreadCurrentUICulture;
        var uiCulture = CultureInfo.GetCultureInfo(culture);
        CultureInfo.CurrentUICulture = uiCulture;
        // Deferred layout can create record rows outside the test callback's execution context.
        CultureInfo.DefaultThreadCurrentUICulture = uiCulture;
        try
        {
            var window = new ExplorerWindow(file, chooseFile: chooseFile, preferencesPath: null);
            try
            {
                window.Show();
                return await interact(window);
            }
            catch (OperationCanceledException error)
            {
                SaveFrame(window, "app-failure");
                throw new InvalidOperationException(string.Join(" | ", ReadText(window)), error);
            }
            finally
            {
                window.Close();
            }
        }
        finally
        {
            CultureInfo.DefaultThreadCurrentUICulture = previousDefaultCulture;
            CultureInfo.CurrentUICulture = previousCulture;
        }
    }, CancellationToken.None);

    internal static async Task WaitFor(Func<bool> ready, int seconds = 8)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        while (!ready())
        {
            await Task.Delay(16, timeout.Token);
            Dispatcher.UIThread.RunJobs();
        }
    }

    internal static IEnumerable<string> ReadText(Visual root) => root.GetVisualDescendants().OfType<TextBlock>()
        .Where(block => block.IsEffectivelyVisible).Select(block => block.Text ?? "");

    internal static T? FindById<T>(Visual root, string automationId) where T : Control =>
        root.GetVisualDescendants().OfType<T>()
            .SingleOrDefault(control => control.IsEffectivelyVisible && AutomationProperties.GetAutomationId(control) == automationId);

    internal static T GetById<T>(Window window, string automationId) where T : Control =>
        FindById<T>(window, automationId) ?? throw new InvalidOperationException($"Visible {typeof(T).Name} '{automationId}' was not found.");

    internal static bool IsRecordSelected(Window window, int recordNumber) =>
        FindById<ListBox>(window, "CaptureRecordList")?.SelectedItem is int index && index == recordNumber - 1;

    internal static RecordRow? FindRow(Window window, int recordNumber) =>
        FindById<RecordRow>(window, FormattableString.Invariant($"CaptureRecord-{recordNumber}"));

    internal static HexView? FindRecordBytes(Window window, int recordNumber) =>
        FindById<HexView>(window, FormattableString.Invariant($"RecordEvidenceBytes-{recordNumber}"));

    internal static Point Center(Control control, Window window) =>
        control.TranslatePoint(new Point(control.Bounds.Width / 2, control.Bounds.Height / 2), window)!.Value;

    internal static void Click(Window window, Control control, Point? local = null)
    {
        var point = local.HasValue ? control.TranslatePoint(local.Value, window)!.Value : Center(control, window);
        window.MouseMove(point);
        window.MouseDown(point, MouseButton.Left);
        window.MouseUp(point, MouseButton.Left);
        Dispatcher.UIThread.RunJobs();
    }

    internal static void SaveFrame(Window window, string name)
    {
        var path = Environment.GetEnvironmentVariable("PACKETLAB_SCREENSHOTS");
        if (string.IsNullOrWhiteSpace(path))
            return;

        using var frame = window.CaptureRenderedFrame();
        frame?.Save(Path.Combine(path, name + ".png"), PngBitmapEncoderOptions.Default);
    }
}
