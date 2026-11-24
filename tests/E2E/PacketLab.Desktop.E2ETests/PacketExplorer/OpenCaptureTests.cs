using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Platform.Storage;
using static PacketLab.Desktop.E2ETests.ExplorerTestHost;
using static PacketLab.Desktop.E2ETests.Fixtures.CaptureFiles;

namespace PacketLab.Desktop.E2ETests.PacketExplorer;

public sealed class OpenCaptureTests
{
    [Test]
    [Arguments("zh-CN")]
    [Arguments("en-US")]
    public async Task Starting_without_a_file_shows_the_open_prompt_and_loads_the_file_chosen_there(string culture)
    {
        FilePickerOpenOptions? picker = null;
        var result = await WithExplorer(async window =>
        {
            var prompt = FindById<Border>(window, "CaptureLanding") is not null;
            var workbench = FindById<Grid>(window, "CaptureWorkbench") is not null;
            SaveFrame(window, culture == "en-US" ? "app-en-landing" : "app-landing");
            Click(window, GetById<Button>(window, "OpenCaptureButton"));
            await WaitFor(() => IsRecordSelected(window, 1) && FindRecordBytes(window, 1) is not null);
            if (culture == "en-US")
                SaveFrame(window, "app-en-workbench");

            return (Prompt: prompt, InitialWorkbench: workbench,
                Records: GetById<ListBox>(window, "CaptureRecordList").ItemCount,
                PromptAfterOpen: FindById<Border>(window, "CaptureLanding") is not null);
        }, file: null, chooseFile: options =>
        {
            picker = options;
            return Task.FromResult<string?>(Fixture("record-workbench.pcapng"));
        }, culture: culture);

        await Assert.That(result.Prompt).IsTrue();
        await Assert.That(result.InitialWorkbench).IsFalse();
        await Assert.That(result.Records).IsEqualTo(16);
        await Assert.That(result.PromptAfterOpen).IsFalse();
        await Assert.That(picker!.FileTypeFilter!.SelectMany(type => type.Patterns!))
            .IsEquivalentTo(["*.pcap", "*.pcapng", "*.cap", "*"]);
    }

    [Test]
    public async Task Control_O_opens_the_file_selected_by_the_picker()
    {
        var result = await WithExplorer(async window =>
        {
            window.KeyPress(Key.O, RawInputModifiers.Control, PhysicalKey.O, null);
            await WaitFor(() => IsRecordSelected(window, 1));

            return GetById<ListBox>(window, "CaptureRecordList").ItemCount;
        }, file: null, chooseFile: _ => Task.FromResult<string?>(Fixture("record-workbench.pcapng")));

        await Assert.That(result).IsEqualTo(16);
    }

    [Test]
    public async Task An_empty_capture_returns_to_the_file_prompt()
    {
        var file = Path.Combine(Path.GetTempPath(), $"packetlab-empty-{Guid.NewGuid():N}.pcap");
        try
        {
            WriteRepeatedCapture(file, 0);
            var result = await WithExplorer(async window =>
            {
                await WaitFor(() => FindById<TextBlock>(window, "CaptureLandingHint")?.Text
                    ?.Contains(Path.GetFileName(file), StringComparison.Ordinal) == true);

                return (Hint: GetById<TextBlock>(window, "CaptureLandingHint").Text,
                    Workbench: FindById<Grid>(window, "CaptureWorkbench") is not null,
                    CanChoose: GetById<Button>(window, "OpenCaptureButton").IsEnabled);
            }, file);

            await Assert.That(result.Hint).Contains(Path.GetFileName(file));
            await Assert.That(result.Workbench).IsFalse();
            await Assert.That(result.CanChoose).IsTrue();
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Test]
    public async Task Truncated_pcapng_shows_a_read_error_on_the_file_prompt()
    {
        var file = Path.GetTempFileName();
        try
        {
            using (var fixture = File.OpenRead(Fixture("record-workbench.pcapng")))
            {
                var prefix = new byte[16];
                fixture.ReadExactly(prefix);
                File.WriteAllBytes(file, prefix);
            }
            var result = await WithExplorer(async window =>
            {
                await WaitFor(() => FindById<TextBlock>(window, "LandingCaptureError") is not null);

                return (Error: GetById<TextBlock>(window, "LandingCaptureError").Text,
                    CanChoose: GetById<Button>(window, "OpenCaptureButton").IsEnabled);
            }, file);

            await Assert.That(result.Error).Contains(Path.GetFileName(file));
            await Assert.That(result.CanChoose).IsTrue();
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Test]
    public async Task Opening_a_truncated_capture_keeps_the_readable_record_available()
    {
        var result = await WithExplorer(async window =>
        {
            await WaitFor(() => IsRecordSelected(window, 1));
            Click(window, GetById<Button>(window, "ChangeCaptureButton"));
            await WaitFor(() => FindById<TextBlock>(window, "WorkbenchCaptureError") is not null &&
                FindRecordBytes(window, 1) is { ByteCount: 3 });

            return (Count: GetById<ListBox>(window, "CaptureRecordList").ItemCount,
                Selected: IsRecordSelected(window, 1), ByteCount: FindRecordBytes(window, 1)!.ByteCount);
        }, Fixture("record-workbench.pcapng"), _ => Task.FromResult<string?>(Fixture("record-truncated.pcap")));

        await Assert.That(result.Count).IsEqualTo(1);
        await Assert.That(result.Selected).IsTrue();
        await Assert.That(result.ByteCount).IsEqualTo(3);
    }

    [Test]
    public async Task Replacing_a_capture_with_an_unreadable_file_keeps_the_loaded_records()
    {
        var file = Path.GetTempFileName();
        try
        {
            var result = await WithExplorer(async window =>
            {
                await WaitFor(() => IsRecordSelected(window, 1));
                Click(window, GetById<Button>(window, "ChangeCaptureButton"));
                await WaitFor(() => FindById<TextBlock>(window, "WorkbenchCaptureError") is not null);

                return (Error: GetById<TextBlock>(window, "WorkbenchCaptureError").Text,
                    VisibleRecords: GetById<ListBox>(window, "CaptureRecordList").ItemCount);
            }, Fixture("record-workbench.pcapng"), _ => Task.FromResult<string?>(file));

            await Assert.That(result.Error).Contains(Path.GetFileName(file));
            await Assert.That(result.VisibleRecords).IsEqualTo(16);
        }
        finally
        {
            File.Delete(file);
        }
    }
}
