using System.Diagnostics;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.VisualTree;
using PacketLab.Desktop.Controls.PacketExplorer;
using static PacketLab.Desktop.E2ETests.ExplorerTestHost;
using static PacketLab.Desktop.E2ETests.Fixtures.CaptureFiles;

namespace PacketLab.Desktop.E2ETests.PacketExplorer;

public sealed class BrowseRecordsTests
{
    [Test]
    public async Task Search_and_fragment_filter_keep_only_matching_capture_records()
    {
        var result = await WithExplorer(async window =>
        {
            await WaitFor(() => IsRecordSelected(window, 1));
            Click(window, GetById<Button>(window, "FilterFragments"));
            var search = GetById<TextBox>(window, "CaptureRecordSearch");
            Click(window, search);
            window.KeyTextInput("#012");
            var records = GetById<ListBox>(window, "CaptureRecordList");
            await WaitFor(() => records is { ItemCount: 1, SelectedItem: 11 });
            var count = records.ItemCount;

            window.KeyTextInput("missing");
            await WaitFor(() => records.ItemCount == 0 && FindById<Button>(window, "ClearCaptureFilters") is not null);
            Click(window, GetById<Button>(window, "ClearCaptureFilters"));
            await WaitFor(() => records.ItemCount == 16);
            return (Count: count, Restored: records.ItemCount);
        });

        await Assert.That(result.Count).IsEqualTo(1);
        await Assert.That(result.Restored).IsEqualTo(16);
    }

    [Test]
    public async Task Splitter_drag_resizes_the_record_list_and_enter_restores_its_width()
    {
        var result = await WithExplorer(async window =>
        {
            await WaitFor(() => IsRecordSelected(window, 1));
            var list = GetById<ListBox>(window, "CaptureRecordList");
            var grip = GetById<Control>(window, "ResizeCaptureRecordList");
            var startWidth = list.Bounds.Width;
            var point = Center(grip, window);
            var target = point + new Vector(72, 0);
            window.MouseDown(point, MouseButton.Left);
            window.MouseMove(target, RawInputModifiers.LeftMouseButton);
            window.MouseUp(target, MouseButton.Left);
            await WaitFor(() => list.Bounds.Width > startWidth);
            var resizedWidth = list.Bounds.Width;

            window.KeyPress(Key.Enter, RawInputModifiers.None, PhysicalKey.Enter, null);
            await WaitFor(() => list.Bounds.Width == startWidth);
            return (Delta: resizedWidth - startWidth, Restored: list.Bounds.Width == startWidth);
        });

        await Assert.That(result.Delta).IsEqualTo(72d);
        await Assert.That(result.Restored).IsTrue();
    }

    [Test]
    public async Task Large_capture_virtualizes_the_record_list_and_can_select_the_final_record()
    {
        var count = StressRecordCount();
        var file = Path.Combine(Path.GetTempPath(), $"packetlab-headless-{Guid.NewGuid():N}.pcap");
        try
        {
            WriteRepeatedCapture(file, count);
            var result = await WithExplorer(async window =>
            {
                var clock = Stopwatch.StartNew();
                await WaitFor(() => FindById<ListBox>(window, "CaptureRecordList") is { ItemCount: > 0 }, seconds: 45);
                var first = clock.ElapsedMilliseconds;
                var records = GetById<ListBox>(window, "CaptureRecordList");
                var status = GetById<TextBlock>(window, "CaptureStatus");
                await WaitFor(() => records.ItemCount == count && status.Text == file, seconds: 45);
                var indexed = clock.ElapsedMilliseconds;
                var visible = window.GetVisualDescendants().OfType<RecordRow>().Count();
                Click(window, GetById<TextBox>(window, "CaptureRecordSearch"));
                window.KeyTextInput($"#{count}");
                await WaitFor(() => IsRecordSelected(window, count) && FindRecordBytes(window, count) is not null, seconds: 45);
                Console.WriteLine($"Capture {count:N0} records · first displayed {first:N0} ms · indexed {indexed:N0} ms · final lookup {clock.ElapsedMilliseconds - indexed:N0} ms · {visible} realized rows");

                return (Visible: visible, Selected: records.SelectedItem, Filtered: records.ItemCount,
                    ByteCount: FindRecordBytes(window, count)!.ByteCount);
            }, file);

            await Assert.That(result.Visible).IsLessThan(100);
            await Assert.That((int)result.Selected!).IsEqualTo(count - 1);
            await Assert.That(result.Filtered).IsEqualTo(1);
            await Assert.That(result.ByteCount).IsEqualTo(1024);
        }
        finally
        {
            File.Delete(file);
        }
    }

    private static int StressRecordCount()
    {
        var supplied = Environment.GetEnvironmentVariable("PACKETLAB_STRESS_RECORDS");
        return int.TryParse(supplied, out var count) && count >= 12_000 ? count : 12_000;
    }
}
