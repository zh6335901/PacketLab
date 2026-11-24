using System.Buffers.Binary;
using System.Diagnostics;
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

namespace PacketLab.Desktop.E2ETests;

public sealed class HeadlessApp
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UseSkia()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });
}

[NotInParallel]
public sealed class ExploreCaptureTests
{
    private static readonly HeadlessUnitTestSession Session = HeadlessUnitTestSession.StartNew(typeof(HeadlessApp));

    [Test]
    public async Task Compact_navigation_keeps_all_tool_icons_and_restores_folded_groups()
    {
        var result = await WithExplorer(async window =>
        {
            await SelectFixtureFragment(window);
            var rail = Find<ToolNavigationView>(window)!;
            var simulator = ButtonNamed(window, "Network Simulator · 规划中");
            var section = simulator.GetVisualAncestors().OfType<Border>().Single(border => border.Classes.Contains("nav-entries"));
            Click(window, ButtonNamed(window, "网络实验"));
            await WaitFor(() => section.Bounds.Height == 0);
            SaveFrame(window, "app-folded");

            Click(window, ButtonNamed(window, "收起工具导航"));
            await WaitFor(() => rail.Bounds.Width == 63 && section.Bounds.Height > 0);
            var disabled = new[] { "实时抓包", "Network Simulator", "Network Benchmark" }
                .All(tool => ButtonNamed(window, tool + " · 规划中") is { IsEffectivelyEnabled: false });
            SaveFrame(window, "app-compact");

            Click(window, ButtonNamed(window, "展开工具导航"));
            await WaitFor(() => rail.Bounds.Width == 254 && section.Bounds.Height == 0);
            Click(window, ButtonNamed(window, "网络实验"));
            await WaitFor(() => section.Bounds.Height > 0);

            return (Disabled: disabled, Selection: Text(window, "记录 #005"));
        });

        await Assert.That(result.Disabled).IsTrue();
        await Assert.That(result.Selection).IsTrue();
    }

    [Test]
    public async Task Narrow_navigation_drawer_dismisses_on_escape_backdrop_and_tool_selection()
    {
        var result = await WithExplorer(async window =>
        {
            window.Width = 620;
            await SelectFixtureFragment(window);
            var rail = Find<ToolNavigationView>(window)!;
            await WaitFor(() => !rail.IsHitTestVisible);
            var toggle = ButtonNamed(window, "打开工具导航");

            async Task OpenDrawer()
            {
                Click(window, toggle);
                await WaitFor(() => rail.IsHitTestVisible && rail.RenderTransform?.Value.M31 == 0);
            }

            await OpenDrawer();
            window.MouseMove(new Point(500, 15));
            SaveFrame(window, "app-drawer");
            window.KeyPress(Key.Escape, RawInputModifiers.None, PhysicalKey.Escape, null);
            await WaitFor(() => !rail.IsHitTestVisible && toggle.IsFocused);
            await OpenDrawer();

            Click(window, window, new Point(550, 100));
            await WaitFor(() => !rail.IsHitTestVisible);
            await OpenDrawer();

            Click(window, rail.GetVisualDescendants().OfType<Button>()
                .Single(button => AutomationProperties.GetName(button) == "Packet Explorer"));
            await WaitFor(() => !rail.IsHitTestVisible && toggle.IsFocused);
            return Text(window, "记录 #005");
        });

        await Assert.That(result).IsTrue();
    }

    [Test]
    public async Task Caption_buttons_maximize_restore_minimize_and_close_the_window()
    {
        var result = await WithExplorer(window =>
        {
            Click(window, ButtonNamed(window, "最大化"));
            var maximized = window.WindowState;
            Click(window, ButtonNamed(window, "向下还原"));
            var restored = window.WindowState;
            Click(window, ButtonNamed(window, "最小化"));
            var minimized = window.WindowState;
            window.WindowState = WindowState.Normal;
            Dispatcher.UIThread.RunJobs();
            Click(window, ButtonNamed(window, "关闭窗口"));

            return Task.FromResult((Maximized: maximized, Restored: restored, Minimized: minimized, Visible: window.IsVisible));
        }, file: null);

        await Assert.That(result.Maximized).IsEqualTo(WindowState.Maximized);
        await Assert.That(result.Restored).IsEqualTo(WindowState.Normal);
        await Assert.That(result.Minimized).IsEqualTo(WindowState.Minimized);
        await Assert.That(result.Visible).IsFalse();
    }

    [Test]
    public async Task Starting_without_a_file_shows_the_open_prompt_and_loads_the_file_chosen_there()
    {
        var result = await WithExplorer(async window =>
        {
            var prompt = Text(window, "打开抓包文件");
            var hint = Text(window, "选择本地 PCAP 或 PCAPNG 文件以查看捕获记录。");
            var workbench = Text(window, "记录工作台");
            SaveFrame(window, "app-landing");
            Click(window, ButtonNamed(window, "选择文件"));
            await WaitFor(() => Text(window, "记录 #001"));

            return (Prompt: prompt, Hint: hint, InitialWorkbench: workbench,
                Records: Find<ListBox>(window)!.ItemCount, PromptAfterOpen: Text(window, "打开抓包文件"));
        }, file: null, chooseFile: _ => Task.FromResult<string?>(Fixture("record-workbench.pcapng")));

        await Assert.That(result.Prompt).IsTrue();
        await Assert.That(result.Hint).IsTrue();
        await Assert.That(result.InitialWorkbench).IsFalse();
        await Assert.That(result.Records).IsEqualTo(16);
        await Assert.That(result.PromptAfterOpen).IsFalse();
    }

    [Test]
    public async Task English_ui_culture_localizes_the_picker_workbench_and_capture_metadata()
    {
        FilePickerOpenOptions? picker = null;
        var result = await WithExplorer(async window =>
        {
            var prompt = Text(window, "Open a capture file");
            var navigation = Text(window, "Traffic analysis");
            SaveFrame(window, "app-en-landing");
            Click(window, ButtonNamed(window, "Choose file"));
            await WaitFor(() => Text(window, "RECORD #001") && Text(window, "ARP / Target IP"));
            var workbench = Text(window, "Record workbench");
            var fields = Text(window, "Protocol fields");
            SaveFrame(window, "app-en-workbench");

            Click(window, ButtonNamed(window, "Capture metadata"));
            await WaitFor(() => Text(window, "16 records · 2 sections · 3 interfaces"));
            var metadata = Text(window, "Byte order") && Text(window, "Big-endian");
            SaveFrame(window, "app-en-metadata");

            return (Prompt: prompt, Navigation: navigation, Workbench: workbench, Fields: fields, Metadata: metadata);
        }, file: null, chooseFile: options =>
        {
            picker = options;
            return Task.FromResult<string?>(Fixture("record-workbench.pcapng"));
        }, culture: "en-US");

        await Assert.That(result.Prompt).IsTrue();
        await Assert.That(result.Navigation).IsTrue();
        await Assert.That(result.Workbench).IsTrue();
        await Assert.That(result.Fields).IsTrue();
        await Assert.That(result.Metadata).IsTrue();
        await Assert.That(picker!.Title).IsEqualTo("Open a capture file");
        await Assert.That(picker.FileTypeFilter!.Select(type => type.Name)).IsEquivalentTo(["Capture files", "All files"]);
    }

    [Test]
    [Arguments("zh-CN", "块被截断，应为 28 字节。")]
    [Arguments("en-US", "Truncated block; expected 28 bytes.")]
    public async Task Truncated_pcapng_reports_the_specific_error_in_the_ui_culture(string culture, string expected)
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
            var error = await WithExplorer(async window =>
            {
                var name = Path.GetFileName(file);
                await WaitFor(() => TextStartsWith(window, name));

                return ReadText(window).Single(text => text.StartsWith(name, StringComparison.Ordinal));
            }, file, culture: culture);

            await Assert.That(error).Contains(expected);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Test]
    public async Task Control_O_opens_the_file_selected_by_the_picker()
    {
        var result = await WithExplorer(async window =>
        {
            window.KeyPress(Key.O, RawInputModifiers.Control, PhysicalKey.O, null);
            await WaitFor(() => Text(window, "记录 #001"));

            return Find<ListBox>(window)!.ItemCount;
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
                await WaitFor(() => Text(window, "没有可预览的记录"));

                return (Hint: Text(window, $"{Path.GetFileName(file)} 中没有捕获记录。"),
                    Workbench: Text(window, "记录工作台"), CanChoose: FindButton(window, "选择其他文件")?.IsEnabled == true);
            }, file);

            await Assert.That(result.Hint).IsTrue();
            await Assert.That(result.Workbench).IsFalse();
            await Assert.That(result.CanChoose).IsTrue();
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Test]
    public async Task Selecting_reassembled_bytes_preserves_the_capture_record_and_reveals_the_field()
    {
        var result = await WithExplorer(async window =>
        {
            await SelectFixtureFragment(window);
            await WaitFor(() => Text(window, "IPv4 / 标识符"));
            SaveFrame(window, "app-main");
            Click(window, ButtonNamed(window, "并排查看完整字节 ▾"));
            await WaitFor(() => FindButton(window, "重组 IP") is not null);
            SaveFrame(window, "app-expanded");

            Click(window, ButtonNamed(window, "重组 IP"));
            await WaitFor(() => Text(window, "UDP / 目的端口"));
            return (Record: Text(window, "记录 #005"), Source: Text(window, "重组 IP 数据报字节"),
                Range: Text(window, "0x0016–0017 · 2 B"), Value: Text(window, "53"));
        });

        await Assert.That(result.Record).IsTrue();
        await Assert.That(result.Source).IsTrue();
        await Assert.That(result.Range).IsTrue();
        await Assert.That(result.Value).IsTrue();
    }

    [Test]
    [Arguments(1325d, 885d, false)]
    [Arguments(1752d, 941d, true)]
    public async Task Protocol_field_panel_resizes_to_the_active_layer(double width, double height, bool sideBySide)
    {
        var result = await WithExplorer(async window =>
        {
            window.Width = width;
            window.Height = height;
            await WaitFor(() => Text(window, "ARP / 目标 IP"));
            var fields = ProtocolFields(window);
            var lastRow = fields.Children[^1];
            await WaitFor(() => lastRow.Bounds.Height > 0);
            var arpHeight = fields.Bounds.Height;
            var arpRows = fields.Children.Count;
            var fits = lastRow.Bounds.Bottom <= arpHeight;
            var scrollAreas = fields.GetVisualAncestors().OfType<ScrollViewer>().Count();
            var fieldCard = fields.GetVisualAncestors().OfType<Border>().First();
            var byteCard = ((Grid)fieldCard.Parent!).Children.OfType<Border>().Single(card => card != fieldCard);
            var aligned = fieldCard.Bounds.Top == byteCard.Bounds.Top && fieldCard.Bounds.Bottom == byteCard.Bounds.Bottom;
            var stacked = byteCard.Bounds.Top >= fieldCard.Bounds.Bottom;
            SaveFrame(window, sideBySide ? "app-wide" : "app-stacked");

            Click(window, ButtonNamed(window, "Ethernet"));
            await WaitFor(() => fields.Bounds.Height < arpHeight && Text(window, "Ethernet / 目的 MAC"));

            return (ArpRows: arpRows, EthernetRows: fields.Children.Count, AllFit: fits,
                ScrollAreas: scrollAreas, Aligned: aligned, ValidLayout: aligned || stacked);
        });

        await Assert.That(result.ArpRows).IsEqualTo(9);
        await Assert.That(result.EthernetRows).IsEqualTo(3);
        await Assert.That(result.AllFit).IsTrue();
        await Assert.That(result.ScrollAreas).IsEqualTo(1);
        await Assert.That(result.Aligned).IsEqualTo(sideBySide);
        await Assert.That(result.ValidLayout).IsTrue();
    }

    [Test]
    public async Task Arrow_keys_scroll_the_focused_record_details()
    {
        var offset = await WithExplorer(async window =>
        {
            await SelectFixtureFragment(window);
            await WaitFor(() => Text(window, "IPv4 / 标识符"));
            var details = ProtocolFields(window).GetVisualAncestors().OfType<ScrollViewer>().Single();
            await WaitFor(() => details.Extent.Height > details.Viewport.Height && details.Viewport.Height > 0);
            details.Focus(NavigationMethod.Tab);
            var initialOffset = details.Offset.Y;

            window.KeyPress(Key.Down, RawInputModifiers.None, PhysicalKey.ArrowDown, null);
            await WaitFor(() => details.Offset.Y > initialOffset);

            return details.Offset.Y - initialOffset;
        });

        await Assert.That(offset).IsGreaterThan(0);
    }

    [Test]
    public async Task Mouse_wheel_over_protocol_fields_scrolls_the_record_details()
    {
        var offset = await WithExplorer(async window =>
        {
            window.Height = 630;
            await WaitFor(() => Text(window, "ARP / 目标 IP"));
            var fields = ProtocolFields(window);
            var details = fields.GetVisualAncestors().OfType<ScrollViewer>().Single();
            await WaitFor(() => details.Extent.Height > details.Viewport.Height && fields.Bounds.Height > 0);
            var initialOffset = details.Offset.Y;

            window.MouseWheel(Center(fields, window), new Vector(0, -1));
            await WaitFor(() => details.Offset.Y > initialOffset);

            return details.Offset.Y - initialOffset;
        });

        await Assert.That(offset).IsGreaterThan(0);
    }

    [Test]
    public async Task Clicking_a_coverage_byte_reports_its_frame_and_reassembled_offsets()
    {
        var result = await WithExplorer(async window =>
        {
            await SelectFixtureFragment(window);
            var map = Find<CoverageMatrix>(window)!;

            Click(window, map, new Point(148, 67));
            await WaitFor(() => TextStartsWith(window, "载荷 +0 B"));
            return ReadText(window).Single(text => text.StartsWith("载荷 +0 B", StringComparison.Ordinal));
        });

        await Assert.That(result).IsEqualTo("载荷 +0 B  ｜  #005 帧 0x0022 ↔ 重组 IP 0x0014  ｜  04");
    }

    [Test]
    public async Task Search_and_fragment_filter_keep_only_matching_capture_records()
    {
        var result = await WithExplorer(async window =>
        {
            await WaitFor(() => Text(window, "记录 #001"));
            Click(window, ButtonNamed(window, "分片"));
            var search = Find<TextBox>(window)!;
            Click(window, search);
            window.KeyTextInput("#012");
            await WaitFor(() => Text(window, "记录 #012") && Text(window, "1 / 16"));
            var count = Find<ListBox>(window)!.ItemCount;

            window.KeyTextInput("missing");
            await WaitFor(() => Text(window, "没有匹配的记录。"));
            Click(window, FindButtonWithContent(window, "清除筛选"));
            await WaitFor(() => Text(window, "16 / 16"));
            return (Count: count, Restored: Find<ListBox>(window)!.ItemCount);
        });

        await Assert.That(result.Count).IsEqualTo(1);
        await Assert.That(result.Restored).IsEqualTo(16);
    }

    [Test]
    public async Task Overlapping_ipv6_fragments_display_the_conflict_without_a_derived_datagram()
    {
        var result = await WithExplorer(async window =>
        {
            await WaitFor(() => FindRow(window, "#012") is not null);
            Click(window, FindRow(window, "#012")!);
            await WaitFor(() => Text(window, "重组已丢弃") && Text(window, "记录 #012"));
            SaveFrame(window, "app-overlap");
            var message = ReadText(window).Single(text => text.StartsWith("载荷 8–15 B", StringComparison.Ordinal));

            return (Message: message, Derived: Text(window, "重组 IP 数据报字节"));
        });

        await Assert.That(result.Message).Contains("IPv6 重叠分片触发整组丢弃");
        await Assert.That(result.Derived).IsFalse();
    }

    [Test]
    public async Task Opening_capture_metadata_shows_both_sections_and_missing_record_time()
    {
        var result = await WithExplorer(async window =>
        {
            await SelectFixtureFragment(window);
            await WaitFor(() => Text(window, "IPv4 / 标识符"));
            Click(window, ButtonNamed(window, "捕获元数据"));
            SaveFrame(window, "app-metadata");
            window.KeyPress(Key.Escape, RawInputModifiers.None, PhysicalKey.Escape, null);
            await WaitFor(() => FindButton(window, "关闭") is null);
            Click(window, FindRow(window, "#013")!);
            await WaitFor(() => Text(window, "记录 #013"));
            Click(window, ButtonNamed(window, "捕获元数据"));

            return (Sections: Text(window, "16 条记录 · 2 个 Section · 3 个接口"),
                BigEndian: Text(window, "大端"), Context: Text(window, "Simple Packet Block · S1 / I0 · 未提供"));
        });

        await Assert.That(result.Sections).IsTrue();
        await Assert.That(result.BigEndian).IsTrue();
        await Assert.That(result.Context).IsTrue();
    }

    [Test]
    public async Task Opening_a_truncated_capture_keeps_the_readable_record_available()
    {
        var result = await WithExplorer(async window =>
        {
            await WaitFor(() => Text(window, "记录 #001"));
            Click(window, ButtonNamed(window, "选择其他抓包文件"));
            await WaitFor(() => Text(window, "× 文件读取错误") && Text(window, "原始记录 #001字节"));

            return (Count: Find<ListBox>(window)!.ItemCount, Raw: Text(window, "3 B · 帧起点"));
        }, Fixture("record-workbench.pcapng"), _ => Task.FromResult<string?>(Fixture("record-truncated.pcap")));

        await Assert.That(result.Count).IsEqualTo(1);
        await Assert.That(result.Raw).IsTrue();
    }

    [Test]
    public async Task Replacing_a_capture_with_an_unreadable_file_keeps_the_loaded_records()
    {
        var file = Path.GetTempFileName();
        try
        {
            var result = await WithExplorer(async window =>
            {
                await WaitFor(() => Text(window, "记录 #001"));
                Click(window, ButtonNamed(window, "选择其他抓包文件"));
                await WaitFor(() => TextStartsWith(window, Path.GetFileName(file) + "："));

                return (Workbench: Text(window, "记录工作台"), VisibleRecords: Find<ListBox>(window)!.ItemCount);
            }, Fixture("record-workbench.pcapng"), _ => Task.FromResult<string?>(file));

            await Assert.That(result.Workbench).IsTrue();
            await Assert.That(result.VisibleRecords).IsEqualTo(16);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Test]
    public async Task Splitter_drag_resizes_the_record_list_and_enter_restores_its_width()
    {
        var result = await WithExplorer(async window =>
        {
            await WaitFor(() => Text(window, "记录 #001"));
            var list = Find<ListBox>(window)!;
            var grip = window.GetVisualDescendants().OfType<Control>()
                .Single(control => AutomationProperties.GetName(control) == "调整捕获记录列表宽度");
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
                var records = Find<ListBox>(window)!;
                await WaitFor(() => records.ItemCount > 0, seconds: 45);
                var first = clock.ElapsedMilliseconds;
                await WaitFor(() => records.ItemCount == count && !Text(window, "正在索引捕获记录…"), seconds: 45);
                var indexed = clock.ElapsedMilliseconds;
                var visible = window.GetVisualDescendants().OfType<RecordRow>().Count();
                Click(window, Find<TextBox>(window)!);
                window.KeyTextInput($"#{count}");
                await WaitFor(() => Text(window, $"记录 #{count}") && Text(window, "1024 B · 帧起点"), seconds: 45);
                Console.WriteLine($"Capture {count:N0} records · first displayed {first:N0} ms · indexed {indexed:N0} ms · final lookup {clock.ElapsedMilliseconds - indexed:N0} ms · {visible} realized rows");

                return (Visible: visible, Selected: records.SelectedItem, Filtered: records.ItemCount);
            }, file);

            await Assert.That(result.Visible).IsLessThan(100);
            await Assert.That((int)result.Selected!).IsEqualTo(count - 1);
            await Assert.That(result.Filtered).IsEqualTo(1);
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

    private static void WriteRepeatedCapture(string file, int count)
    {
        using var output = File.Create(file);
        output.Write(Convert.FromHexString("D4C3B2A1020004000000000000000000FFFF000001000000"));
        const int size = 16 + 1024;
        var record = new byte[size];
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(8), 1024);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(12), 1024);
        var arp = Convert.FromHexString("FFFFFFFFFFFF0200000000010806000108000604000102000000000100000000000000000000C0000202");
        arp.CopyTo(record, 16);
        const int blockCount = 512;
        var block = new byte[blockCount * size];
        for (var i = 0; i < blockCount; i++)
            record.CopyTo(block, i * size);

        for (var done = 0; done < count; done += blockCount)
            output.Write(block.AsSpan(0, Math.Min(count - done, blockCount) * size));
    }

    private static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    private static async Task SelectFixtureFragment(ExplorerWindow window)
    {
        await WaitFor(() => FindRow(window, "#005") is not null);
        Click(window, FindRow(window, "#005")!);
        await WaitFor(() => Find<CoverageMatrix>(window) is not null && Text(window, "记录 #005"));
    }

    private static Task<T> WithExplorer<T>(Func<ExplorerWindow, Task<T>> interact) =>
        WithExplorer(interact, Fixture("record-workbench.pcapng"));

    private static Task<T> WithExplorer<T>(Func<ExplorerWindow, Task<T>> interact, string? file,
        Func<FilePickerOpenOptions, Task<string?>>? chooseFile = null, string culture = "zh-CN") => Session.Dispatch<T>(async () =>
    {
        var previousCulture = CultureInfo.CurrentUICulture;
        CultureInfo.CurrentUICulture = CultureInfo.GetCultureInfo(culture);
        var window = new ExplorerWindow(file, chooseFile: chooseFile);
        window.Show();
        try
        {
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
            CultureInfo.CurrentUICulture = previousCulture;
        }
    }, CancellationToken.None);

    private static async Task WaitFor(Func<bool> ready, int seconds = 8)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(seconds));
        while (!ready())
        {
            await Task.Delay(16, timeout.Token);
            Dispatcher.UIThread.RunJobs();
        }
    }

    private static IEnumerable<string> ReadText(Window window) => window.GetVisualDescendants().OfType<TextBlock>()
        .Where(block => block.IsEffectivelyVisible).Select(block => block.Text ?? "");

    private static bool Text(Window window, string value) => ReadText(window).Contains(value);
    private static bool TextStartsWith(Window window, string prefix) =>
        ReadText(window).Any(text => text.StartsWith(prefix, StringComparison.Ordinal));

    private static T? Find<T>(Window window) where T : Visual => window.GetVisualDescendants().OfType<T>().FirstOrDefault();
    private static StackPanel ProtocolFields(Window window) => window.GetVisualDescendants().OfType<StackPanel>()
        .Single(scroll => AutomationProperties.GetName(scroll) == "当前协议字段");
    private static Button? FindButton(Window window, string name) => window.GetVisualDescendants().OfType<Button>()
        .FirstOrDefault(button => button.IsEffectivelyVisible && AutomationProperties.GetName(button) == name);
    private static Button ButtonNamed(Window window, string name) => FindButton(window, name)!;
    private static Button FindButtonWithContent(Window window, string text) => window.GetVisualDescendants().OfType<Button>()
        .Single(button => button.IsEffectivelyVisible && button.Content is TextBlock content && content.Text == text);

    private static RecordRow? FindRow(Window window, string id) => window.GetVisualDescendants().OfType<RecordRow>()
        .FirstOrDefault(row => AutomationProperties.GetName(row)?.StartsWith(id + " ·", StringComparison.Ordinal) == true);

    private static Point Center(Control control, Window window) =>
        control.TranslatePoint(new Point(control.Bounds.Width / 2, control.Bounds.Height / 2), window)!.Value;

    private static void Click(Window window, Control control, Point? local = null)
    {
        var point = local.HasValue ? control.TranslatePoint(local.Value, window)!.Value : Center(control, window);
        window.MouseMove(point);
        window.MouseDown(point, MouseButton.Left);
        window.MouseUp(point, MouseButton.Left);
        Dispatcher.UIThread.RunJobs();
    }

    private static void SaveFrame(Window window, string name)
    {
        var path = Environment.GetEnvironmentVariable("PACKETLAB_SCREENSHOTS");
        if (string.IsNullOrWhiteSpace(path))
            return;

        using var frame = window.CaptureRenderedFrame();
        frame?.Save(Path.Combine(path, name + ".png"), PngBitmapEncoderOptions.Default);
    }
}
