using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.VisualTree;
using static PacketLab.Desktop.E2ETests.ExplorerTestHost;

namespace PacketLab.Desktop.E2ETests.PacketExplorer;

public sealed class InspectRecordTests
{
    [Test]
    [Arguments(1325d, 885d, false)]
    [Arguments(1752d, 941d, true)]
    public async Task Protocol_field_panel_resizes_to_the_active_layer(double width, double height, bool sideBySide)
    {
        var result = await WithExplorer(async window =>
        {
            window.Width = width;
            window.Height = height;
            await WaitFor(() => FindById<StackPanel>(window, "CurrentProtocolFields") is { Children.Count: > 0 });
            var fields = GetById<StackPanel>(window, "CurrentProtocolFields");
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

            Click(window, GetById<Button>(window, "ProtocolLayer-Ethernet"));
            await WaitFor(() => fields.Children.Count == 3 && fields.Bounds.Height < arpHeight);

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
            await WaitFor(() => FindById<StackPanel>(window, "CurrentProtocolFields") is { Children.Count: > 0 });
            var details = GetById<ScrollViewer>(window, "RecordDetails");
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
            await WaitFor(() => FindById<StackPanel>(window, "CurrentProtocolFields") is { Children.Count: > 0 });
            var fields = GetById<StackPanel>(window, "CurrentProtocolFields");
            var details = GetById<ScrollViewer>(window, "RecordDetails");
            await WaitFor(() => details.Extent.Height > details.Viewport.Height && fields.Bounds.Height > 0);
            var initialOffset = details.Offset.Y;

            window.MouseWheel(Center(fields, window), new Vector(0, -1));
            await WaitFor(() => details.Offset.Y > initialOffset);

            return details.Offset.Y - initialOffset;
        });

        await Assert.That(offset).IsGreaterThan(0);
    }

    [Test]
    public async Task Opening_capture_metadata_shows_interfaces_from_both_sections_and_the_selected_record()
    {
        var result = await WithExplorer(async window =>
        {
            await SelectFixtureFragment(window);
            await WaitFor(() => FindRecordBytes(window, 5) is not null);
            Click(window, GetById<Button>(window, "OpenCaptureMetadataButton"));
            SaveFrame(window, "app-metadata");
            window.KeyPress(Key.Escape, RawInputModifiers.None, PhysicalKey.Escape, null);
            await WaitFor(() => FindById<Button>(window, "CloseCaptureMetadataButton") is null);
            Click(window, FindRow(window, 13)!);
            await WaitFor(() => IsRecordSelected(window, 13));
            Click(window, GetById<Button>(window, "OpenCaptureMetadataButton"));
            await WaitFor(() => FindById<ItemsControl>(window, "CaptureRecordFacts") is { ItemCount: > 0 });

            var interfaces = GetById<ItemsControl>(window, "CaptureInterfaces");
            var recordFacts = GetById<ItemsControl>(window, "CaptureRecordFacts");
            var context = ReadText(recordFacts).Single(text => text.Contains("Simple Packet Block", StringComparison.Ordinal));

            return (Interfaces: interfaces.ItemCount, InterfaceDetails: ReadText(interfaces).ToArray(), Context: context);
        });

        await Assert.That(result.Interfaces).IsEqualTo(3);
        await Assert.That(result.InterfaceDetails).Contains("S0 / I0");
        await Assert.That(result.InterfaceDetails).Contains("S1 / I0");
        await Assert.That(result.Context).Contains("S1 / I0");
    }
}
