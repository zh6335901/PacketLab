using Avalonia;
using Avalonia.Controls;
using Avalonia.Headless;
using Avalonia.Input;
using Avalonia.Threading;
using Avalonia.VisualTree;
using PacketLab.Desktop.Views.Shell;
using static PacketLab.Desktop.E2ETests.ExplorerTestHost;

namespace PacketLab.Desktop.E2ETests.Shell;

public sealed class UseShellTests
{
    [Test]
    public async Task Compact_navigation_keeps_all_tool_icons_and_restores_folded_groups()
    {
        var result = await WithExplorer(async window =>
        {
            await SelectFixtureFragment(window);
            var rail = GetById<ToolNavigation>(window, "ToolNavigation");
            var simulator = GetById<Button>(window, "NetworkSimulatorTool");
            var section = simulator.GetVisualAncestors().OfType<Border>().Single(border => border.Classes.Contains("nav-entries"));
            Click(window, GetById<Button>(window, "NetworkExperimentsGroup"));
            await WaitFor(() => section.Bounds.Height == 0);
            SaveFrame(window, "app-folded");

            Click(window, GetById<Button>(window, "ToggleNavigationRail"));
            await WaitFor(() => rail.Bounds.Width == 63 && section.Bounds.Height > 0);
            var disabled = new[] { "LiveCaptureTool", "NetworkSimulatorTool", "NetworkBenchmarkTool" }
                .All(id => GetById<Button>(window, id) is { IsEffectivelyEnabled: false });
            SaveFrame(window, "app-compact");

            Click(window, GetById<Button>(window, "ToggleNavigationRail"));
            await WaitFor(() => rail.Bounds.Width == 254 && section.Bounds.Height == 0);
            Click(window, GetById<Button>(window, "NetworkExperimentsGroup"));
            await WaitFor(() => section.Bounds.Height > 0);

            return (Disabled: disabled, Selection: IsRecordSelected(window, 5));
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
            var rail = GetById<ToolNavigation>(window, "ToolNavigation");
            await WaitFor(() => !rail.IsHitTestVisible);
            var toggle = GetById<Button>(window, "NavigationDrawerToggle");

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

            Click(window, GetById<Button>(window, "PacketExplorerTool"));
            await WaitFor(() => !rail.IsHitTestVisible && toggle.IsFocused);
            return IsRecordSelected(window, 5);
        });

        await Assert.That(result).IsTrue();
    }

    [Test]
    public async Task Caption_buttons_maximize_restore_minimize_and_close_the_window()
    {
        var result = await WithExplorer(window =>
        {
            Click(window, GetById<Button>(window, "WindowToggleSize"));
            var maximized = window.WindowState;
            Click(window, GetById<Button>(window, "WindowToggleSize"));
            var restored = window.WindowState;
            Click(window, GetById<Button>(window, "WindowMinimize"));
            var minimized = window.WindowState;
            window.WindowState = WindowState.Normal;
            Dispatcher.UIThread.RunJobs();
            Click(window, GetById<Button>(window, "WindowClose"));

            return Task.FromResult((Maximized: maximized, Restored: restored, Minimized: minimized, Visible: window.IsVisible));
        }, file: null);

        await Assert.That(result.Maximized).IsEqualTo(WindowState.Maximized);
        await Assert.That(result.Restored).IsEqualTo(WindowState.Normal);
        await Assert.That(result.Minimized).IsEqualTo(WindowState.Minimized);
        await Assert.That(result.Visible).IsFalse();
    }
}
