using System.Runtime.InteropServices;
using Avalonia;
using Avalonia.Animation;
using Avalonia.Animation.Easings;
using Avalonia.Controls;
using Avalonia.Data.Converters;
using Avalonia.Media;
using Avalonia.Media.Transformation;
using PacketLab.Desktop.ViewModels;

namespace PacketLab.Desktop.Views;

internal sealed partial class ToolNavigationView : UserControl
{
    public static readonly FuncValueConverter<string, Geometry?> IconGeometry = new(path => path is null ? null : Geometry.Parse(path));
    private readonly DoubleTransition widthTransition = new() { Property = WidthProperty, Easing = NavigationMotion.EasyEase };
    private readonly TransformOperationsTransition drawerTransition = new() { Property = RenderTransformProperty };
    private readonly Transitions widthTransitions;
    private readonly Transitions drawerTransitions;
    private bool wasNarrow;
    private bool initialized;
    private double drawerOffset;

    public ToolNavigationView()
    {
        InitializeComponent();
        widthTransitions = [widthTransition];
        drawerTransitions = [drawerTransition];
    }

    internal void UpdateLayout(double windowWidth, ToolNavigationViewModel navigation, bool animate)
    {
        var narrow = navigation.IsNarrow;
        var compact = navigation.IsCompactDesktop;
        var modeChanged = !initialized || wasNarrow != narrow;
        initialized = true;
        wasNarrow = narrow;
        Classes.Set("motion", animate);
        Classes.Set("mid-width", windowWidth <= 900);
        widthTransition.Duration = TimeSpan.FromMilliseconds(compact ? 200 : 250);
        drawerTransition.Duration = TimeSpan.FromMilliseconds(navigation.DrawerOpen ? 250 : 200);
        drawerTransition.Easing = navigation.DrawerOpen ? NavigationMotion.Decelerate : NavigationMotion.Accelerate;
        if (modeChanged)
            Transitions = null;
        Width = RailWidth(windowWidth, narrow, compact);
        var drawerHidden = narrow && !navigation.DrawerOpen;
        IsHitTestVisible = !drawerHidden;
        IsEnabled = !drawerHidden;
        var offset = drawerHidden ? -Width * 1.04 : 0;
        if (modeChanged || offset != drawerOffset)
        {
            drawerOffset = offset;
            var translate = TransformOperations.CreateBuilder(1);
            translate.AppendTranslate(offset, 0);
            RenderTransform = translate.Build();
        }
        if (modeChanged && animate)
            Transitions = narrow ? drawerTransitions : widthTransitions;
    }

    private static double RailWidth(double width, bool narrow, bool compact)
    {
        if (narrow)
            return Math.Min(272, width * .85);
        if (compact)
            return 63;

        return width <= 900 ? 210 : 254;
    }
}

internal static class NavigationMotion
{
    private const uint GetClientAreaAnimation = 0x1042;
    public static readonly SplineEasing EasyEase = new() { X1 = .33, X2 = .67, Y2 = 1 };
    internal static readonly SplineEasing Decelerate = new() { Y2 = 1 };
    internal static readonly SplineEasing Accelerate = new() { X1 = 1, X2 = 1, Y2 = 1 };

    internal static bool Enabled => !OperatingSystem.IsWindows() ||
        SystemParametersInfo(GetClientAreaAnimation, 0, out var enabled, 0) == 0 || enabled != 0;

    [DllImport("user32.dll", EntryPoint = "SystemParametersInfoW", ExactSpelling = true)]
    private static extern int SystemParametersInfo(uint action, uint parameter, out int value, uint flags);
}
