using Avalonia;
using Avalonia.Controls;
using Path = Avalonia.Controls.Shapes.Path;
using Avalonia.Layout;
using Avalonia.Media;

namespace PacketLab.Desktop;

internal static class ViewStyle
{
    internal static readonly IBrush Bg = Brush("#1C1D1F");
    internal static readonly IBrush Top = Brush("#202327");
    internal static readonly IBrush PanelBrush = Brush("#292A2D");
    internal static readonly IBrush Lift = Brush("#333539");
    internal static readonly IBrush Line = Brush("#46484C");
    internal static readonly IBrush CardBorder = Brush("#414348");
    internal static readonly IBrush Text = Brush("#F5F5F5");
    internal static readonly IBrush Muted = Brush("#D0D2D6");
    internal static readonly IBrush Soft = Brush("#AFB3BA");
    internal static readonly IBrush Accent = Brush("#76B9ED");
    internal static readonly IBrush Selected = Brush("#2B3946");
    internal static readonly IBrush Warn = Brush("#F4CD89");
    internal static readonly IBrush WarnBackground = Brush("#413727");
    internal static readonly IBrush Bad = Brush("#FFB8B8");
    internal static readonly IBrush BadBackground = Brush("#472E35");
    internal static readonly IBrush Blue = Brush("#A3D4F8");
    internal static readonly IBrush BlueBackground = Brush("#2A3C4D");
    internal static readonly IBrush Neutral = Brush("#D1CFDB");
    internal static readonly IBrush NeutralBackground = Brush("#36353D");
    internal static readonly IBrush Good = Brush("#AADCAE");
    internal static readonly IBrush GoodBackground = Brush("#2C3D30");
    internal static readonly IBrush PeerBackground = Brush("#2D3137");
    internal static readonly IBrush Arp = Brush("#E9C797");
    internal static readonly IBrush Udp = Brush("#A5D9C2");
    internal static readonly IBrush IPv6 = Brush("#CEBEE9");
    internal static readonly FontFamily Body = new("Segoe UI Variable Text, Segoe UI, Microsoft YaHei UI");
    internal static readonly FontFamily Display = new("Segoe UI Variable Display, Segoe UI, Microsoft YaHei UI");
    internal static readonly FontFamily Mono = new("Cascadia Mono, Consolas, monospace");
    internal static readonly FontWeight Demi = FontWeight.SemiBold;

    internal static SolidColorBrush Brush(string hex) => new(Color.Parse(hex));

    internal static TextBlock Label(string text, double size = 12, IBrush? brush = null, bool mono = false, FontWeight weight = FontWeight.Normal) =>
        new()
        {
            Text = text, FontFamily = mono ? Mono : Body, FontSize = size, Foreground = brush ?? Text,
            FontWeight = weight, VerticalAlignment = VerticalAlignment.Center, TextTrimming = TextTrimming.CharacterEllipsis
        };

    internal static Border Card(Control child) => new()
    {
        Child = child, Background = PanelBrush, BorderBrush = CardBorder, BorderThickness = new Thickness(1),
        CornerRadius = new CornerRadius(8), ClipToBounds = true
    };

    internal static Border LineBelow(Control child, Thickness padding) => new()
    {
        Child = child, Padding = padding, BorderBrush = Line, BorderThickness = new Thickness(0, 0, 0, 1)
    };

    internal static Grid LayoutGrid(string columns, params Control[] children)
    {
        var grid = new Grid { ColumnDefinitions = new ColumnDefinitions(columns) };
        for (var col = 0; col < children.Length; col++)
        {
            Avalonia.Controls.Grid.SetColumn(children[col], col);
            grid.Children.Add(children[col]);
        }

        return grid;
    }

    internal static StackPanel Horizontal(double gap, params Control[] children)
    {
        var stack = new StackPanel { Orientation = Orientation.Horizontal, Spacing = gap, VerticalAlignment = VerticalAlignment.Center };
        foreach (var child in children)
            stack.Children.Add(child);

        return stack;
    }

    internal static StackPanel Vertical(double gap, params Control[] children)
    {
        var stack = new StackPanel { Spacing = gap };
        foreach (var child in children)
            stack.Children.Add(child);

        return stack;
    }

    internal static Button Button(Control content, Action clicked, string? tooltip = null)
    {
        var button = new Button { Content = content, Classes = { "explorer" } };
        if (tooltip is not null)
        {
            ToolTip.SetTip(button, tooltip);
            Avalonia.Automation.AutomationProperties.SetName(button, tooltip);
        }
        button.Click += (_, _) => clicked();

        return button;
    }

    internal static Button Button(string label, Action clicked) => Button(Label(label), clicked, label);

    internal static Path Icon(string path, double size = 16, IBrush? stroke = null) => new()
    {
        Data = Geometry.Parse(path), Width = size, Height = size, Stretch = Stretch.Uniform,
        Stroke = stroke ?? Accent, StrokeThickness = 1.4, StrokeLineCap = PenLineCap.Round,
        StrokeJoin = PenLineJoin.Round, VerticalAlignment = VerticalAlignment.Center
    };

    internal static IBrush ProtocolBrush(Protocol protocol) => protocol switch
    {
        Protocol.Arp => Arp, Protocol.Udp => Udp, Protocol.IPv6 => IPv6, _ => Blue
    };

    internal static Border Badge(string caption, IBrush foreground, IBrush background, double size = 11) => new()
    {
        Background = background, CornerRadius = new CornerRadius(4), Padding = new Thickness(5, 0),
        Child = Label(caption, size, foreground, weight: Demi), VerticalAlignment = VerticalAlignment.Center,
        MinHeight = size == 10 ? 15 : 20
    };
}
