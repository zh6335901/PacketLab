using Avalonia;
using Avalonia.Automation;
using Avalonia.Controls;
using Avalonia.Layout;
using Avalonia.Media;
using static PacketLab.Desktop.ViewStyle;

namespace PacketLab.Desktop;

internal sealed partial class ExplorerWindow
{
    private readonly Border landing;
    private readonly TextBlock landingTitle = LandingText(24, 32, Text, Demi);
    private readonly TextBlock landingHint = LandingText(14, 22, Muted);
    private readonly TextBlock landingError = LandingText(14, 22, Bad);
    private readonly TextBlock landingAction = LandingText(14, 18, Brush("#102333"), Demi);
    private readonly Button landingButton = new() { Classes = { "choose-capture" } };

    private Border MakeLanding()
    {
        var icon = new OpenCaptureIcon { Width = 54, Height = 54, Margin = new Thickness(0, 0, 0, 18) };
        landingTitle.FontFamily = Display;
        landingHint.Margin = new Thickness(0, 7, 0, 0);
        landingError.Margin = new Thickness(0, 14, 0, 0);
        landingButton.HorizontalAlignment = HorizontalAlignment.Center;
        landingButton.Margin = new Thickness(0, 23, 0, 0);
        landingButton.Content = landingAction;
        landingButton.Click += (_, _) => _ = PickLocalFileAsync();
        var prompt = Vertical(0, icon, landingTitle, landingHint, landingButton, landingError);
        prompt.MaxWidth = 400;
        prompt.HorizontalAlignment = HorizontalAlignment.Center;
        prompt.VerticalAlignment = VerticalAlignment.Center;

        return new Border { Child = prompt, Padding = new Thickness(20, 28, 20, 100) };
    }

    private static TextBlock LandingText(double size, double lineHeight, IBrush foreground, FontWeight weight = FontWeight.Normal) => new()
    {
        FontFamily = Body, Foreground = foreground, FontSize = size, FontWeight = weight, LineHeight = lineHeight,
        TextWrapping = TextWrapping.Wrap, TextAlignment = TextAlignment.Center
    };

    private void UpdateLanding(string? error)
    {
        (landingTitle.Text, landingHint.Text, landingAction.Text) = (loading, capture) switch
        {
            (true, _) => ("正在读取抓包文件", "正在本地读取文件…", "正在读取…"),
            (false, { } opened) => ("没有可预览的记录", $"{Path.GetFileName(opened.Path)} 中没有捕获记录。", "选择其他文件"),
            _ => ("打开抓包文件", "选择本地 PCAP 或 PCAPNG 文件以查看捕获记录。", "选择文件")
        };
        AutomationProperties.SetName(landingButton, landingAction.Text);
        landingButton.IsEnabled = !loading;
        landingError.Text = error;
        landingError.IsVisible = error is not null;
    }

    private sealed class OpenCaptureIcon : Control
    {
        private static readonly Geometry Sheet = Geometry.Parse("M13 9H27L35 17V40H13Z M27 9V17H35");
        private static readonly Geometry Folder = Geometry.Parse("M7 25H21L25 29H45L41 45H7Z");
        private static readonly Geometry Mark = Geometry.Parse("M14 36H29");
        private static readonly IBrush SheetFill = Brush("#263947");
        private static readonly IBrush FolderFill = Brush("#314C61");
        private static readonly Pen SheetEdge = new(Brush("#80BDE9"), 1.6, lineJoin: PenLineJoin.Round);
        private static readonly Pen FolderEdge = new(Brush("#A2D4F7"), 1.6, lineJoin: PenLineJoin.Round);
        private static readonly Pen MarkEdge = new(Brush("#86BDE3"), 1.6, lineCap: PenLineCap.Round);

        public override void Render(DrawingContext context)
        {
            context.DrawGeometry(SheetFill, SheetEdge, Sheet);
            context.DrawGeometry(FolderFill, FolderEdge, Folder);
            context.DrawGeometry(null, MarkEdge, Mark);
        }
    }
}
