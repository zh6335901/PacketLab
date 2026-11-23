using Avalonia.Controls;
using Avalonia.Media;
using static PacketLab.Desktop.ViewStyle;

namespace PacketLab.Desktop;

internal sealed class OpenCaptureIcon : Control
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
