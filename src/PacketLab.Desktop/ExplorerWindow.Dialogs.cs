using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Primitives;
using Avalonia.Layout;
using Avalonia.Media;
using PacketLab.Pcap;
using static PacketLab.Desktop.ViewStyle;

namespace PacketLab.Desktop;

internal sealed partial class ExplorerWindow
{
    private void ShowMetadata()
    {
        if (capture is not { } current)
            return;

        var file = $"{Path.GetFileName(current.Path)} · {snapshot.Format}";
        var time = snapshot.TimedRecords == 0 ? "未提供" :
            $"{snapshot.FirstTime.Format(date: true)} – {snapshot.LastTime.Format(date: true)}（{snapshot.TimedRecords:N0} 条有时间）";
        var structure = snapshot.Header is not null ? "全局链路信息 · Section 不适用" :
            $"{snapshot.Sections.Count} 个 Section · {snapshot.Interfaces.Count} 个接口";
        var rows = Vertical(0, MetadataRow("文件与格式", file),
            MetadataRow("捕获时间", time),
            MetadataRow("捕获结构", $"{snapshot.Count:N0} 条记录 · {structure}"));
        var cards = new UniformGrid { Columns = 3, Margin = new Thickness(0, 13, 0, 11) };
        if (snapshot.Header is { } header)
        {
            var precision = header.TimestampPrecision == PcapTimestampPrecision.Microseconds ? "1 μs" : "1 ns";
            var fcs = header.FcsLengthBytes is { } length ? $"{length} B" : "未提供";
            var card = MetadataCard("全局", "不适用", "接口名未提供",
                Link(header.LinkType),
                Order(header.ByteOrder), precision, header.SnapLen, $"FCS {fcs}");
            cards.Children.Add(card);
        }
        foreach (var item in snapshot.Interfaces)
        {
            var resolution = Resolution(item.TimestampResolution);
            var scope = $"S{item.Section.Number} / I{item.Id}";
            var version = $"Section {item.Section.MajorVersion}.{item.Section.MinorVersion}";
            var card = MetadataCard(scope, item.Name ?? "未提供",
                item.Description ?? "描述未提供",
                Link(item.LinkType),
                Order(item.Section.ByteOrder), resolution, item.SnapLen, $"{version} · 时间偏移 {item.TimestampOffsetSeconds} s");
            cards.Children.Add(card);
        }
        if (cards.Children.Count > 0)
            rows.Children.Add(cards);
        foreach (var section in snapshot.Sections.Where(section => snapshot.Interfaces.All(item => item.Section.Number != section.Number)))
        {
            var text = $"PCAPNG {section.MajorVersion}.{section.MinorVersion} · {Order(section.ByteOrder)} · 未提供接口";
            rows.Children.Add(MetadataRow($"Section S{section.Number}", text));
        }
        if (selected >= 0)
        {
            var subheading = Label($"当前记录 {RecordStatus.Number(selected)}", 12, weight: Demi);
            subheading.Margin = new Thickness(0, 5);
            rows.Children.Add(subheading);
            rows.Children.Add(MetadataRow("捕获上下文", $"{anchor.Block} · {anchor.Context} · {anchor.Time.Format(date: true)}"));
            var comment = current.Comment(selected);
            rows.Children.Add(MetadataRow("记录注释", comment));
            rows.Children.Add(MetadataRow("报文字节来源", $"{Path.GetFileName(current.Path)} · 文件偏移 0x{anchor.DataOffset:X}"));
        }
        rows.Children.Add(new TextBlock { Text = current.Path, Foreground = Muted, FontSize = 12,
            TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 12, 0, 0) });

        ShowOverlay("捕获元数据", rows);
    }

    private static string Resolution(byte resolution) => resolution switch
    {
        6 => "1 μs", 9 => "1 ns", (byte)0 => "1 s",
        _ => $"{((resolution & 0x80) == 0 ? 10 : 2)}⁻^({resolution & 0x7f}) s"
    };

    private static string Link(ushort link) => link switch
    {
        1 => "Ethernet · 1", 101 => "Raw IP · 101", _ => $"类型 {link} · 未支持"
    };

    private static string Order(PcapByteOrder order) => order == PcapByteOrder.LittleEndian ? "小端" : "大端";

    private static Border MetadataRow(string name, string value)
    {
        var text = Label(value);
        text.TextWrapping = TextWrapping.Wrap;
        var key = Label(name, 12, Muted);

        return LineBelow(LayoutGrid("125,*", key, text), new Thickness(0, 7));
    }

    private static Control MetadataCard(string id, string name, string description, string link, string order,
        string resolution, uint snap, string extra)
    {
        var note = Label(extra, 10, Soft, mono: true);
        note.TextWrapping = TextWrapping.Wrap;
        var card = new Border
        {
            Background = Bg, BorderBrush = Line, BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(6),
            Padding = new Thickness(11), Margin = new Thickness(0, 0, 6, 6),
            Child = Vertical(4, Label(id, 10, Accent, mono: true, weight: Demi),
                Label(name, 20, mono: true, weight: Demi),
                Label(description, 11, Muted),
                    MetaValue("链路", link),
                        MetaValue("字节序", order),
                MetaValue("时间分辨率", resolution),
                    MetaValue("SnapLen", snap == 0 ? "无上限 · 0" : $"{snap} B"), note)
        };

        return card;
    }

    private static Control MetaValue(string key, string value) =>
        Vertical(0, Label(key, 11, Muted), Label(value, 12, mono: true));

    private void ShowOverlay(string title, Control content)
    {
        overlay.Children.Clear();
        var close = Button(Label("×", 18), CloseOverlay, "关闭");
        close.Classes.Add("outline");
        close.Width = 32;
        close.Height = 32;
        close.HorizontalContentAlignment = HorizontalAlignment.Center;
        var header = LayoutGrid("*,Auto", Label(title, 22, weight: Demi), close);
        var scroll = new ScrollViewer { Content = content, MaxHeight = Math.Max(245, Bounds.Height * .75 - 68) };
        var pane = new Border
        {
            Child = Vertical(12, LineBelow(header, new Thickness(0, 0, 0, 12)), scroll),
            Background = Brush("#303135"), BorderBrush = CardBorder, BorderThickness = new Thickness(1),
            CornerRadius = new CornerRadius(8), Padding = new Thickness(22, 17, 22, 20), MaxWidth = 740,
            Width = Math.Min(740, Bounds.Width - 36), Margin = new Thickness(0, Math.Clamp(Bounds.Height * .09, 30, 92), 0, 0),
            HorizontalAlignment = HorizontalAlignment.Center, VerticalAlignment = VerticalAlignment.Top
        };
        overlay.Children.Add(pane);
        overlay.IsVisible = true;
        close.Focus();
    }

    private void CloseOverlay()
    {
        if (!overlay.IsVisible)
            return;

        overlay.IsVisible = false;
        overlay.Children.Clear();
        fileButton.Focus();
    }
}
