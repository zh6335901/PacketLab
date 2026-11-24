using Avalonia;
using Avalonia.Headless;

[assembly: NotInParallel]

namespace PacketLab.Desktop.E2ETests;

public sealed class HeadlessApp
{
    public static AppBuilder BuildAvaloniaApp() => AppBuilder.Configure<App>().UseSkia()
        .UseHeadless(new AvaloniaHeadlessPlatformOptions { UseHeadlessDrawing = false });
}
