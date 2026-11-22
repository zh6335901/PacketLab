using Avalonia;
using Avalonia.Controls.ApplicationLifetimes;
using Avalonia.Markup.Xaml;

namespace PacketLab.Desktop;

internal sealed partial class App : Application
{
    public override void Initialize() => AvaloniaXamlLoader.Load(this);

    public override void OnFrameworkInitializationCompleted()
    {
        if (ApplicationLifetime is IClassicDesktopStyleApplicationLifetime desktop)
        {
            var local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            var preferences = Path.Combine(local, "PacketLab", "explorer-list-width.txt");
            desktop.MainWindow = new ExplorerWindow(desktop.Args?.FirstOrDefault(), preferences);
        }

        base.OnFrameworkInitializationCompleted();
    }
}
