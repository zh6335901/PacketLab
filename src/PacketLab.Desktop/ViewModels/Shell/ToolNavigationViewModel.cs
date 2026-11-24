using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using PacketLab.Desktop.Localization;

namespace PacketLab.Desktop.ViewModels.Shell;

internal sealed class ToolNavigationViewModel : ObservableObject
{
    private bool compact;
    private bool narrow;
    private bool drawerOpen;

    internal ToolNavigationViewModel()
    {
        CloseDrawerCommand = new RelayCommand(() => DrawerOpen = false, () => DrawerOpen);
        var activateExplorer = new RelayCommand(() => DrawerOpen = false);
        var planned = new RelayCommand(static () => { }, static () => false);
        var explorer = new ToolEntry("PacketExplorerTool", "Packet Explorer", "M5 3H14L19 8V21H5Z M14 3V9H19 M8 13H16 M8 16H14", true, activateExplorer);
        var live = new ToolEntry("LiveCaptureTool", Strings.LiveCapture, "M2 13H6L9 6L13 19L16 10L18 13H22", false, planned);
        var simulator = new ToolEntry("NetworkSimulatorTool", "Network Simulator", "M2 10H7V15H2Z M16 3H21V8H16Z M16 16H21V21H16Z M7 12H11L16 6 M11 12L16 18", false, planned);
        var benchmark = new ToolEntry("NetworkBenchmarkTool", "Network Benchmark", "M3 20H21 M6 16V12 M11 16V8 M16 16V5 M20 16V9", false, planned);
        var traffic = new ToolGroup("TrafficAnalysisGroup", Strings.TrafficAnalysis, [explorer, live]);
        var experiments = new ToolGroup("NetworkExperimentsGroup", Strings.NetworkExperiments, [simulator, benchmark]);
        Groups = [traffic, experiments];

        ToggleRailCommand = new RelayCommand(ToggleRail);
        ToggleDrawerCommand = new RelayCommand(() => DrawerOpen = !DrawerOpen, () => IsNarrow);
    }

    public IReadOnlyList<ToolGroup> Groups { get; }
    public IRelayCommand ToggleRailCommand { get; }
    public IRelayCommand ToggleDrawerCommand { get; }
    public IRelayCommand CloseDrawerCommand { get; }
    public bool IsCompactDesktop => compact && !narrow;
    public bool IsNarrow => narrow;
    public string RailAction => compact ? Strings.ExpandNavigation : Strings.CollapseNavigation;
    public string DrawerAction => drawerOpen ? Strings.CloseNavigation : Strings.OpenNavigation;

    public bool DrawerOpen
    {
        get => drawerOpen;
        private set
        {
            if (SetProperty(ref drawerOpen, value))
            {
                OnPropertyChanged(nameof(DrawerAction));
                CloseDrawerCommand.NotifyCanExecuteChanged();
            }
        }
    }

    internal void SetNarrow(bool value)
    {
        if (narrow == value)
            return;

        narrow = value;
        DrawerOpen = false;
        UpdateCompactState();
        OnPropertyChanged(nameof(IsNarrow));
        ToggleDrawerCommand.NotifyCanExecuteChanged();
    }

    private void ToggleRail()
    {
        compact = !compact;
        UpdateCompactState();
        OnPropertyChanged(nameof(RailAction));
    }

    private void UpdateCompactState()
    {
        foreach (var group in Groups)
            group.SetCompact(IsCompactDesktop);

        OnPropertyChanged(nameof(IsCompactDesktop));
    }
}

internal sealed class ToolGroup : ObservableObject
{
    private bool compact;
    private bool expanded = true;

    internal ToolGroup(string automationId, string name, IReadOnlyList<ToolEntry> entries)
    {
        AutomationId = automationId;
        Name = name;
        Entries = entries;
        ToggleCommand = new RelayCommand(Toggle, () => !compact);
    }

    public string AutomationId { get; }
    public string Name { get; }
    public IReadOnlyList<ToolEntry> Entries { get; }
    public IRelayCommand ToggleCommand { get; }
    public bool ItemsVisible => compact || expanded;
    public bool Folded => !expanded;
    public string ActionHint => expanded ? UIText.Format(Strings.CollapseGroup, Name) : UIText.Format(Strings.ExpandGroup, Name);

    internal void SetCompact(bool value)
    {
        if (compact == value)
            return;

        compact = value;
        OnPropertyChanged(nameof(ItemsVisible));
        ToggleCommand.NotifyCanExecuteChanged();
    }

    private void Toggle()
    {
        expanded = !expanded;
        OnPropertyChanged(nameof(ItemsVisible));
        OnPropertyChanged(nameof(Folded));
        OnPropertyChanged(nameof(ActionHint));
    }
}

internal sealed record ToolEntry(string AutomationId, string Name, string Glyph, bool Available, IRelayCommand Command)
{
    public bool Planned => !Available;
    public string Tooltip => Available ? Name : UIText.Format(Strings.PlannedTool, Name);
}
