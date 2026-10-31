using System.Text;
using ConsoleAppFramework;
using PacketLab.Cli;

Console.OutputEncoding = Encoding.UTF8;
ConsoleApp.LogError = Console.Error.WriteLine;
// The framework also shows help for missing arguments and unknown commands.
var helpRequested = args
    .TakeWhile(arg => arg != "--")
    .Any(arg => arg is "-h" or "--help" or "--version");

ConsoleApp.Log = message =>
{
    if (helpRequested)
        Console.WriteLine(message);
    else
    {
        Console.Error.WriteLine(message);
        Environment.ExitCode = 2;
    }
};

var app = ConsoleApp.Create();
app.Add("pcap read", PcapCommands.Read);
app.Run(args);
