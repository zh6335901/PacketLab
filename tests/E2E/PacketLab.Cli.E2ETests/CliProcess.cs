using System.Diagnostics;
using System.Text;

namespace PacketLab.Cli.E2ETests;

internal static class CliProcess
{
    internal static async Task<ProcessResult> Run(params string[] args)
    {
        var executable = Environment.GetEnvironmentVariable("PACKETLAB_CLI_EXECUTABLE");
        var start = new ProcessStartInfo
        {
            FileName = string.IsNullOrWhiteSpace(executable) ? "dotnet" : executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
            CreateNoWindow = true,
            WorkingDirectory = AppContext.BaseDirectory
        };
        if (string.IsNullOrWhiteSpace(executable))
            start.ArgumentList.Add(System.IO.Path.Combine(AppContext.BaseDirectory, "cli", "PacketLab.Cli.dll"));
        foreach (var arg in args) start.ArgumentList.Add(arg);
        using var process = Process.Start(start) ?? throw new InvalidOperationException("CLI did not start.");
        var output = process.StandardOutput.ReadToEndAsync();
        var error = process.StandardError.ReadToEndAsync();
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
        try
        {
            await process.WaitForExitAsync(timeout.Token);
            return new ProcessResult(process.ExitCode, await output, await error);
        }
        finally
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                await process.WaitForExitAsync();
            }
        }
    }

    internal sealed record ProcessResult(int ExitCode, string Output, string Error);

    internal sealed class InputFile : IDisposable
    {
        private readonly string directory = System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"PacketLab tests {Guid.NewGuid():N}");
        internal string Path { get; }

        internal InputFile(byte[] bytes)
        {
            Directory.CreateDirectory(directory);
            Path = System.IO.Path.Combine(directory, "capture 样例.pcap");
            File.WriteAllBytes(Path, bytes);
        }

        public void Dispose()
        {
            File.Delete(Path);
            Directory.Delete(directory);
        }
    }
}
