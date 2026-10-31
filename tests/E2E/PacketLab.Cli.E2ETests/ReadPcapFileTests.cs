using System.Diagnostics;
using System.Text;
using PacketLab.Tests;

namespace PacketLab.Cli.E2ETests;

public class ReadPcapFileTests
{
    [Test]
    public async Task Cli_reads_entire_file_and_prints_accurate_summary()
    {
        var bytes = PcapSamples.Replace(Convert.FromHexString(PcapSamples.Multiple), 16, "03000000FFFF0000");
        using var input = new InputFile(bytes);
        var result = await Run("pcap", "read", input.Path);
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Error).IsEqualTo("");
        await Assert.That(result.Output.Replace("\r\n", "\n")).IsEqualTo(
            "PCAP 2.4\nByte order: LittleEndian\nTimestamp precision: Microseconds\nSnapLen: 3\nLink type: 65535\nPackets: 3\n");
    }

    [Test]
    public async Task Missing_file_reports_the_path_and_exits_with_failure()
    {
        using var input = new InputFile([]);
        var path = input.Path + ".missing";
        var result = await Run("pcap", "read", path);
        await Assert.That(result.ExitCode).IsEqualTo(1);
        await Assert.That(result.Output).IsEqualTo("");
        await Assert.That(result.Error).Contains("Unable to read");
        await Assert.That(result.Error).Contains(path);
    }

    [Test]
    public async Task Invalid_file_header_reports_open_failure_without_a_success_summary()
    {
        using var input = new InputFile([]);
        var result = await Run("pcap", "read", input.Path);
        await Assert.That(result.ExitCode).IsEqualTo(1);
        await Assert.That(result.Output).IsEqualTo("");
        await Assert.That(result.Error).Contains("Error at byte 0");
        await Assert.That(result.Error).Contains("Incomplete file header");
    }

    [Test]
    public async Task Failure_after_a_packet_reports_location_without_a_success_summary()
    {
        using var input = new InputFile(Convert.FromHexString(PcapSamples.Multiple)[..60]);
        var result = await Run("pcap", "read", input.Path);
        await Assert.That(result.ExitCode).IsEqualTo(1);
        await Assert.That(result.Output).IsEqualTo("");
        await Assert.That(result.Error).Contains("Error at byte 60");
        await Assert.That(result.Error).Contains("Incomplete packet data");
        await Assert.That(result.Error).Contains("record 2");
    }

    private static async Task<ProcessResult> Run(params string[] args)
    {
        // A Windows console process started without a console uses the system code page.
        // TUnit's UTF-8 console setting in the parent does not change the child's encoding.
        Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        var encoding = Encoding.GetEncoding(0);
        var executable = Environment.GetEnvironmentVariable("PACKETLAB_CLI_EXECUTABLE");
        var start = new ProcessStartInfo
        {
            FileName = string.IsNullOrWhiteSpace(executable) ? "dotnet" : executable,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            StandardOutputEncoding = encoding,
            StandardErrorEncoding = encoding,
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

    private sealed record ProcessResult(int ExitCode, string Output, string Error);

    private sealed class InputFile : IDisposable
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
