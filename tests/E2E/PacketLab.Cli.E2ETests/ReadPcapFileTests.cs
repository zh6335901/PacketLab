using static PacketLab.Cli.E2ETests.CliProcess;
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
}
