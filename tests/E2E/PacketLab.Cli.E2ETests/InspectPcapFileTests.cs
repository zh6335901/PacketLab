using static PacketLab.Cli.E2ETests.CliProcess;

namespace PacketLab.Cli.E2ETests;

public class InspectPcapFileTests
{
    [Test]
    [Arguments("ethernet-little", "ethernet", 0)]
    [Arguments("ethernet-big", "ethernet", 0)]
    [Arguments("arp-little", "arp", 0)]
    [Arguments("arp-big", "arp", 0)]
    [Arguments("arp-variants", "arp-variants", 0)]
    [Arguments("arp-truncated", "arp-truncated", 0)]
    [Arguments("ipv4-mixed", "ipv4-mixed", 0)]
    [Arguments("ipv6-little", "ipv6-mixed", 0)]
    [Arguments("ipv6-big", "ipv6-mixed", 0)]
    [Arguments("record-truncated", "record-truncated", 1)]
    [Arguments("unsupported-link", "unsupported-link", 1)]
    public async Task Inspect_matches_expected_file_output(string sample, string expectation, int exitCode)
    {
        var result = await Run("pcap", "inspect", Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var expected = Path.Combine(AppContext.BaseDirectory, "Expected", expectation);
        await Assert.That(result.ExitCode).IsEqualTo(exitCode);
        await Assert.That(result.Output.ReplaceLineEndings("\n")).IsEqualTo(File.ReadAllText(expected + ".stdout.txt").ReplaceLineEndings("\n"));
        await Assert.That(result.Error.ReplaceLineEndings("\n")).IsEqualTo(File.ReadAllText(expected + ".stderr.txt").ReplaceLineEndings("\n"));
    }
}
