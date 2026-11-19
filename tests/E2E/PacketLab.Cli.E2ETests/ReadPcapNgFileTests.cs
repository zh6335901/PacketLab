using static PacketLab.Cli.E2ETests.CliProcess;

namespace PacketLab.Cli.E2ETests;

public class ReadPcapNgFileTests
{
    [Test]
    public async Task Read_accepts_pcapng_and_reports_all_sections_interfaces_and_packets()
    {
        var result = await Run("pcap", "read", Path.Combine(AppContext.BaseDirectory, "TestData", "PcapNg", "mixed.pcapng"));

        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Error).IsEqualTo("");
        await Assert.That(result.Output.Contains("Packets: 3")).IsTrue();
        await Assert.That(result.Output.Contains("Section 1: PCAPNG 1.0; BigEndian")).IsTrue();
        await Assert.That(result.Output.Contains("Interface 0/1: link type=1")).IsTrue();
    }

    [Test]
    public async Task Inspect_continues_past_unsupported_interfaces_and_displays_time_data_and_comments()
    {
        var result = await Run("pcap", "inspect", Path.Combine(AppContext.BaseDirectory, "TestData", "PcapNg", "mixed.pcapng"));

        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Error).IsEqualTo("");
        await Assert.That(result.Output.Contains("Unsupported link type 101")).IsTrue();
        await Assert.That(result.Output.Contains("Record 3: section=1, interface=0, link type=1")).IsTrue();
        await Assert.That(result.Output.Contains("Timestamp: 1.234567890 s since Unix epoch; captured=42; original=42")).IsTrue();
        await Assert.That(result.Output.Contains("Data: 010203")).IsTrue();
        await Assert.That(result.Output.Contains("Comment: capture note")).IsTrue();
        await Assert.That(result.Output.Contains("ARP")).IsTrue();
    }
}
