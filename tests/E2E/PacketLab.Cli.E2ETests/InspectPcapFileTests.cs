using static PacketLab.Cli.E2ETests.CliProcess;

namespace PacketLab.Cli.E2ETests;

public class InspectPcapFileTests
{
    [Test]
    [Arguments("ethernet-little.pcap")]
    [Arguments("ethernet-big.pcap")]
    public async Task Inspect_lists_outer_headers_and_continues_after_frame_errors(string sample)
    {
        var result = await Run("pcap", "inspect", Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample));
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Error).IsEqualTo("");
        await Assert.That(result.Output.ReplaceLineEndings()).IsEqualTo("""
            Record 1: src 02:00:00:00:00:01 dst FF:FF:FF:FF:FF:FF EtherType 0x0806 (ARP)
            Record 2: Incomplete Ethernet header: expected 14 bytes, captured 3.
            Record 3: Unsupported IEEE 802.3 length encapsulation (length 1500).
            Record 4: Invalid Length/Type field: 0x05DD.
            Record 5: src 66:55:44:33:22:11 dst 00:11:22:33:44:55 EtherType 0x8100
            """.ReplaceLineEndings() + Environment.NewLine);
    }

    [Test]
    public async Task Unsupported_link_type_stops_before_inspecting_records()
    {
        using var input = new InputFile(PcapSamples.Replace(PcapSamples.Multiple(), 20, "65000000"));
        var result = await Run("pcap", "inspect", input.Path);
        await Assert.That(result.ExitCode).IsEqualTo(1);
        await Assert.That(result.Output).IsEqualTo("");
        await Assert.That(result.Error).Contains("Unsupported link type 101");
    }

    [Test]
    public async Task Truncated_record_fails_the_file_after_printing_complete_records()
    {
        using var input = new InputFile(PcapSamples.Multiple()[..60]);
        var result = await Run("pcap", "inspect", input.Path);
        await Assert.That(result.ExitCode).IsEqualTo(1);
        await Assert.That(result.Output.TrimEnd()).IsEqualTo("Record 1: Incomplete Ethernet header: expected 14 bytes, captured 3.");
        await Assert.That(result.Error).Contains("Error at byte 60, record 2: Incomplete packet data");
    }
}
