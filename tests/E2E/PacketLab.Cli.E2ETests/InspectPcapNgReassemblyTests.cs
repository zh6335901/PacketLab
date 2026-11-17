using static PacketLab.Cli.E2ETests.CliProcess;
using static PacketLab.Testing.PcapNgSamples;

namespace PacketLab.Cli.E2ETests;

public class InspectPcapNgReassemblyTests
{
    [Test]
    public async Task Interfaces_reassemble_identical_ids_independently()
    {
        var (first, tail) = Fragments(4);
        using var file = new InputFile([.. Section(), .. Interface(), .. Interface(),
            .. Packet(first), .. Packet(tail, id: 1), .. Packet(tail)]);

        var result = await Run("pcap", "inspect", file.Path);

        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Output.Contains("Complete; records=[1,3]")).IsTrue();
        await Assert.That(result.Output.Contains("IncompleteAtEndOfFile; records=[2]")).IsTrue();
    }

    [Test]
    public async Task Section_changes_finish_old_state_before_processing_new_fragments()
    {
        var (first, tail) = Fragments(6);
        using var file = new InputFile([.. Section(), .. Interface(), .. Packet(first),
            .. Section(true), .. Interface(true), .. Packet(tail, true)]);

        var result = await Run("pcap", "inspect", file.Path);

        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Output.Contains("IncompleteAtEndOfSection; records=[1]")).IsTrue();
        await Assert.That(result.Output.Contains("IncompleteAtEndOfFile; records=[2]")).IsTrue();
        await Assert.That(result.Output.Contains("Complete; records=")).IsFalse();
    }

    [Test]
    public async Task An_empty_trailing_section_still_finishes_the_previous_section()
    {
        var (first, _) = Fragments(4);
        using var file = new InputFile([.. Section(), .. Interface(), .. Packet(first), .. Section(true)]);

        var result = await Run("pcap", "inspect", file.Path);

        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Output.Contains("IncompleteAtEndOfSection; records=[1]")).IsTrue();
        await Assert.That(result.Output.Contains("IncompleteAtEndOfFile")).IsFalse();
    }

    [Test]
    public async Task A_file_error_explicitly_aborts_pending_datagrams()
    {
        var (first, _) = Fragments(4);
        using var file = new InputFile([.. Section(), .. Interface(), .. Packet(first), 1]);

        var result = await Run("pcap", "inspect", file.Path);

        await Assert.That(result.ExitCode).IsEqualTo(1);
        await Assert.That(result.Output.Contains("Aborted; records=[1]")).IsTrue();
        await Assert.That(result.Error.Contains("Error at byte")).IsTrue();
    }

    [Test]
    public async Task Binary_timestamp_expiry_runs_before_accepting_the_next_fragment()
    {
        var (first, tail) = Fragments(6);
        using var file = new InputFile([.. Section(), .. Interface(options: Option(9, [0x81])),
            .. Packet(first, time: 2), .. Packet(tail, time: 122)]);

        var result = await Run("pcap", "inspect", file.Path);

        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Output.Contains("Expired; records=[1]")).IsTrue();
        await Assert.That(result.Output.Contains("Complete; records=")).IsFalse();
    }

    [Test]
    public async Task A_lazily_started_session_uses_the_interfaces_existing_clock()
    {
        var (first, tail) = Fragments(4);
        byte[] arp = Convert.FromHexString("FFFFFFFFFFFF02000000000108060001080006040001020000000001C0000201000000000000C0000202");
        using var file = new InputFile([.. Section(), .. Interface(), .. Packet(arp, time: 100_000_000),
            .. Packet(first, time: 1_000_000), .. Packet(tail, time: 61_000_000)]);

        var result = await Run("pcap", "inspect", file.Path);

        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Output.Contains("Complete; records=[2,3]")).IsTrue();
        await Assert.That(result.Output.Contains("Expired;")).IsFalse();
    }

    private static (byte[] First, byte[] Tail) Fragments(int version)
    {
        const string firstPayload = "04D20035001800000102030405060708";
        const string tailPayload = "090A0B0C0D0E0F10";
        const string addresses = "0000000000000000000000000000000100000000000000000000000000000002";
        var first = version == 4
            ? "00000000000000000000000008004500002400012000401100000A0000000B000000" + firstPayload
            : "00000000000000000000000086DD6000000000182C40" + addresses + "1100000100000001" + firstPayload;
        var tail = version == 4
            ? "00000000000000000000000008004500001C00010002401100000A0000000B000000" + tailPayload
            : "00000000000000000000000086DD6000000000102C40" + addresses + "1100001000000001" + tailPayload;

        return (Convert.FromHexString(first), Convert.FromHexString(tail));
    }
}
