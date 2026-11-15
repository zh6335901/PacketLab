using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Protocols.UnitTests.IP.Reassembly;

public partial class ReassembleIpTests
{
    [Test]
    [Arguments(30, false)]
    [Arguments(60, true)]
    public async Task Timeout_deadline_is_respected_near_the_maximum_timestamp(int elapsedSeconds, bool expired)
    {
        using var reassembler = new IpFragmentReassembler();
        reassembler.AdvanceTime(ulong.MaxValue - (ulong)elapsedSeconds * 1_000_000_000UL);
        var pending = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        long[] expected = expired ? [pending.DatagramId] : [];

        var updates = reassembler.AdvanceTime(ulong.MaxValue);

        await Assert.That(updates.Select(x => x.DatagramId).ToArray()).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments(60_000_000_000UL, false)]
    [Arguments(89_999_999_999UL, false)]
    [Arguments(90_000_000_000UL, true)]
    public async Task A_remaining_datagram_expires_at_its_own_deadline_after_the_oldest_is_removed(ulong time, bool expired)
    {
        using var reassembler = new IpFragmentReassembler();
        var oldest = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.AdvanceTime(30_000_000_000);
        var younger = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;
        reassembler.Expire(oldest.DatagramId);
        long[] expected = expired ? [younger.DatagramId] : [];

        var updates = reassembler.AdvanceTime(time);

        await Assert.That(updates.Select(x => x.DatagramId).ToArray()).IsEquivalentTo(expected);
    }

    [Test]
    public async Task A_new_datagram_can_use_capacity_released_by_timeout()
    {
        using var reassembler = new IpFragmentReassembler(new(maxDatagrams: 1));
        reassembler.Process(Fragment(4, 0, true, Payload[..16]));
        reassembler.AdvanceTime(60_000_000_000);

        var result = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;

        await Assert.That(result.Status).IsEqualTo(IpReassemblyStatus.Pending);
    }

    [Test]
    public async Task Advancing_time_reports_only_datagrams_whose_deadline_has_been_reached()
    {
        using var reassembler = new IpFragmentReassembler();
        var older = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.AdvanceTime(30_000_000_000);
        reassembler.Process(Fragment(4, 0, true, Payload[..16], 2));

        var updates = reassembler.AdvanceTime(60_000_000_000);

        await Assert.That(updates.Select(x => x.DatagramId).ToArray()).IsEquivalentTo([older.DatagramId]);
    }
}
