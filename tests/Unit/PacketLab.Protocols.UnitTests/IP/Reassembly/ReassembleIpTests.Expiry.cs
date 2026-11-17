using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Protocols.UnitTests.IP.Reassembly;

public partial class ReassembleIpTests
{
    [Test]
    [Arguments(30, false)]
    [Arguments(60, true)]
    public async Task Timeout_deadline_is_respected_near_the_maximum_timestamp(int elapsedSeconds, bool expired)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        reassembler.AdvanceTime(ulong.MaxValue - (ulong)elapsedSeconds * 1_000_000_000UL);
        reassembler.Expire();
        var pending = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        long[] expected = expired ? [pending.DatagramId] : [];

        // Act
        reassembler.AdvanceTime(ulong.MaxValue);
        var updates = reassembler.Expire();

        // Assert
        await Assert.That(updates.Select(x => x.DatagramId).ToArray()).IsEquivalentTo(expected);
    }

    [Test]
    [Arguments(60_000_000_000UL, false)]
    [Arguments(89_999_999_999UL, false)]
    [Arguments(90_000_000_000UL, true)]
    public async Task A_remaining_datagram_expires_at_its_own_deadline_after_the_oldest_is_removed(ulong time, bool expired)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var oldest = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.AdvanceTime(30_000_000_000);
        reassembler.Expire();
        var younger = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;
        reassembler.Expire(oldest.DatagramId);
        long[] expected = expired ? [younger.DatagramId] : [];

        // Act
        reassembler.AdvanceTime(time);
        var updates = reassembler.Expire();

        // Assert
        await Assert.That(updates.Select(x => x.DatagramId).ToArray()).IsEquivalentTo(expected);
    }

    [Test]
    public async Task A_new_datagram_can_use_capacity_released_by_timeout()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler(new(maxDatagrams: 1));
        reassembler.Process(Fragment(4, 0, true, Payload[..16]));
        reassembler.AdvanceTime(60_000_000_000);
        reassembler.Expire();

        // Act
        var result = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;

        // Assert
        await Assert.That(result.Status).IsEqualTo(IpReassemblyStatus.Pending);
    }

    [Test]
    public async Task Advancing_time_reports_only_datagrams_whose_deadline_has_been_reached()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var older = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.AdvanceTime(30_000_000_000);
        reassembler.Expire();
        reassembler.Process(Fragment(4, 0, true, Payload[..16], 2));

        // Act
        reassembler.AdvanceTime(60_000_000_000);
        var updates = reassembler.Expire();

        // Assert
        await Assert.That(updates.Select(x => x.DatagramId).ToArray()).IsEquivalentTo([older.DatagramId]);
    }
}
