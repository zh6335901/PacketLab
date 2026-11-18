using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Protocols.UnitTests.IP.Reassembly;

public partial class ReassembleIpTests
{
    [Test]
    [Arguments(30, 0)]
    [Arguments(60, 1)]
    public async Task Timeout_deadline_is_respected_near_the_maximum_timestamp(int elapsedSeconds, int expiredCount)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        reassembler.AdvanceTime(ulong.MaxValue - (ulong)elapsedSeconds * 1_000_000_000UL);
        var pending = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;

        // Act
        var updates = reassembler.AdvanceTime(ulong.MaxValue);

        // Assert
        await Assert.That(updates.Length).IsEqualTo(expiredCount);
        await Assert.That(updates.All(x => x.DatagramId == pending.DatagramId)).IsTrue();
    }

    [Test]
    public async Task A_remaining_datagram_expires_at_its_own_deadline_after_the_oldest_is_removed()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var oldest = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.AdvanceTime(30_000_000_000);
        var younger = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;
        reassembler.Expire(oldest.DatagramId);

        // Act
        var oldestDeadline = reassembler.AdvanceTime(60_000_000_000UL);
        var before = reassembler.AdvanceTime(89_999_999_999UL);
        var atDeadline = reassembler.AdvanceTime(90_000_000_000UL);

        // Assert
        await Assert.That(oldestDeadline.IsEmpty).IsTrue();
        await Assert.That(before.IsEmpty).IsTrue();
        await Assert.That(atDeadline.Single().DatagramId).IsEqualTo(younger.DatagramId);
    }

    [Test]
    public async Task A_new_datagram_can_use_capacity_released_by_timeout()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler(new(maxDatagrams: 1));
        reassembler.Process(Fragment(4, 0, true, Payload[..16]));
        reassembler.AdvanceTime(60_000_000_000);

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
        reassembler.Process(Fragment(4, 0, true, Payload[..16], 2));

        // Act
        var updates = reassembler.AdvanceTime(60_000_000_000);

        // Assert
        await Assert.That(updates.Select(x => x.DatagramId).ToArray()).IsEquivalentTo([older.DatagramId]);
    }
}
