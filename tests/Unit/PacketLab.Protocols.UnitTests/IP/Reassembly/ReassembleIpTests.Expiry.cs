using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Protocols.UnitTests.IP.Reassembly;

public partial class ReassembleIpTests
{
    [Test]
    [Arguments(30, false)]
    [Arguments(60, true)]
    public async Task Expiry_near_the_timestamp_limit_uses_elapsed_time_without_overflow(int elapsedSeconds, bool expired)
    {
        using var reassembler = new IpFragmentReassembler();
        reassembler.AdvanceTime(ulong.MaxValue - (ulong)elapsedSeconds * 1_000_000_000UL);
        var pending = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        var updates = reassembler.AdvanceTime(ulong.MaxValue);
        await Assert.That(updates.Length).IsEqualTo(expired ? 1 : 0);
        await Assert.That(reassembler.IsRetained(pending.DatagramId)).IsEqualTo(!expired);
    }

    [Test]
    public async Task Removing_the_oldest_entry_does_not_expire_younger_entries_early()
    {
        using var reassembler = new IpFragmentReassembler();
        var oldest = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.AdvanceTime(30_000_000_000);
        var younger = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;
        reassembler.Expire(oldest.DatagramId);
        await Assert.That(reassembler.AdvanceTime(60_000_000_000).IsEmpty).IsTrue();
        await Assert.That(reassembler.IsRetained(younger.DatagramId)).IsTrue();
        await Assert.That(reassembler.AdvanceTime(89_999_999_999).IsEmpty).IsTrue();
        await Assert.That(reassembler.AdvanceTime(90_000_000_000).Single().DatagramId).IsEqualTo(younger.DatagramId);
    }

    [Test]
    [Arguments(1)]
    [Arguments(32)]
    [Arguments(1024)]
    public async Task Time_sweep_removes_every_expired_identity_and_reuses_the_table(int count)
    {
        using var reassembler = new IpFragmentReassembler(new(maxDatagrams: count));
        reassembler.AdvanceTime(10_000_000_000);
        var pending = Enumerable.Range(0, count)
            .Select(i => reassembler.Process(Fragment(4, 0, true, Payload[..16], (ushort)i))!).ToArray();
        foreach (var update in pending.Where(x => x.DatagramId % 2 == 0))
            reassembler.Discard(update.DatagramId);

        var expired = reassembler.AdvanceTime(70_000_000_000);
        await Assert.That(expired.Select(x => x.DatagramId).ToArray())
            .IsEquivalentTo(pending.Select(x => x.DatagramId).ToArray());
        await Assert.That(expired.All(x => x.Status == IpReassemblyStatus.Expired)).IsTrue();
        await Assert.That(pending.Any(x => reassembler.IsRetained(x.DatagramId))).IsFalse();
        await Assert.That(reassembler.Process(Fragment(4, 0, true, Payload[..16]))!.Status)
            .IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(reassembler.AdvanceTime(0).IsEmpty).IsTrue();
        await Assert.That(reassembler.AdvanceTime(129_999_999_999).IsEmpty).IsTrue();
        await Assert.That(reassembler.AdvanceTime(130_000_000_000).Single().Status).IsEqualTo(IpReassemblyStatus.Expired);
    }

    [Test]
    public async Task Time_sweep_keeps_younger_datagrams_until_their_own_deadline()
    {
        using var reassembler = new IpFragmentReassembler();
        var older = Enumerable.Range(0, 32)
            .Select(i => reassembler.Process(Fragment(4, 0, true, Payload[..16], (ushort)i))!.DatagramId).ToArray();
        reassembler.AdvanceTime(30_000_000_000);
        var younger = Enumerable.Range(32, 32)
            .Select(i => reassembler.Process(Fragment(4, 0, true, Payload[..16], (ushort)i))!.DatagramId).ToArray();

        await Assert.That(reassembler.AdvanceTime(60_000_000_000).Select(x => x.DatagramId).ToArray()).IsEquivalentTo(older);
        await Assert.That(younger.All(reassembler.IsRetained)).IsTrue();
        await Assert.That(reassembler.AdvanceTime(90_000_000_000).Select(x => x.DatagramId).ToArray()).IsEquivalentTo(younger);
    }
}
