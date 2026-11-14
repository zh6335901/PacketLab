using FsCheck;
using FsCheck.Fluent;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Protocols.UnitTests.IP.Reassembly;

public partial class ReassembleIpTests
{
    [Test]
    public async Task Matching_numeric_addresses_in_different_ip_versions_remain_separate()
    {
        using var reassembler = new IpFragmentReassembler();
        var ipv4 = Fragment(4, 0, true, Payload[..16], nextHeader: 0);
        var ipv6 = Fragment(6, 0, true, Payload[..16]);
        ipv6.AsSpan(8, 32).Clear();
        ipv4.AsSpan(12, 4).CopyTo(ipv6.AsSpan(20, 4));
        ipv4.AsSpan(16, 4).CopyTo(ipv6.AsSpan(36, 4));

        var first = reassembler.Process(ipv4)!;
        var second = reassembler.Process(ipv6)!;
        await Assert.That(first.Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(second.Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(first.DatagramId).IsNotEqualTo(second.DatagramId);
        await Assert.That(reassembler.Finish().Length).IsEqualTo(2);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Partial_overlap_discards_the_whole_identity_until_expiry(int version)
    {
        var packets = Packets(Fragment(version, 0, true, Payload[..16]), Fragment(version, 8, true, Payload[8..]),
            Fragment(version, 16, false, Payload[16..]), Fragment(version, 0, true, Payload[..16]),
            Fragment(version, 0, true, Payload[..16], 2), Fragment(version, 16, false, Payload[16..], 2));
        using var sequence = new FragmentSequence(packets);
        sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
        sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
        sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Partial_overlap_conflicts_even_when_fragment_contents_are_identical(int version) =>
        Prop.ForAll((byte blocks, byte overlap, byte fill) =>
        {
            int length = 8 * (2 + blocks);
            int shift = 8 * (1 + overlap % (length / 8 - 1));
            var data = Enumerable.Repeat(fill, length).ToArray();
            var first = Fragment(version, 8, true, data);
            var identical = Fragment(version, 8 + shift, true, data);
            data[0] ^= 1;
            var different = Fragment(version, 8 + shift, true, data);
            return ConflictsInEitherOrder(first, identical) && ConflictsInEitherOrder(first, different);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Same_range_with_different_bytes_is_a_conflict(int version) =>
        Prop.ForAll((byte[] data, DoNotSize<ushort> position, byte bit) =>
        {
            byte[] original = [.. Payload[..8], .. data.Take(data.Length / 8 * 8)];
            var changed = (byte[])original.Clone();
            changed[position.Item % changed.Length] ^= (byte)(1 << (bit % 8));
            return ConflictsInEitherOrder(Fragment(version, 0, true, original), Fragment(version, 0, true, changed));
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Different_final_boundaries_conflict_in_either_order(int version) =>
        Prop.ForAll((byte blocks, byte gap, byte size) =>
        {
            int offset = (1 + blocks) * 8;
            var first = Fragment(version, offset, false, new byte[1 + size % 8]);
            var other = Fragment(version, offset + 8 * (1 + gap), false, new byte[1 + size % 8]);
            return ConflictsInEitherOrder(first, other);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Fragment_past_final_boundary_conflicts_in_either_order(int version) =>
        Prop.ForAll((byte blocks, byte gap, byte size) =>
        {
            int offset = (1 + blocks) * 8;
            var final = Fragment(version, offset, false, new byte[1 + size % 8]);
            var beyond = Fragment(version, offset + 8 * (1 + gap), true, new byte[8 * (1 + size)]);
            return ConflictsInEitherOrder(final, beyond);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task Different_options_in_repeated_ipv4_first_fragments_are_not_safe_duplicates()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..20].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[20..]).ToArray();
        first[0] = 0x46; first[3] += 4;
        var duplicate = first.ToArray(); duplicate[20] = 0;
        var packets = Packets(first, duplicate);
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    [Arguments(4, 12, 4)]
    [Arguments(4, 16, 4)]
    [Arguments(4, 9, 1)]
    [Arguments(6, 8, 16)]
    [Arguments(6, 24, 16)]
    public void Different_identity_fields_never_combine(int version, int field, int width) =>
        Prop.ForAll((byte index, byte difference) =>
        {
            var tail = Fragment(version, 16, false, Payload[16..]);
            tail[field + index % width] ^= (byte)(1 + difference % 255);
            using var reassembler = new IpFragmentReassembler();
            var first = reassembler.Process(Fragment(version, 0, true, Payload[..16]));
            var second = reassembler.Process(tail);
            var incomplete = reassembler.Finish();
            return first?.Status == IpReassemblyStatus.Pending && second?.Status == IpReassemblyStatus.Pending
                && first.DatagramId != second.DatagramId && incomplete.Length == 2
                && incomplete.All(update => update.Status == IpReassemblyStatus.Incomplete);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task IPv6_incompatible_next_header_is_a_conflict_within_the_same_identity()
    {
        var packets = Packets(Fragment(6, 0, true, Payload[..16]), Fragment(6, 16, false, Payload[16..], nextHeader: 6));
        using var sequence = new FragmentSequence(packets);
        sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task IPv6_changed_per_fragment_extension_context_is_rejected()
    {
        var tail = Fragment(6, 16, false, Payload[16..], hopByHop: true); tail[42] = 1;
        var packets = Packets(Fragment(6, 0, true, Payload[..16], hopByHop: true), tail);
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Incompatible_ipv6_flow_context_is_not_silently_combined()
    {
        var tail = Fragment(6, 16, false, Payload[16..]); tail[3] = 1;
        var packets = Packets(Fragment(6, 0, true, Payload[..16]), tail);
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Atomic_fragment_is_independent_of_a_conflicting_ipv6_identity()
    {
        var packets = Packets(Fragment(6, 0, true, Payload[..16]), Fragment(6, 8, true, Payload[8..]),
            Fragment(6, 0, false, Payload), Fragment(6, 16, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets);
        sequence.Next(); sequence.Next(); sequence.Next();
        var atomic = sequence.Updates.Single();
        await Assert.That(atomic.Status).IsEqualTo(IpReassemblyStatus.Atomic);
        await Assert.That(atomic.Packet!.Bytes.Span[6]).IsEqualTo((byte)17);
        await Assert.That(Udp(atomic).IsComplete).IsTrue();
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    private static bool ConflictsInEitherOrder(byte[] left, byte[] right) =>
        Conflicts(left, right) && Conflicts(right, left);

    private static bool Conflicts(byte[] first, byte[] second)
    {
        using var reassembler = new IpFragmentReassembler();
        return reassembler.Process(first)?.Status == IpReassemblyStatus.Pending
            && reassembler.Process(second)?.Status == IpReassemblyStatus.Conflict;
    }
}
