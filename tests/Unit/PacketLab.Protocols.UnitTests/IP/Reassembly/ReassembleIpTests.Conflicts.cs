using FsCheck;
using FsCheck.Fluent;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Protocols.UnitTests.IP.Reassembly;

public partial class ReassembleIpTests
{
    [Test]
    public async Task Matching_numeric_addresses_in_different_ip_versions_remain_separate()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler(IpReassemblyOptions.Default);
        var ipv4 = Fragment(4, 0, true, Payload[..16], nextHeader: 0);
        var ipv6 = Fragment(6, 0, true, Payload[..16]);
        ipv6.AsSpan(8, 32).Clear();
        ipv4.AsSpan(12, 4).CopyTo(ipv6.AsSpan(20, 4));
        ipv4.AsSpan(16, 4).CopyTo(ipv6.AsSpan(36, 4));
        var first = reassembler.Process(ipv4)!;

        // Act
        var second = reassembler.Process(ipv6)!;

        // Assert
        await Assert.That(second.Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(first.DatagramId).IsNotEqualTo(second.DatagramId);
    }

    [Test]
    [Arguments(4, 1, IpReassemblyStatus.Conflict)]
    [Arguments(4, 2, IpReassemblyStatus.Conflict)]
    [Arguments(4, 3, IpReassemblyStatus.Conflict)]
    [Arguments(4, 5, IpReassemblyStatus.Complete)]
    [Arguments(6, 1, IpReassemblyStatus.Conflict)]
    [Arguments(6, 2, IpReassemblyStatus.Conflict)]
    [Arguments(6, 3, IpReassemblyStatus.Conflict)]
    [Arguments(6, 5, IpReassemblyStatus.Complete)]
    public async Task Overlap_conflicts_remain_scoped_to_the_affected_identity(int version, int preceding, IpReassemblyStatus expected)
    {
        // Arrange
        var packets = Packets(Fragment(version, 0, true, Payload[..16]), Fragment(version, 8, true, Payload[8..]),
            Fragment(version, 16, false, Payload[16..]), Fragment(version, 0, true, Payload[..16]),
            Fragment(version, 0, true, Payload[..16], 2), Fragment(version, 16, false, Payload[16..], 2));
        using var sequence = new FragmentSequence(packets);
        for (int i = 0; i < preceding; i++) sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments(4, false)]
    [Arguments(4, true)]
    [Arguments(6, false)]
    [Arguments(6, true)]
    public void Partial_overlap_conflicts_regardless_of_contents_or_arrival_order(int version, bool different) =>
        Prop.ForAll((byte blocks, byte overlap, (byte Fill, bool Reverse) choice) =>
        {
            // Arrange
            byte fill = choice.Fill;
            bool reverse = choice.Reverse;
            int length = 8 * (2 + blocks);
            int shift = 8 * (1 + overlap % (length / 8 - 1));
            var data = Enumerable.Repeat(fill, length).ToArray();
            var first = Fragment(version, 8, true, data);
            if (different) data[0] ^= 1;
            var second = Fragment(version, 8 + shift, true, data);

            // Act
            var conflicts = Conflicts(reverse ? second : first, reverse ? first : second);

            // Assert
            return conflicts;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Same_range_with_different_bytes_is_a_conflict(int version) =>
        Prop.ForAll((byte[] data, DoNotSize<ushort> position, (byte Bit, bool Reverse) choice) =>
        {
            // Arrange
            byte bit = choice.Bit;
            bool reverse = choice.Reverse;
            byte[] original = [.. Payload[..8], .. data.Take(data.Length / 8 * 8)];
            var changed = (byte[])original.Clone();
            changed[position.Item % changed.Length] ^= (byte)(1 << (bit % 8));
            var first = Fragment(version, 0, true, original);
            var second = Fragment(version, 0, true, changed);

            // Act
            var result = Conflicts(reverse ? second : first, reverse ? first : second);

            // Assert
            return result;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Different_final_boundaries_conflict_in_either_order(int version) =>
        Prop.ForAll((byte blocks, byte gap, (byte Size, bool Reverse) choice) =>
        {
            // Arrange
            byte size = choice.Size;
            bool reverse = choice.Reverse;
            int offset = (1 + blocks) * 8;
            var first = Fragment(version, offset, false, new byte[1 + size % 8]);
            var other = Fragment(version, offset + 8 * (1 + gap), false, new byte[1 + size % 8]);

            // Act
            var result = Conflicts(reverse ? other : first, reverse ? first : other);

            // Assert
            return result;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Fragment_past_final_boundary_conflicts_in_either_order(int version) =>
        Prop.ForAll((byte blocks, byte gap, (byte Size, bool Reverse) choice) =>
        {
            // Arrange
            byte size = choice.Size;
            bool reverse = choice.Reverse;
            int offset = (1 + blocks) * 8;
            var final = Fragment(version, offset, false, new byte[1 + size % 8]);
            var beyond = Fragment(version, offset + 8 * (1 + gap), true, new byte[8 * (1 + size)]);

            // Act
            var result = Conflicts(reverse ? beyond : final, reverse ? final : beyond);

            // Assert
            return result;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task Different_options_in_repeated_ipv4_first_fragments_are_not_safe_duplicates()
    {
        // Arrange
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..20].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[20..]).ToArray();
        first[0] = 0x46;
        first[3] += 4;
        var duplicate = first.ToArray();
        duplicate[20] = 0;
        var packets = Packets(first, duplicate);
        using var sequence = new FragmentSequence(packets);
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
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
            // Arrange
            var tail = Fragment(version, 16, false, Payload[16..]);
            tail[field + index % width] ^= (byte)(1 + difference % 255);
            using var reassembler = new IpFragmentReassembler(IpReassemblyOptions.Default);
            var first = reassembler.Process(Fragment(version, 0, true, Payload[..16]));

            // Act
            var second = reassembler.Process(tail);

            // Assert
            return second?.Status == IpReassemblyStatus.Pending && first!.DatagramId != second.DatagramId;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task IPv6_incompatible_next_header_is_a_conflict_within_the_same_identity()
    {
        // Arrange
        var packets = Packets(Fragment(6, 0, true, Payload[..16]), Fragment(6, 16, false, Payload[16..], nextHeader: 6));
        using var sequence = new FragmentSequence(packets);
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task IPv6_changed_per_fragment_extension_context_is_rejected()
    {
        // Arrange
        var tail = Fragment(6, 16, false, Payload[16..], hopByHop: true);
        tail[42] = 1;
        var packets = Packets(Fragment(6, 0, true, Payload[..16], hopByHop: true), tail);
        using var sequence = new FragmentSequence(packets);
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Incompatible_ipv6_flow_context_is_not_silently_combined()
    {
        // Arrange
        var tail = Fragment(6, 16, false, Payload[16..]);
        tail[3] = 1;
        var packets = Packets(Fragment(6, 0, true, Payload[..16]), tail);
        using var sequence = new FragmentSequence(packets);
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Atomic_fragment_is_independent_of_a_conflicting_ipv6_identity()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler(IpReassemblyOptions.Default);
        reassembler.Process(Fragment(6, 0, true, Payload[..16]));
        reassembler.Process(Fragment(6, 8, true, Payload[8..]));

        // Act
        var atomic = reassembler.Process(Fragment(6, 0, false, Payload))!;

        // Assert
        await Assert.That(atomic.Status).IsEqualTo(IpReassemblyStatus.Atomic);
        await Assert.That(atomic.Packet!.Bytes.Span[6]).IsEqualTo((byte)17);
        await Assert.That(Udp(atomic).IsComplete).IsTrue();
    }

    [Test]
    public async Task A_fragment_still_conflicts_after_an_atomic_packet_with_the_same_identity()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler(IpReassemblyOptions.Default);
        reassembler.Process(Fragment(6, 0, true, Payload[..16]));
        reassembler.Process(Fragment(6, 8, true, Payload[8..]));
        reassembler.Process(Fragment(6, 0, false, Payload));

        // Act
        var result = reassembler.Process(Fragment(6, 16, false, Payload[16..]));

        // Assert
        await Assert.That(result!.Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    private static bool Conflicts(byte[] first, byte[] second)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler(IpReassemblyOptions.Default);
        reassembler.Process(first);

        // Act
        var result = reassembler.Process(second);

        // Assert
        return result?.Status == IpReassemblyStatus.Conflict;
    }
}
