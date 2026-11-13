using System.Buffers.Binary;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.UnitTests.IP.Reassembly;

public class ReassembleIpTests
{
    private static readonly byte[] Payload = Convert.FromHexString("04D20035001800000102030405060708090A0B0C0D0E0F10");

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
    public async Task Same_range_with_different_bytes_is_a_conflict(int version)
    {
        var changed = Payload[..16]; changed[8] ^= 1;
        var packets = Packets(Fragment(version, 0, true, Payload[..16]), Fragment(version, 0, true, changed));
        using var sequence = new FragmentSequence(packets);
        sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Truncated_fragments_cannot_be_completed_by_later_fragments(int version)
    {
        var packets = Packets(Fragment(version, 0, true, Payload[..16])[..^1], Fragment(version, 16, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets);
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Truncated);
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Packet).IsNull();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Non_final_fragment_requires_eight_byte_alignment(int version)
    {
        var packets = Packets(Fragment(version, 0, true, Payload[..15]));
        using var sequence = new FragmentSequence(packets);
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Fragment_end_must_fit_the_ip_length_field(int version)
    {
        var packets = Packets(Fragment(version, 65528, false, Payload[..16]));
        using var sequence = new FragmentSequence(packets);
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Conflicting_final_lengths_are_rejected(int version)
    {
        var packets = Packets(Fragment(version, 16, false, Payload[16..]), Fragment(version, 8, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets);
        sequence.Next(); sequence.Next();
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

    [Test]
    public async Task IPv6_extension_headers_before_and_after_fragment_survive_reassembly()
    {
        var withDestination = new byte[] { 17, 0, 0, 0, 0, 0, 0, 0 }.Concat(Payload).ToArray();
        var packets = Packets(Fragment(6, 24, false, withDestination[24..], nextHeader: 60, hopByHop: true),
            Fragment(6, 0, true, withDestination[..24], nextHeader: 60, hopByHop: true));
        using var sequence = new FragmentSequence(packets);
        sequence.Next(); sequence.Next();
        var result = sequence.Updates.Single();
        await Assert.That(result.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(result.Packet!.Bytes.Span[40]).IsEqualTo((byte)60);
        await Assert.That(result.Packet.Bytes.Span[48..56].SequenceEqual(withDestination[..8])).IsTrue();
        await Assert.That(Udp(result).Payload.Span.SequenceEqual(Payload[8..])).IsTrue();
    }

    [Test]
    public async Task IPv6_first_fragment_cannot_split_an_extension_header_across_fragments()
    {
        var incompleteDestination = new byte[] { 17, 1, 0, 0, 0, 0, 0, 0 };
        var packets = Packets(Fragment(6, 0, true, incompleteDestination, nextHeader: 60),
            Fragment(6, 8, false, Payload, nextHeader: 60));
        using var sequence = new FragmentSequence(packets);
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Packet).IsNull();
    }

    [Test]
    public async Task IPv6_incompatible_next_header_is_a_conflict_within_the_same_identity()
    {
        var packets = Packets(Fragment(6, 0, true, Payload[..16]), Fragment(6, 16, false, Payload[16..], nextHeader: 6));
        using var sequence = new FragmentSequence(packets);
        sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Datagram_limit_includes_tombstones_and_does_not_block_an_existing_datagram()
    {
        var packets = Packets(Fragment(4, 0, true, Payload[..16]), Fragment(4, 0, true, Payload[..16], 2),
            Fragment(4, 16, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets, new(maxDatagrams: 1));
        sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
        await Assert.That(sequence.Updates.Single().DatagramId).IsEqualTo(2L);
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Byte_limit_discards_the_affected_datagram_and_releases_its_buffers()
    {
        var packets = Packets(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]),
            Fragment(4, 16, false, Payload[16..], 2));
        using var sequence = new FragmentSequence(packets, new(maxBufferedBytes: 56));
        sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Pending);
    }

    [Test]
    public async Task Single_datagram_limit_is_reported_before_buffering()
    {
        var packets = Packets(Fragment(4, 16, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets, new(maxDatagramBytes: 40));
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
    }

#pragma warning disable PL0003 // Each permutation verifies the same reconstruction invariant.
    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Every_arrival_permutation_of_three_fragments_reconstructs_the_same_payload(int version)
    {
        int[][] orders = [[0, 1, 2], [0, 2, 1], [1, 0, 2], [1, 2, 0], [2, 0, 1], [2, 1, 0]];
        var fragments = new[] { Fragment(version, 0, true, Payload[..8]), Fragment(version, 8, true, Payload[8..16]), Fragment(version, 16, false, Payload[16..]) };
        foreach (var order in orders)
        {
            var packets = Packets(order.Select(x => fragments[x]).ToArray());
            using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next(); sequence.Next();
            var result = sequence.Updates.Single();
            await Assert.That(result.Status).IsEqualTo(IpReassemblyStatus.Complete);
            await Assert.That(Udp(result).Payload.Span.SequenceEqual(Payload[8..])).IsTrue();
        }
    }

#pragma warning restore PL0003

    [Test]
    [Arguments(4, 12)]
    [Arguments(4, 16)]
    [Arguments(4, 9)]
    [Arguments(6, 8)]
    [Arguments(6, 24)]
    public async Task Source_destination_and_ipv4_protocol_are_part_of_the_identity(int version, int changedByte)
    {
        var tail = Fragment(version, 16, false, Payload[16..]); tail[changedByte] ^= 1;
        var packets = Packets(Fragment(version, 0, true, Payload[..16]), tail);
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Length).IsEqualTo(2);
        await Assert.That(sequence.Updates.All(x => x.Status == IpReassemblyStatus.Incomplete)).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Bytes_beyond_the_declared_ip_length_are_not_fragment_payload(int version)
    {
        var tail = Fragment(version, 16, false, Payload[16..]).Concat(new byte[] { 0xaa, 0xbb, 0xcc }).ToArray();
        var packets = Packets(Fragment(version, 0, true, Payload[..16]), tail);
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Packet!.Bytes.Length).IsEqualTo(version == 4 ? 44 : 64);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Empty_non_atomic_fragment_is_invalid(int version)
    {
        var packets = Packets(Fragment(version, 16, false, []));
        using var sequence = new FragmentSequence(packets); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    public async Task IPv6_hop_by_hop_after_fragment_is_invalid_even_when_reconstruction_would_move_it_first()
    {
        var payload = new byte[] { 17, 0, 0, 0, 0, 0, 0, 0 }.Concat(Payload[..8]).ToArray();
        var packets = Packets(Fragment(6, 0, true, payload, nextHeader: 0));
        using var sequence = new FragmentSequence(packets); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
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
    public async Task Reassembly_preserves_unavailable_ipv6_routing_checksum_context()
    {
        var first = Fragment(6, 0, true, Payload[..16], hopByHop: true);
        var tail = Fragment(6, 16, false, Payload[16..], hopByHop: true);
        first[6] = tail[6] = 43; first[43] = tail[43] = 1;
        first[62] = 0x12; first[63] = 0x34;
        var packets = Packets(first, tail);
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(Udp(sequence.Updates.Single()).Checksum is UdpChecksumUnavailable
            { Reason: UdpUnavailableReason.PseudoHeaderUnavailable }).IsTrue();
    }

    [Test]
    public async Task Completion_releases_bytes_for_the_next_datagram()
    {
        var packets = Packets(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]),
            Fragment(4, 0, true, Payload[..16], 2), Fragment(4, 16, false, Payload[16..], 2));
        using var sequence = new FragmentSequence(packets, new(maxBufferedBytes: 64)); sequence.Next(); sequence.Next(); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Ipv4_offset_zero_options_are_preserved_when_the_first_fragment_arrives_late()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..20].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[20..]).ToArray();
        first[0] = 0x46; first[3] += 4;
        var packets = Packets(Fragment(4, 16, false, Payload[16..]), first);
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        var frame = sequence.Updates.Single().Packet!.Bytes;
        await Assert.That(frame.Span[20..24].SequenceEqual(new byte[] { 1, 1, 0, 0 })).IsTrue();
        await Assert.That(Udp(sequence.Updates.Single()).IsComplete).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Duplicate_final_fragment_is_safe_before_the_missing_first_fragment_arrives(int version)
    {
        var tail = Fragment(version, 16, false, Payload[16..]);
        var packets = Packets(tail, tail, Fragment(version, 0, true, Payload[..16]));
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Duplicate);
        sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Fragment_beyond_an_already_known_final_boundary_is_rejected(int version)
    {
        var packets = Packets(Fragment(version, 8, false, Payload[16..]), Fragment(version, 24, true, Payload[..8]));
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Final_fragment_cannot_end_before_an_already_buffered_fragment(int version)
    {
        var packets = Packets(Fragment(version, 24, true, Payload[..8]), Fragment(version, 8, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Maximum_ipv4_length_is_accepted_with_a_valid_rewritten_header_checksum()
    {
        var item = MaximumDatagram(4, 65515);
        await Assert.That(item.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(item.Packet!.Bytes.Length).IsEqualTo(65535);
        var decoding = item.Packet!.Decoding;
        var ip = decoding is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 ? d4 : throw new InvalidOperationException();
        await Assert.That(ip.Packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
        await Assert.That(ip.Packet.Header.TotalLength).IsEqualTo((ushort)65535);
    }

    [Test]
    public async Task Maximum_ipv6_payload_length_is_accepted_without_a_fragment_header()
    {
        var item = MaximumDatagram(6, 65535);
        await Assert.That(item.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(item.Packet!.Bytes.Length).IsEqualTo(65575);
        var decoding = item.Packet!.Decoding;
        var ip = decoding is IPv6DecodeResult v6 && v6 is DecodedIPv6 d6 ? d6 : throw new InvalidOperationException();
        await Assert.That(ip.Header.PayloadLength).IsEqualTo((ushort)65535);
        await Assert.That(ip.Extensions.Length).IsEqualTo(0);
    }

    [Test]
    public async Task First_ipv4_header_options_are_included_in_the_final_size_limit()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..20].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[20..]).ToArray();
        first[0] = 0x46; first[3] += 4;
        var packets = Packets(Fragment(4, 16, false, new byte[65499]), first);
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    public async Task Configured_size_limit_includes_a_late_first_header_with_options()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..20].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[20..]).ToArray();
        first[0] = 0x46; first[3] += 4;
        var packets = Packets(Fragment(4, 16, false, Payload[16..]), first);
        using var sequence = new FragmentSequence(packets, new(maxDatagramBytes: 44)); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
    }

    [Test]
    public async Task Datagram_exactly_at_configured_size_limit_completes()
    {
        var packets = Packets(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets, new(maxDatagramBytes: 44)); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    [Arguments(0x40)]
    [Arguments(0x80)]
    public async Task Invalid_ipv4_fragmentation_flags_are_diagnosed(byte flag)
    {
        var frame = Fragment(4, 0, true, Payload[..16]); frame[6] |= flag;
        var packets = Packets(frame);
        using var sequence = new FragmentSequence(packets); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

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
    public async Task Aggregate_buffer_limit_applies_across_distinct_datagrams()
    {
        var packets = Packets(Fragment(4, 16, false, Payload[16..]), Fragment(4, 16, false, Payload[16..], 2));
        using var sequence = new FragmentSequence(packets, new(maxBufferedBytes: 55)); sequence.Next(); sequence.Next();
        var item = sequence.Updates.Single();
        await Assert.That(item.Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
        await Assert.That(item.DatagramId).IsEqualTo(2L);
        await Assert.That(item.DatagramId).IsEqualTo(2L);
    }

    [Test]
    [Arguments(16, 5, IpReassemblyStatus.Invalid)]
    [Arguments(24, 4, IpReassemblyStatus.Invalid)]
    [Arguments(24, 7, IpReassemblyStatus.Invalid)]
    [Arguments(24, 6, IpReassemblyStatus.Pending)]
    [Arguments(24, 5, IpReassemblyStatus.Pending)]
    public async Task IPv6_first_fragment_must_contain_the_whole_tcp_header(int length, byte dataOffset, IpReassemblyStatus status)
    {
        var tcp = new byte[length]; tcp[12] = (byte)(dataOffset << 4);
        var packets = Packets(Fragment(6, 0, true, tcp, nextHeader: 6));
        using var sequence = new FragmentSequence(packets); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(status);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Identical_bytes_at_different_overlapping_offsets_are_not_duplicates(int version)
    {
        var bytes = new byte[16]; bytes[4] = bytes[12] = 0; bytes[5] = bytes[13] = 24;
        var packets = Packets(Fragment(version, 0, true, bytes), Fragment(version, 8, true, bytes));
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Header_storage_is_included_in_the_buffer_limit_before_payload_is_accepted()
    {
        var packets = Packets(Fragment(4, 0, true, Payload[..16]));
        using var sequence = new FragmentSequence(packets, new(maxBufferedBytes: 55)); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
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
    public async Task Atomic_tcp_with_exactly_twenty_header_bytes_is_complete()
    {
        var tcp = new byte[20]; tcp[12] = 0x50;
        var packets = Packets(Fragment(6, 0, false, tcp, nextHeader: 6));
        using var sequence = new FragmentSequence(packets); sequence.Next();
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Atomic);
    }

    [Test]
    public async Task Reconstructed_ipv4_header_checksum_can_be_zero()
    {
        var packets = Packets(Fragment(4, 0, true, Payload[..16], 0x65c2), Fragment(4, 16, false, Payload[16..], 0x65c2));
        using var sequence = new FragmentSequence(packets); sequence.Next(); sequence.Next();
        var decoding = sequence.Updates.Single().Packet!.Decoding;

        var ip = decoding is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 ? d4 : throw new InvalidOperationException();
        await Assert.That(ip.Packet.Header.HeaderChecksum).IsEqualTo((ushort)0);
        await Assert.That(ip.Packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
    }

    [Test]
    [Arguments(0, 0, 0)]
    [Arguments(1, 1, 1)]
    [Arguments(2, 2, 2)]
    [Arguments(3, 3, 3)]
    [Arguments(2, 3, 3)]
    [Arguments(3, 2, 3)]
    [Arguments(1, 3, 3)]
    [Arguments(3, 1, 3)]
    public async Task IPv4_reassembly_preserves_ecn_and_recalculates_the_header_checksum(byte firstEcn, byte tailEcn, byte expected)
    {
        var first = Fragment(4, 0, true, Payload[..16]); first[1] = (byte)(0xa8 | firstEcn);
        var tail = Fragment(4, 16, false, Payload[16..]); tail[1] = tailEcn;
        foreach (var packets in new[] { new[] { first, tail }, new[] { tail, first } })
        {
            using var reassembler = new IpFragmentReassembler();
            reassembler.Process(packets[0]);
            var complete = reassembler.Process(packets[1])!;
            var decoding = complete.Packet!.Decoding;
            var ip = decoding is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 ? d4.Packet : throw new InvalidOperationException();
            await Assert.That(ip.Header.Ecn).IsEqualTo(expected);
            await Assert.That(ip.Header.Dscp).IsEqualTo((byte)42);
            await Assert.That(ip.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
        }
    }

    [Test]
    public async Task IPv4_duplicate_fragment_contributes_its_ce_marking()
    {
        var first = Fragment(4, 0, true, Payload[..16]); first[1] = 2;
        var duplicate = first.ToArray(); duplicate[1] = 3;
        var tail = Fragment(4, 16, false, Payload[16..]); tail[1] = 2;
        using var reassembler = new IpFragmentReassembler();
        reassembler.Process(first);
        await Assert.That(reassembler.Process(duplicate)!.Status).IsEqualTo(IpReassemblyStatus.Duplicate);
        var complete = reassembler.Process(tail)!;
        await Assert.That(complete.Packet!.Bytes.Span[1] & 3).IsEqualTo(3);
    }

    [Test]
    [Arguments(0, 3)]
    [Arguments(3, 0)]
    public async Task IPv4_ce_and_not_ect_fragments_discard_the_identity(byte firstEcn, byte tailEcn)
    {
        var first = Fragment(4, 0, true, Payload[..16]); first[1] = firstEcn;
        var tail = Fragment(4, 16, false, Payload[16..]); tail[1] = tailEcn;
        using var reassembler = new IpFragmentReassembler();
        reassembler.Process(first);
        await Assert.That(reassembler.Process(tail)!.Status).IsEqualTo(IpReassemblyStatus.Conflict);
        await Assert.That(reassembler.Process(first)!.Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Fragment_limit_bounds_storage_without_counting_ignored_duplicates()
    {
        using var reassembler = new IpFragmentReassembler(new(maxFragmentsPerDatagram: 1));
        var first = Fragment(4, 0, true, Payload[..16]);
        reassembler.Process(first);
        await Assert.That(reassembler.Process(first)!.Status).IsEqualTo(IpReassemblyStatus.Duplicate);
        await Assert.That(reassembler.Process(Fragment(4, 16, false, Payload[16..]))!.Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
    }

    [Test]
    public async Task Supplied_time_expires_pending_and_discarded_identities_at_the_boundary()
    {
        using var reassembler = new IpFragmentReassembler(new(maxDatagrams: 2));
        reassembler.AdvanceTime(1_000_000_000);
        var first = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        var second = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;
        reassembler.Discard(second.DatagramId);
        await Assert.That(reassembler.AdvanceTime(60_999_999_999).Length).IsEqualTo(0);
        var expired = reassembler.AdvanceTime(61_000_000_000);
        await Assert.That(expired.Select(x => x.DatagramId).ToArray()).IsEquivalentTo(new[] { first.DatagramId, second.DatagramId });
        await Assert.That(reassembler.IsRetained(second.DatagramId)).IsFalse();
    }

    [Test]
    public async Task Discard_keeps_a_tombstone_until_explicit_expiry()
    {
        using var reassembler = new IpFragmentReassembler();
        var first = reassembler.Process(Fragment(6, 0, true, Payload[..16]))!;
        reassembler.Discard(first.DatagramId);
        var tail = Fragment(6, 16, false, Payload[16..]);
        await Assert.That(reassembler.Process(tail)!.Status).IsEqualTo(IpReassemblyStatus.Discarded);
        await Assert.That(reassembler.FindDatagram(tail)).IsEqualTo((long?)first.DatagramId);
        reassembler.Expire(first.DatagramId);
        await Assert.That(reassembler.FindDatagram(tail)).IsNull();
        await Assert.That(reassembler.Process(tail)!.Status).IsEqualTo(IpReassemblyStatus.Pending);
    }

    [Test]
    public async Task Caller_buffer_mutation_and_disposal_do_not_change_reassembled_bytes()
    {
        var reassembler = new IpFragmentReassembler();
        var first = Fragment(4, 0, true, Payload[..16]);
        reassembler.Process(first);
        Array.Fill(first, (byte)0xff);
        var completed = reassembler.Process(Fragment(4, 16, false, Payload[16..]))!;
        reassembler.Dispose();
        await Assert.That(completed.Packet!.Bytes.Span[20..].SequenceEqual(Payload)).IsTrue();
        await Assert.That(() => reassembler.Process(first)).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Finish_reports_missing_bytes_without_assuming_a_capture_end_reason()
    {
        using var reassembler = new IpFragmentReassembler();
        var pending = reassembler.Process(Fragment(4, 16, false, Payload[16..]))!;
        await Assert.That(reassembler.Finish().Single().Status).IsEqualTo(IpReassemblyStatus.Incomplete);
        await Assert.That(reassembler.IsRetained(pending.DatagramId)).IsFalse();
        await Assert.That(reassembler.Finish().Length).IsEqualTo(0);
    }

    private static IpReassemblyUpdate MaximumDatagram(int version, int payloadLength)
    {
        var payload = new byte[payloadLength]; Payload.CopyTo(payload, 0);
        using var sequence = new FragmentSequence(Packets(Fragment(version, 0, true, payload[..16]), Fragment(version, 16, false, payload[16..])));
        sequence.Next(); sequence.Next();
        return sequence.Updates.Single();
    }

    private static UdpDatagram Udp(IpReassemblyUpdate item)
    {
        var decoding = item.Packet!.Decoding;
        if (decoding is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 && d4.Payload is UdpParseResult p4 && p4 is UdpDatagram u4) return u4;
        if (decoding is IPv6DecodeResult v6 && v6 is DecodedIPv6 d6 && d6.Payload is UdpParseResult p6 && p6 is UdpDatagram u6) return u6;
        throw new InvalidOperationException("Expected UDP");
    }

    private static byte[][] Packets(params byte[][] packets) => packets;

    [Test]
    public async Task Explicit_expiry_only_releases_the_requested_identity()
    {
        using var reassembler = new IpFragmentReassembler();
        var first = reassembler.Process(Fragment(4, 0, true, Payload[..16], 1))!;
        var second = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;
        await Assert.That(reassembler.Expire(second.DatagramId)!.DatagramId).IsEqualTo(second.DatagramId);
        await Assert.That(reassembler.IsRetained(first.DatagramId)).IsTrue();
        await Assert.That(reassembler.IsRetained(second.DatagramId)).IsFalse();
        await Assert.That(reassembler.Expire(second.DatagramId)).IsNull();
        await Assert.That(reassembler.Discard(second.DatagramId)).IsNull();
    }

    [Test]
    public async Task Disposal_releases_retained_identities()
    {
        var reassembler = new IpFragmentReassembler();
        var first = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.Dispose();
        await Assert.That(reassembler.IsRetained(first.DatagramId)).IsFalse();
        await Assert.That(() => reassembler.AdvanceTime(1)).Throws<ObjectDisposedException>();
        await Assert.That(() => reassembler.Expire(first.DatagramId)).Throws<ObjectDisposedException>();
        await Assert.That(() => reassembler.Discard(first.DatagramId)).Throws<ObjectDisposedException>();
        await Assert.That(() => reassembler.FindDatagram(ReadOnlyMemory<byte>.Empty)).Throws<ObjectDisposedException>();
        await Assert.That(() => reassembler.Finish()).Throws<ObjectDisposedException>();
    }

    // Feeds explicit IP byte arrays into the public reassembler, with no capture format or link layer.
    private sealed class FragmentSequence(byte[][] packets, IpReassemblyOptions? options = null) : IDisposable
    {
        private readonly IpFragmentReassembler reassembler = new(options);
        private int index;
        internal System.Collections.Immutable.ImmutableArray<IpReassemblyUpdate> Updates { get; private set; } = [];
        internal void Next() => Updates = index == packets.Length ? reassembler.Finish()
            : reassembler.Process(packets[index++]) is { } update ? [update] : [];
        public void Dispose() => reassembler.Dispose();
    }

    private static byte[] Fragment(int version, int offset, bool more, byte[] payload, ushort id = 1,
        byte nextHeader = 17, bool hopByHop = false)
    {
        var header = version == 4 ? 20 : hopByHop ? 56 : 48;
        var frame = new byte[header + payload.Length];
        var ip = frame.AsSpan();
        if (version == 4)
        {
            ip[0] = 0x45; ip[8] = 64; ip[9] = nextHeader; ip[12] = 10; ip[16] = 11;
            BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)(20 + payload.Length));
            BinaryPrimitives.WriteUInt16BigEndian(ip[4..], id);
            BinaryPrimitives.WriteUInt16BigEndian(ip[6..], (ushort)(offset / 8 | (more ? 0x2000 : 0)));
        }
        else
        {
            ip[0] = 0x60; ip[6] = hopByHop ? (byte)0 : (byte)44; ip[7] = 64; ip[23] = 1; ip[39] = 2;
            BinaryPrimitives.WriteUInt16BigEndian(ip[4..], (ushort)(header - 40 + payload.Length));
            if (hopByHop) ip[40] = 44;
            var fragment = ip[(header - 8)..]; fragment[0] = nextHeader;
            BinaryPrimitives.WriteUInt16BigEndian(fragment[2..], (ushort)(offset | (more ? 1 : 0)));
            BinaryPrimitives.WriteUInt32BigEndian(fragment[4..], id);
        }
        payload.CopyTo(frame, header);
        return frame;
    }

}
