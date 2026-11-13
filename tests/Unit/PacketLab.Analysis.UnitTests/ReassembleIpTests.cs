using System.Buffers.Binary;
using PacketLab.Pcap;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;
using PacketLab.Protocols.Udp;

namespace PacketLab.Analysis.UnitTests;

public class ReassembleIpTests
{
    private static readonly byte[] Payload = Convert.FromHexString("04D20035001800000102030405060708090A0B0C0D0E0F10");

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Out_of_order_fragments_reconstruct_exact_bytes_and_record_relationships(int version)
    {
        using var stream = Capture(Fragment(version, 16, false, Payload[16..]), Fragment(version, 0, true, Payload[..16]));
        using var reader = Open(stream);
        Read(reader);
        var first = reader.ReassemblyEvents.Single();
        Read(reader);
        var complete = reader.ReassemblyEvents.Single();
        await Assert.That(first.Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(complete.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(complete.RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 1, 2 });
        await Assert.That(complete.Packet!.Frame.Span[(version == 4 ? 34 : 54)..].SequenceEqual(Payload)).IsTrue();
        await Assert.That(Udp(complete).IsComplete).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Interleaved_identities_complete_independently(int version)
    {
        using var stream = Capture(Fragment(version, 0, true, Payload[..16], 1), Fragment(version, 0, true, Payload[..16], 2),
            Fragment(version, 16, false, Payload[16..], 2), Fragment(version, 16, false, Payload[16..], 1));
        using var reader = Open(stream);
        Read(reader); Read(reader); Read(reader);
        var second = reader.ReassemblyEvents.Single();
        Read(reader);
        var first = reader.ReassemblyEvents.Single();
        await Assert.That(second.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(second.RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 2, 3 });
        await Assert.That(first.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(first.RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 1, 4 });
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Exact_duplicates_do_not_add_coverage_or_conflict(int version)
    {
        var first = Fragment(version, 0, true, Payload[..16]);
        using var stream = Capture(first, first, Fragment(version, 16, false, Payload[16..]));
        using var reader = Open(stream);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Duplicate);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(reader.ReassemblyEvents.Single().RecordNumbers.Length).IsEqualTo(3);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Partial_overlap_discards_the_whole_identity_until_expiry(int version)
    {
        using var stream = Capture(Fragment(version, 0, true, Payload[..16]), Fragment(version, 8, true, Payload[8..]),
            Fragment(version, 16, false, Payload[16..]), Fragment(version, 0, true, Payload[..16]),
            Fragment(version, 0, true, Payload[..16], 2), Fragment(version, 16, false, Payload[16..], 2));
        using var reader = Open(stream);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Same_range_with_different_bytes_is_a_conflict(int version)
    {
        var changed = Payload[..16]; changed[8] ^= 1;
        using var stream = Capture(Fragment(version, 0, true, Payload[..16]), Fragment(version, 0, true, changed));
        using var reader = Open(stream);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Missing_middle_is_incomplete_at_eof_and_terminal_reads_do_not_repeat_events(int version)
    {
        using var stream = Capture(Fragment(version, 0, true, Payload[..8]), Fragment(version, 16, false, Payload[16..]));
        using var reader = Open(stream);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.IncompleteAtEndOfFile);
        reader.ReadNext();
        await Assert.That(reader.ReassemblyEvents.Length).IsEqualTo(0);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Capture_truncation_cannot_be_filled_by_original_length_or_later_fragments(int version)
    {
        using var stream = Capture(Fragment(version, 0, true, Payload[..16])[..^1], Fragment(version, 16, false, Payload[16..]));
        using var reader = Open(stream);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Truncated);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Packet).IsNull();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Non_final_fragment_requires_eight_byte_alignment(int version)
    {
        using var stream = Capture(Fragment(version, 0, true, Payload[..15]));
        using var reader = Open(stream);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Fragment_end_must_fit_the_ip_length_field(int version)
    {
        using var stream = Capture(Fragment(version, 65528, false, Payload[..16]));
        using var reader = Open(stream);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Conflicting_final_lengths_are_rejected(int version)
    {
        using var stream = Capture(Fragment(version, 16, false, Payload[16..]), Fragment(version, 8, false, Payload[16..]));
        using var reader = Open(stream);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Atomic_fragment_is_independent_of_a_conflicting_ipv6_identity()
    {
        using var stream = Capture(Fragment(6, 0, true, Payload[..16]), Fragment(6, 8, true, Payload[8..]),
            Fragment(6, 0, false, Payload), Fragment(6, 16, false, Payload[16..]));
        using var reader = Open(stream);
        Read(reader); Read(reader); Read(reader);
        var atomic = reader.ReassemblyEvents.Single();
        await Assert.That(atomic.Status).IsEqualTo(IpReassemblyStatus.Atomic);
        await Assert.That(atomic.RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 3 });
        await Assert.That(atomic.Packet!.Frame.Span[20]).IsEqualTo((byte)17);
        await Assert.That(Udp(atomic).IsComplete).IsTrue();
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task IPv6_extension_headers_before_and_after_fragment_survive_reassembly()
    {
        var withDestination = new byte[] { 17, 0, 0, 0, 0, 0, 0, 0 }.Concat(Payload).ToArray();
        using var stream = Capture(Fragment(6, 24, false, withDestination[24..], nextHeader: 60, hopByHop: true),
            Fragment(6, 0, true, withDestination[..24], nextHeader: 60, hopByHop: true));
        using var reader = Open(stream);
        Read(reader); Read(reader);
        var result = reader.ReassemblyEvents.Single();
        await Assert.That(result.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(result.Packet!.Frame.Span[54]).IsEqualTo((byte)60);
        await Assert.That(result.Packet.Frame.Span[62..70].SequenceEqual(withDestination[..8])).IsTrue();
        await Assert.That(Udp(result).Payload.Span.SequenceEqual(Payload[8..])).IsTrue();
    }

    [Test]
    public async Task IPv6_first_fragment_cannot_split_an_extension_header_across_records()
    {
        var incompleteDestination = new byte[] { 17, 1, 0, 0, 0, 0, 0, 0 };
        using var stream = Capture(Fragment(6, 0, true, incompleteDestination, nextHeader: 60),
            Fragment(6, 8, false, Payload, nextHeader: 60));
        using var reader = Open(stream);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Packet).IsNull();
    }

    [Test]
    public async Task IPv6_incompatible_next_header_is_a_conflict_within_the_same_identity()
    {
        using var stream = Capture(Fragment(6, 0, true, Payload[..16]), Fragment(6, 16, false, Payload[16..], nextHeader: 6));
        using var reader = Open(stream);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Independent_readers_never_combine_fragments()
    {
        using var first = Capture(Fragment(4, 0, true, Payload[..16]));
        using var second = Capture(Fragment(4, 16, false, Payload[16..]));
        using var left = Open(first); using var right = Open(second);
        Read(left); Read(right); right.ReadNext();
        await Assert.That(right.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.IncompleteAtEndOfFile);
    }

    [Test]
    public async Task Time_expiry_uses_first_arrival_and_does_not_refresh_on_duplicates()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        using var stream = Capture(first, first, Fragment(4, 16, false, Payload[16..]));
        SetSeconds(stream, 1, 100); SetSeconds(stream, 2, 159); SetSeconds(stream, 3, 160);
        using var reader = Open(stream);
        Read(reader); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Select(x => x.Status).ToArray()).IsEquivalentTo(
            new[] { IpReassemblyStatus.Expired, IpReassemblyStatus.Pending });
        await Assert.That(reader.ReassemblyEvents[0].DatagramNumber).IsEqualTo(1L);
    }

    [Test]
    public async Task Record_age_expires_state_when_capture_time_is_not_advancing()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), new byte[14], Fragment(4, 16, false, Payload[16..]));
        using var reader = Open(stream, new(maxRecordAge: 2));
        Read(reader); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents[0].Status).IsEqualTo(IpReassemblyStatus.Expired);
        await Assert.That(reader.ReassemblyEvents[1].Status).IsEqualTo(IpReassemblyStatus.Pending);
    }

    [Test]
    public async Task Datagram_limit_includes_tombstones_and_does_not_block_an_existing_datagram()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 0, true, Payload[..16], 2),
            Fragment(4, 16, false, Payload[16..]));
        using var reader = Open(stream, new(maxDatagrams: 1));
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
        await Assert.That(reader.ReassemblyEvents.Single().RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 2 });
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Byte_limit_discards_the_affected_datagram_and_releases_its_buffers()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]),
            Fragment(4, 16, false, Payload[16..], 2));
        using var reader = Open(stream, new(maxBufferedBytes: 84));
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Pending);
    }

    [Test]
    public async Task Duplicate_flood_hits_the_record_association_limit()
    {
        var fragment = Fragment(4, 0, true, Payload[..16]);
        using var stream = Capture(fragment, fragment, fragment);
        using var reader = Open(stream, new(maxRecordsPerDatagram: 2));
        Read(reader); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.All(x => x.Status == IpReassemblyStatus.ResourceLimit)).IsTrue();
        await Assert.That(reader.ReassemblyEvents.All(x => x.RecordNumbers.Length <= 2)).IsTrue();
        await Assert.That(reader.ReassemblyEvents.SelectMany(x => x.RecordNumbers).ToArray()).IsEquivalentTo(new long[] { 1, 2, 3 });
    }

    [Test]
    public async Task Single_datagram_limit_is_reported_before_buffering()
    {
        using var stream = Capture(Fragment(4, 16, false, Payload[16..]));
        using var reader = Open(stream, new(maxDatagramBytes: 40));
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
    }

    [Test]
    public async Task Disposal_releases_state_and_keeps_caller_stream_open()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]));
        var reader = Open(stream); Read(reader); reader.Dispose();
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Aborted);
        await Assert.That(stream.CanRead).IsTrue();
        await Assert.That(() => reader.ReadNext()).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Completed_bytes_and_original_records_survive_later_reads_and_disposal()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]), new byte[14]);
        var reader = Open(stream);
        var raw = Read(reader); Read(reader);
        var complete = reader.ReassemblyEvents.Single();
        Read(reader); reader.ReadNext(); reader.Dispose();
        await Assert.That(complete.Packet!.Frame.Span[34..].SequenceEqual(Payload)).IsTrue();
        await Assert.That(raw.Packet.Data.Span[34..].SequenceEqual(Payload[..16])).IsTrue();
    }

    [Test]
    public async Task Pcap_failure_reports_aborted_datagrams_without_hiding_the_file_error()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]));
        stream.Position = stream.Length; stream.WriteByte(1); stream.Position = 0;
        using var reader = Open(stream); Read(reader);
        await Assert.That(reader.ReadNext() is PcapError).IsTrue();
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Aborted);
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
            using var stream = Capture(order.Select(x => fragments[x]).ToArray());
            using var reader = Open(stream); Read(reader); Read(reader); Read(reader);
            var result = reader.ReassemblyEvents.Single();
            await Assert.That(result.Status).IsEqualTo(IpReassemblyStatus.Complete);
            await Assert.That(Udp(result).Payload.Span.SequenceEqual(Payload[8..])).IsTrue();
        }
    }

    #pragma warning restore PL0003

    [Test]
    [Arguments(4, 26)]
    [Arguments(4, 30)]
    [Arguments(4, 23)]
    [Arguments(6, 22)]
    [Arguments(6, 38)]
    public async Task Source_destination_and_ipv4_protocol_are_part_of_the_identity(int version, int changedByte)
    {
        var tail = Fragment(version, 16, false, Payload[16..]); tail[changedByte] ^= 1;
        using var stream = Capture(Fragment(version, 0, true, Payload[..16]), tail);
        using var reader = Open(stream); Read(reader); Read(reader); reader.ReadNext();
        await Assert.That(reader.ReassemblyEvents.Length).IsEqualTo(2);
        await Assert.That(reader.ReassemblyEvents.All(x => x.Status == IpReassemblyStatus.IncompleteAtEndOfFile)).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Ethernet_padding_is_not_fragment_payload(int version)
    {
        var tail = Fragment(version, 16, false, Payload[16..]).Concat(new byte[] { 0xaa, 0xbb, 0xcc }).ToArray();
        using var stream = Capture(Fragment(version, 0, true, Payload[..16]), tail);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Packet!.Frame.Length).IsEqualTo(version == 4 ? 58 : 78);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Empty_non_atomic_fragment_is_invalid(int version)
    {
        using var stream = Capture(Fragment(version, 16, false, []));
        using var reader = Open(stream); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    public async Task IPv6_hop_by_hop_after_fragment_is_invalid_even_when_reconstruction_would_move_it_first()
    {
        var payload = new byte[] { 17, 0, 0, 0, 0, 0, 0, 0 }.Concat(Payload[..8]).ToArray();
        using var stream = Capture(Fragment(6, 0, true, payload, nextHeader: 0));
        using var reader = Open(stream); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    public async Task IPv6_truncated_fragment_header_remains_a_raw_parse_failure()
    {
        using var stream = Capture(Fragment(6, 0, true, Payload[..16])[..58]);
        using var reader = Open(stream);
        var record = Read(reader);
        await Assert.That(reader.ReassemblyEvents.Length).IsEqualTo(0);
        var ethernet = record.Decoding is EthernetDecodeResult e && e is DecodedEthernet d ? d : throw new InvalidOperationException();
        await Assert.That(ethernet.Payload is IPv6DecodeResult v6 && v6 is DecodedIPv6 parsed && parsed.Payload is IPv6PayloadUnavailable).IsTrue();
    }

    [Test]
    public async Task IPv6_changed_per_fragment_extension_context_is_rejected()
    {
        var tail = Fragment(6, 16, false, Payload[16..], hopByHop: true); tail[56] = 1;
        using var stream = Capture(Fragment(6, 0, true, Payload[..16], hopByHop: true), tail);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Reassembly_preserves_unavailable_ipv6_routing_checksum_context()
    {
        var first = Fragment(6, 0, true, Payload[..16], hopByHop: true);
        var tail = Fragment(6, 16, false, Payload[16..], hopByHop: true);
        first[20] = tail[20] = 43; first[57] = tail[57] = 1;
        first[76] = 0x12; first[77] = 0x34;
        using var stream = Capture(first, tail);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(Udp(reader.ReassemblyEvents.Single()).Checksum is UdpChecksumUnavailable
            { Reason: UdpUnavailableReason.PseudoHeaderUnavailable }).IsTrue();
    }

    [Test]
    public async Task Nanosecond_capture_timeout_uses_the_fractional_boundary()
    {
        var first = Fragment(6, 0, true, Payload[..16]);
        using var stream = Capture(first, first, Fragment(6, 16, false, Payload[16..]));
        var bytes = stream.GetBuffer();
        BinaryPrimitives.WriteUInt32LittleEndian(bytes, 0xa1b23c4d);
        SetSeconds(stream, 1, 1); SetSeconds(stream, 2, 61); SetSeconds(stream, 3, 61);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(28), 1);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(24 + (16 + first.Length) * 2 + 4), 1);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Duplicate);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents[0].Status).IsEqualTo(IpReassemblyStatus.Expired);
    }

    [Test]
    public async Task Reordered_timestamps_never_underflow_the_expiry_clock()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]));
        SetSeconds(stream, 1, 100); SetSeconds(stream, 2, 1);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Invalid_timestamp_fraction_does_not_expire_other_datagrams()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]));
        SetSeconds(stream, 2, 100);
        BinaryPrimitives.WriteUInt32LittleEndian(stream.GetBuffer().AsSpan(24 + 16 + 50 + 4), 1_000_000);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Tombstones_bound_the_table_and_expire_before_accepting_a_new_identity()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        using var stream = Capture(first, Fragment(4, 8, true, Payload[8..]), Fragment(4, 16, false, Payload[16..], 2),
            Fragment(4, 0, true, Payload[..16], 2), Fragment(4, 16, false, Payload[16..], 2));
        SetSeconds(stream, 4, 61); SetSeconds(stream, 5, 61);
        using var reader = Open(stream, new(maxDatagrams: 1)); Read(reader); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Completion_releases_bytes_for_the_next_datagram()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]),
            Fragment(4, 0, true, Payload[..16], 2), Fragment(4, 16, false, Payload[16..], 2));
        using var reader = Open(stream, new(maxBufferedBytes: 92)); Read(reader); Read(reader); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Ipv4_offset_zero_options_are_preserved_when_the_first_fragment_arrives_late()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..34].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[34..]).ToArray();
        first[14] = 0x46; first[17] += 4;
        using var stream = Capture(Fragment(4, 16, false, Payload[16..]), first);
        using var reader = Open(stream); Read(reader); Read(reader);
        var frame = reader.ReassemblyEvents.Single().Packet!.Frame;
        await Assert.That(frame.Span[34..38].SequenceEqual(new byte[] { 1, 1, 0, 0 })).IsTrue();
        await Assert.That(Udp(reader.ReassemblyEvents.Single()).IsComplete).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Duplicate_final_fragment_is_safe_before_the_missing_first_fragment_arrives(int version)
    {
        var tail = Fragment(version, 16, false, Payload[16..]);
        using var stream = Capture(tail, tail, Fragment(version, 0, true, Payload[..16]));
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Duplicate);
        Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Fragment_beyond_an_already_known_final_boundary_is_rejected(int version)
    {
        using var stream = Capture(Fragment(version, 8, false, Payload[16..]), Fragment(version, 24, true, Payload[..8]));
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Final_fragment_cannot_end_before_an_already_buffered_fragment(int version)
    {
        using var stream = Capture(Fragment(version, 24, true, Payload[..8]), Fragment(version, 8, false, Payload[16..]));
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Maximum_ipv4_length_is_accepted_with_a_valid_rewritten_header_checksum()
    {
        var item = MaximumDatagram(4, 65515);
        await Assert.That(item.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(item.Packet!.Frame.Length).IsEqualTo(65549);
        var ethernet = item.Packet.Decoding is EthernetDecodeResult e && e is DecodedEthernet d ? d : throw new InvalidOperationException();
        var ip = ethernet.Payload is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 ? d4 : throw new InvalidOperationException();
        await Assert.That(ip.Packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
        await Assert.That(ip.Packet.Header.TotalLength).IsEqualTo((ushort)65535);
    }

    [Test]
    public async Task Maximum_ipv6_payload_length_is_accepted_without_a_fragment_header()
    {
        var item = MaximumDatagram(6, 65535);
        await Assert.That(item.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(item.Packet!.Frame.Length).IsEqualTo(65589);
        var ethernet = item.Packet.Decoding is EthernetDecodeResult e && e is DecodedEthernet d ? d : throw new InvalidOperationException();
        var ip = ethernet.Payload is IPv6DecodeResult v6 && v6 is DecodedIPv6 d6 ? d6 : throw new InvalidOperationException();
        await Assert.That(ip.Header.PayloadLength).IsEqualTo((ushort)65535);
        await Assert.That(ip.Extensions.Length).IsEqualTo(0);
    }

    private static IpReassemblyEvent MaximumDatagram(int version, int payloadLength)
    {
        var payload = new byte[payloadLength]; Payload.CopyTo(payload, 0);
        using var stream = Capture(Fragment(version, 0, true, payload[..16]), Fragment(version, 16, false, payload[16..]));
        using var reader = Open(stream); Read(reader); Read(reader);
        return reader.ReassemblyEvents.Single();
    }

    [Test]
    public async Task First_ipv4_header_options_are_included_in_the_final_size_limit()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..34].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[34..]).ToArray();
        first[14] = 0x46; first[17] += 4;
        using var stream = Capture(Fragment(4, 16, false, new byte[65499]), first);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    public async Task Configured_size_limit_includes_a_late_first_header_with_options()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..34].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[34..]).ToArray();
        first[14] = 0x46; first[17] += 4;
        using var stream = Capture(Fragment(4, 16, false, Payload[16..]), first);
        using var reader = Open(stream, new(maxDatagramBytes: 44)); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
    }

    [Test]
    public async Task Datagram_exactly_at_configured_size_limit_completes()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]));
        using var reader = Open(stream, new(maxDatagramBytes: 44)); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    [Arguments(0x40)]
    [Arguments(0x80)]
    public async Task Invalid_ipv4_fragmentation_flags_are_diagnosed(byte flag)
    {
        var frame = Fragment(4, 0, true, Payload[..16]); frame[20] |= flag;
        using var stream = Capture(frame);
        using var reader = Open(stream); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    public async Task Different_options_in_repeated_ipv4_first_fragments_are_not_safe_duplicates()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..34].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[34..]).ToArray();
        first[14] = 0x46; first[17] += 4;
        var duplicate = first.ToArray(); duplicate[34] = 0;
        using var stream = Capture(first, duplicate);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Aggregate_buffer_limit_applies_across_distinct_datagrams()
    {
        using var stream = Capture(Fragment(4, 16, false, Payload[16..]), Fragment(4, 16, false, Payload[16..], 2));
        using var reader = Open(stream, new(maxBufferedBytes: 83)); Read(reader); Read(reader);
        var item = reader.ReassemblyEvents.Single();
        await Assert.That(item.Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
        await Assert.That(item.DatagramNumber).IsEqualTo(2L);
        await Assert.That(item.RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 2 });
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
        using var stream = Capture(Fragment(6, 0, true, tcp, nextHeader: 6));
        using var reader = Open(stream); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(status);
    }

    [Test]
    public async Task Microsecond_capture_fraction_is_used_for_expiry()
    {
        var first = Fragment(4, 0, true, Payload[..16]);
        using var stream = Capture(first, Fragment(4, 16, false, Payload[16..]));
        SetSeconds(stream, 1, 1); SetSeconds(stream, 2, 61);
        BinaryPrimitives.WriteUInt32LittleEndian(stream.GetBuffer().AsSpan(28), 1);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Nanosecond_fractions_are_not_scaled_as_microseconds()
    {
        var first = Fragment(6, 0, true, Payload[..16]);
        using var stream = Capture(first, Fragment(6, 16, false, Payload[16..]));
        var bytes = stream.GetBuffer(); BinaryPrimitives.WriteUInt32LittleEndian(bytes, 0xa1b23c4d);
        SetSeconds(stream, 1, 1); SetSeconds(stream, 2, 61);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(28), 500_000_000);
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(24 + 16 + first.Length + 4), 500_000_000);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents[0].Status).IsEqualTo(IpReassemblyStatus.Expired);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Identical_bytes_at_different_overlapping_offsets_are_not_duplicates(int version)
    {
        var bytes = new byte[16]; bytes[4] = bytes[12] = 0; bytes[5] = bytes[13] = 24;
        using var stream = Capture(Fragment(version, 0, true, bytes), Fragment(version, 8, true, bytes));
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Header_storage_is_included_in_the_buffer_limit_before_payload_is_accepted()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]));
        using var reader = Open(stream, new(maxBufferedBytes: 83)); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
    }

    [Test]
    public async Task Incompatible_ipv6_flow_context_is_not_silently_combined()
    {
        var tail = Fragment(6, 16, false, Payload[16..]); tail[17] = 1;
        using var stream = Capture(Fragment(6, 0, true, Payload[..16]), tail);
        using var reader = Open(stream); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    public async Task Atomic_tcp_with_exactly_twenty_header_bytes_is_complete()
    {
        var tcp = new byte[20]; tcp[12] = 0x50;
        using var stream = Capture(Fragment(6, 0, false, tcp, nextHeader: 6));
        using var reader = Open(stream); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Atomic);
    }

    [Test]
    public async Task Reconstructed_ipv4_header_checksum_can_be_zero()
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16], 0x65c2), Fragment(4, 16, false, Payload[16..], 0x65c2));
        using var reader = Open(stream); Read(reader); Read(reader);
        var decoding = reader.ReassemblyEvents.Single().Packet!.Decoding;
        var ethernet = decoding is EthernetDecodeResult e && e is DecodedEthernet d ? d : throw new InvalidOperationException();
        var ip = ethernet.Payload is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 ? d4 : throw new InvalidOperationException();
        await Assert.That(ip.Packet.Header.HeaderChecksum).IsEqualTo((ushort)0);
        await Assert.That(ip.Packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
    }

    private static UdpDatagram Udp(IpReassemblyEvent item)
    {
        var ethernet = item.Packet!.Decoding is EthernetDecodeResult e && e is DecodedEthernet d ? d : throw new InvalidOperationException();
        if (ethernet.Payload is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 && d4.Payload is UdpParseResult p4 && p4 is UdpDatagram u4) return u4;
        if (ethernet.Payload is IPv6DecodeResult v6 && v6 is DecodedIPv6 d6 && d6.Payload is UdpParseResult p6 && p6 is UdpDatagram u6) return u6;
        throw new InvalidOperationException("Expected UDP");
    }

    private static PcapAnalysisReader Open(Stream stream, IpReassemblyOptions? options = null) =>
        PcapAnalysisReader.Open(stream, reassemblyOptions: options) is PcapAnalysisReader reader ? reader : throw new InvalidOperationException();
    private static AnalyzedPacket Read(PcapAnalysisReader reader) => reader.ReadNext() is AnalyzedPacket packet ? packet : throw new InvalidOperationException();

    private static byte[] Fragment(int version, int offset, bool more, byte[] payload, ushort id = 1,
        byte nextHeader = 17, bool hopByHop = false)
    {
        var header = version == 4 ? 20 : hopByHop ? 56 : 48;
        var frame = new byte[14 + header + payload.Length];
        frame[12] = version == 4 ? (byte)8 : (byte)0x86; frame[13] = version == 4 ? (byte)0 : (byte)0xdd;
        var ip = frame.AsSpan(14);
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
        payload.CopyTo(frame, 14 + header);
        return frame;
    }

    private static MemoryStream Capture(params byte[][] frames)
    {
        var stream = new MemoryStream();
        stream.Write(Convert.FromHexString("D4C3B2A10200040000000000000000000000020001000000"));
        using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        foreach (var frame in frames)
        {
            writer.Write(1u); writer.Write(0u); writer.Write((uint)frame.Length); writer.Write(65535u); writer.Write(frame);
        }
        stream.Position = 0;
        return stream;
    }

    private static void SetSeconds(MemoryStream stream, int record, uint seconds)
    {
        var bytes = stream.GetBuffer(); var position = 24;
        for (var i = 1; i < record; i++) position += 16 + (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(position + 8));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(position), seconds);
    }
}
