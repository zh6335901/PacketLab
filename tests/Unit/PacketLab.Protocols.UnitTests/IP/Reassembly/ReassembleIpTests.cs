using System.Buffers.Binary;
using FsCheck.Fluent;
using FsCheck;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Protocols.Udp;

namespace PacketLab.Protocols.UnitTests.IP.Reassembly;

public partial class ReassembleIpTests
{
    private static readonly byte[] Payload = Convert.FromHexString("04D20035001800000102030405060708090A0B0C0D0E0F10");

    [Test]
    [Arguments(0)]
    [Arguments(0x40)]
    [Arguments(0x80)]
    [Arguments(0xc0)]
    public async Task Processing_unfragmented_ipv4_returns_no_update_even_when_its_identity_is_pending(byte flags)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        reassembler.Process(Fragment(4, 0, true, Payload[..16]));
        var packet = Fragment(4, 0, false, Payload);
        packet[6] = flags;

        // Act
        var result = reassembler.Process(packet);

        // Assert
        await Assert.That(result).IsNull();
    }

    [Test]
    public async Task Looking_up_unfragmented_ipv4_returns_no_datagram_even_when_its_identity_is_pending()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        reassembler.Process(Fragment(4, 0, true, Payload[..16]));
        var packet = Fragment(4, 0, false, Payload);

        // Act
        var result = reassembler.FindDatagram(packet);

        // Assert
        await Assert.That(result).IsNull();
    }

    [Test]
    public async Task A_final_fragment_completes_the_pending_datagram_after_an_unfragmented_packet_with_the_same_identity()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var pending = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.Process(Fragment(4, 0, false, Payload));

        // Act
        var completed = reassembler.Process(Fragment(4, 16, false, Payload[16..]))!;

        // Assert
        await Assert.That(completed.DatagramId).IsEqualTo(pending.DatagramId);
        await Assert.That(completed.Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public void Processing_truncated_ipv4_headers_returns_no_update() =>
        Prop.ForAll((byte length, bool more) =>
        {
            // Arrange
            using var reassembler = new IpFragmentReassembler();
            var packet = Fragment(4, 0, more, Payload).AsMemory(0, length % 20);

            // Act
            var result = reassembler.Process(packet);

            // Assert
            return result is null;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public void Looking_up_truncated_ipv4_headers_returns_no_datagram() =>
        Prop.ForAll((byte length, bool more) =>
        {
            // Arrange
            using var reassembler = new IpFragmentReassembler();
            var packet = Fragment(4, 0, more, Payload).AsMemory(0, length % 20);

            // Act
            var result = reassembler.FindDatagram(packet);

            // Assert
            return result is null;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(4, 0)]
    [Arguments(4, 1)]
    [Arguments(6, 0)]
    [Arguments(6, 1)]
    public async Task Truncated_datagrams_never_produce_a_packet(int version, int preceding)
    {
        // Arrange
        var packets = Packets(Fragment(version, 0, true, Payload[..16])[..^1], Fragment(version, 16, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets);
        for (int i = 0; i < preceding; i++) sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Truncated);
        await Assert.That(sequence.Updates.Single().Packet).IsNull();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Non_final_fragment_requires_eight_byte_alignment(int version) =>
        Prop.ForAll((byte blocks, byte tail) =>
        {
            // Arrange
            using var reassembler = new IpFragmentReassembler();
            int remainder = 1 + tail % 7;
            var fragment = Fragment(version, 8, true, new byte[(blocks + 1) * 8 + remainder]);

            // Act
            var result = reassembler.Process(fragment);

            // Assert
            return result?.Status == IpReassemblyStatus.Invalid;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Fragment_end_must_fit_the_ip_length_field(int version)
    {
        // Arrange
        var packets = Packets(Fragment(version, 65528, false, Payload[..16]));
        using var sequence = new FragmentSequence(packets);

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Empty_non_atomic_fragment_is_invalid(int version)
    {
        // Arrange
        var packets = Packets(Fragment(version, 16, false, []));
        using var sequence = new FragmentSequence(packets);

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    [Arguments(0x40)]
    [Arguments(0x80)]
    public async Task Invalid_ipv4_fragmentation_flags_are_diagnosed(byte flag)
    {
        // Arrange
        var frame = Fragment(4, 0, true, Payload[..16]);
        frame[6] |= flag;
        var packets = Packets(frame);
        using var sequence = new FragmentSequence(packets);

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    [Arguments(0)]
    [Arguments(1)]
    public async Task IPv6_split_extension_header_invalidates_subsequent_fragments(int preceding)
    {
        // Arrange
        var incompleteDestination = new byte[] { 17, 1, 0, 0, 0, 0, 0, 0 };
        var packets = Packets(Fragment(6, 0, true, incompleteDestination, nextHeader: 60),
            Fragment(6, 8, false, Payload, nextHeader: 60));
        using var sequence = new FragmentSequence(packets);
        for (int i = 0; i < preceding; i++) sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
        await Assert.That(sequence.Updates.Single().Packet).IsNull();
    }

    [Test]
    public async Task IPv6_hop_by_hop_after_fragment_is_invalid_even_when_reconstruction_would_move_it_first()
    {
        // Arrange
        var payload = new byte[] { 17, 0, 0, 0, 0, 0, 0, 0 }.Concat(Payload[..8]).ToArray();
        var packets = Packets(Fragment(6, 0, true, payload, nextHeader: 0));
        using var sequence = new FragmentSequence(packets);

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    [Arguments(16, 5, IpReassemblyStatus.Invalid)]
    [Arguments(24, 4, IpReassemblyStatus.Invalid)]
    [Arguments(24, 7, IpReassemblyStatus.Invalid)]
    [Arguments(24, 6, IpReassemblyStatus.Pending)]
    [Arguments(24, 5, IpReassemblyStatus.Pending)]
    public async Task IPv6_first_fragment_must_contain_the_whole_tcp_header(int length, byte dataOffset, IpReassemblyStatus status)
    {
        // Arrange
        var tcp = new byte[length];
        tcp[12] = (byte)(dataOffset << 4);
        var packets = Packets(Fragment(6, 0, true, tcp, nextHeader: 6));
        using var sequence = new FragmentSequence(packets);

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(status);
    }

    [Test]
    public async Task Atomic_tcp_with_exactly_twenty_header_bytes_is_complete()
    {
        // Arrange
        var tcp = new byte[20];
        tcp[12] = 0x50;
        var packets = Packets(Fragment(6, 0, false, tcp, nextHeader: 6));
        using var sequence = new FragmentSequence(packets);

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Atomic);
    }

    [Test]
    public async Task IPv6_extension_headers_before_and_after_fragment_survive_reassembly()
    {
        // Arrange
        var withDestination = new byte[] { 17, 0, 0, 0, 0, 0, 0, 0 }.Concat(Payload).ToArray();
        var packets = Packets(Fragment(6, 24, false, withDestination[24..], nextHeader: 60, hopByHop: true),
            Fragment(6, 0, true, withDestination[..24], nextHeader: 60, hopByHop: true));
        using var sequence = new FragmentSequence(packets);
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        var result = sequence.Updates.Single();
        await Assert.That(result.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(result.Packet!.Bytes.Span[40]).IsEqualTo((byte)60);
        await Assert.That(result.Packet.Bytes.Span[48..56].SequenceEqual(withDestination[..8])).IsTrue();
        await Assert.That(Udp(result).Payload.Span.SequenceEqual(Payload[8..])).IsTrue();
    }

    [Test]
    [Arguments(1, IpReassemblyStatus.ResourceLimit, 2L)]
    [Arguments(2, IpReassemblyStatus.Complete, 1L)]
    public async Task Full_datagram_table_rejects_new_identities_but_accepts_existing_fragments(
        int preceding, IpReassemblyStatus expected, long datagramId)
    {
        // Arrange
        var packets = Packets(Fragment(4, 0, true, Payload[..16]), Fragment(4, 0, true, Payload[..16], 2),
            Fragment(4, 16, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets, new(maxDatagrams: 1));
        for (int i = 0; i < preceding; i++) sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(expected);
        await Assert.That(sequence.Updates.Single().DatagramId).IsEqualTo(datagramId);
    }

    [Test]
    [Arguments(1, IpReassemblyStatus.ResourceLimit)]
    [Arguments(2, IpReassemblyStatus.Pending)]
    public async Task Buffer_limit_failure_releases_capacity_for_another_datagram(int preceding, IpReassemblyStatus expected)
    {
        // Arrange
        var packets = Packets(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]),
            Fragment(4, 16, false, Payload[16..], 2));
        using var sequence = new FragmentSequence(packets, new(maxBufferedBytes: 56));
        for (int i = 0; i < preceding; i++) sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(expected);
    }

    [Test]
    public async Task Single_datagram_limit_is_reported_before_buffering()
    {
        // Arrange
        var packets = Packets(Fragment(4, 16, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets, new(maxDatagramBytes: 40));

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
    }

    [Test]
    public async Task Reassembly_preserves_unavailable_ipv6_routing_checksum_context()
    {
        // Arrange
        var first = Fragment(6, 0, true, Payload[..16], hopByHop: true);
        var tail = Fragment(6, 16, false, Payload[16..], hopByHop: true);
        first[6] = tail[6] = 43;
        first[43] = tail[43] = 1;
        first[62] = 0x12;
        first[63] = 0x34;
        var packets = Packets(first, tail);
        using var sequence = new FragmentSequence(packets);
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(Udp(sequence.Updates.Single()).Checksum is UdpChecksumUnavailable
        { Reason: UdpUnavailableReason.PseudoHeaderUnavailable }).IsTrue();
    }

    [Test]
    public async Task Completion_releases_bytes_for_the_next_datagram()
    {
        // Arrange
        var packets = Packets(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]),
            Fragment(4, 0, true, Payload[..16], 2), Fragment(4, 16, false, Payload[16..], 2));
        using var sequence = new FragmentSequence(packets, new(maxBufferedBytes: 64));
        sequence.Next();
        sequence.Next();
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Ipv4_offset_zero_options_are_preserved_when_the_first_fragment_arrives_late()
    {
        // Arrange
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..20].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[20..]).ToArray();
        first[0] = 0x46;
        first[3] += 4;
        var packets = Packets(Fragment(4, 16, false, Payload[16..]), first);
        using var sequence = new FragmentSequence(packets);
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        var frame = sequence.Updates.Single().Packet!.Bytes;
        await Assert.That(frame.Span[20..24].SequenceEqual(new byte[] { 1, 1, 0, 0 })).IsTrue();
        await Assert.That(Udp(sequence.Updates.Single()).IsComplete).IsTrue();
    }

    [Test]
    public async Task Maximum_ipv4_length_is_accepted_with_a_valid_rewritten_header_checksum()
    {
        // Act
        var item = MaximumDatagram(4, 65515);

        // Assert
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
        // Act
        var item = MaximumDatagram(6, 65535);

        // Assert
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
        // Arrange
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..20].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[20..]).ToArray();
        first[0] = 0x46;
        first[3] += 4;
        var packets = Packets(Fragment(4, 16, false, new byte[65499]), first);
        using var sequence = new FragmentSequence(packets);
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Invalid);
    }

    [Test]
    public async Task Configured_size_limit_includes_a_late_first_header_with_options()
    {
        // Arrange
        var first = Fragment(4, 0, true, Payload[..16]);
        first = first[..20].Concat(new byte[] { 1, 1, 0, 0 }).Concat(first[20..]).ToArray();
        first[0] = 0x46;
        first[3] += 4;
        var packets = Packets(Fragment(4, 16, false, Payload[16..]), first);
        using var sequence = new FragmentSequence(packets, new(maxDatagramBytes: 44));
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
    }

    [Test]
    public async Task Datagram_exactly_at_configured_size_limit_completes()
    {
        // Arrange
        var packets = Packets(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]));
        using var sequence = new FragmentSequence(packets, new(maxDatagramBytes: 44));
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public async Task Aggregate_buffer_limit_applies_across_distinct_datagrams()
    {
        // Arrange
        var packets = Packets(Fragment(4, 16, false, Payload[16..]), Fragment(4, 16, false, Payload[16..], 2));
        using var sequence = new FragmentSequence(packets, new(maxBufferedBytes: 55));
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        var item = sequence.Updates.Single();
        await Assert.That(item.Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
        await Assert.That(item.DatagramId).IsEqualTo(2L);
    }

    [Test]
    public async Task Header_storage_is_included_in_the_buffer_limit_before_payload_is_accepted()
    {
        // Arrange
        var packets = Packets(Fragment(4, 0, true, Payload[..16]));
        using var sequence = new FragmentSequence(packets, new(maxBufferedBytes: 55));

        // Act
        sequence.Next();

        // Assert
        await Assert.That(sequence.Updates.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
    }

    [Test]
    public async Task Reconstructed_ipv4_header_checksum_can_be_zero()
    {
        // Arrange
        var packets = Packets(Fragment(4, 0, true, Payload[..16], 0x65c2), Fragment(4, 16, false, Payload[16..], 0x65c2));
        using var sequence = new FragmentSequence(packets);
        sequence.Next();

        // Act
        sequence.Next();

        // Assert
        var decoding = sequence.Updates.Single().Packet!.Decoding;
        var ip = decoding is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 ? d4 : throw new InvalidOperationException();
        await Assert.That(ip.Packet.Header.HeaderChecksum).IsEqualTo((ushort)0);
        await Assert.That(ip.Packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
    }

    [Test]
    [Arguments(0, 0, 0, false)]
    [Arguments(0, 0, 0, true)]
    [Arguments(1, 1, 1, false)]
    [Arguments(1, 1, 1, true)]
    [Arguments(2, 2, 2, false)]
    [Arguments(2, 2, 2, true)]
    [Arguments(3, 3, 3, false)]
    [Arguments(3, 3, 3, true)]
    [Arguments(2, 3, 3, false)]
    [Arguments(2, 3, 3, true)]
    [Arguments(3, 2, 3, false)]
    [Arguments(3, 2, 3, true)]
    [Arguments(1, 3, 3, false)]
    [Arguments(1, 3, 3, true)]
    [Arguments(3, 1, 3, false)]
    [Arguments(3, 1, 3, true)]
    public async Task IPv4_reassembly_preserves_ecn_and_recalculates_checksum_in_either_arrival_order(
        byte firstEcn, byte tailEcn, byte expected, bool tailArrivesFirst)
    {
        // Arrange
        var first = Fragment(4, 0, true, Payload[..16]);
        first[1] = (byte)(0xa8 | firstEcn);
        var tail = Fragment(4, 16, false, Payload[16..]);
        tail[1] = tailEcn;
        var packets = tailArrivesFirst ? new[] { tail, first } : new[] { first, tail };
        using var reassembler = new IpFragmentReassembler();
        reassembler.Process(packets[0]);

        // Act
        var complete = reassembler.Process(packets[1])!;

        // Assert
        var decoding = complete.Packet!.Decoding;
        var ip = decoding is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 ? d4.Packet : throw new InvalidOperationException();
        await Assert.That(ip.Header.Ecn).IsEqualTo(expected);
        await Assert.That(ip.Header.Dscp).IsEqualTo((byte)42);
        await Assert.That(ip.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
    }

    [Test]
    public async Task IPv4_duplicate_fragment_contributes_its_ce_marking()
    {
        // Arrange
        var first = Fragment(4, 0, true, Payload[..16]);
        first[1] = 2;
        var duplicate = first.ToArray();
        duplicate[1] = 3;
        var tail = Fragment(4, 16, false, Payload[16..]);
        tail[1] = 2;
        using var reassembler = new IpFragmentReassembler();
        reassembler.Process(first);
        reassembler.Process(duplicate);

        // Act
        var complete = reassembler.Process(tail)!;

        // Assert
        await Assert.That(complete.Packet!.Bytes.Span[1] & 3).IsEqualTo(3);
    }

    [Test]
    [Arguments(0, 3, 1)]
    [Arguments(3, 0, 1)]
    [Arguments(0, 3, 2)]
    [Arguments(3, 0, 2)]
    public async Task IPv4_ce_and_not_ect_fragments_discard_the_identity(byte firstEcn, byte tailEcn, int preceding)
    {
        // Arrange
        var first = Fragment(4, 0, true, Payload[..16]);
        first[1] = firstEcn;
        var tail = Fragment(4, 16, false, Payload[16..]);
        tail[1] = tailEcn;
        byte[][] packets = [first, tail, first];
        using var reassembler = new IpFragmentReassembler();
        for (int i = 0; i < preceding; i++) reassembler.Process(packets[i]);

        // Act
        var result = reassembler.Process(packets[preceding]);

        // Assert
        await Assert.That(result!.Status).IsEqualTo(IpReassemblyStatus.Conflict);
    }

    [Test]
    [Arguments(1, IpReassemblyStatus.Duplicate)]
    [Arguments(2, IpReassemblyStatus.ResourceLimit)]
    public async Task Fragment_limit_counts_new_fragments_but_ignores_duplicates(int preceding, IpReassemblyStatus expected)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler(new(maxFragmentsPerDatagram: 1));
        var first = Fragment(4, 0, true, Payload[..16]);
        byte[][] packets = [first, first, Fragment(4, 16, false, Payload[16..])];
        for (int i = 0; i < preceding; i++) reassembler.Process(packets[i]);

        // Act
        var result = reassembler.Process(packets[preceding]);

        // Assert
        await Assert.That(result!.Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments(60_999_999_999UL, false)]
    [Arguments(61_000_000_000UL, true)]
    public async Task Supplied_time_expires_pending_and_discarded_identities_at_the_boundary(ulong time, bool expires)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler(new(maxDatagrams: 2));
        reassembler.AdvanceTime(1_000_000_000);
        reassembler.Expire();
        var first = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        var second = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;
        reassembler.Discard(second.DatagramId);
        long[] expected = expires ? [first.DatagramId, second.DatagramId] : [];

        // Act
        reassembler.AdvanceTime(time);
        var expired = reassembler.Expire();

        // Assert
        await Assert.That(expired.Select(x => x.DatagramId).ToArray()).IsEquivalentTo(expected);
        await Assert.That(expired.All(x => x.Status == IpReassemblyStatus.Expired)).IsTrue();
    }

    [Test]
    public async Task Timed_out_tombstone_is_no_longer_retained()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var pending = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.Discard(pending.DatagramId);
        reassembler.AdvanceTime(60_000_000_000);
        reassembler.Expire();

        // Act
        var retained = reassembler.IsRetained(pending.DatagramId);

        // Assert
        await Assert.That(retained).IsFalse();
    }

    [Test]
    [Arguments(false, IpReassemblyStatus.Discarded)]
    [Arguments(true, IpReassemblyStatus.Pending)]
    public async Task Processing_a_discarded_identity_depends_on_whether_it_has_expired(bool expired, IpReassemblyStatus expected)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var first = reassembler.Process(Fragment(6, 0, true, Payload[..16]))!;
        reassembler.Discard(first.DatagramId);
        if (expired) reassembler.Expire(first.DatagramId);
        var tail = Fragment(6, 16, false, Payload[16..]);

        // Act
        var result = reassembler.Process(tail);

        // Assert
        await Assert.That(result!.Status).IsEqualTo(expected);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Lookup_finds_a_tombstone_only_until_it_expires(bool expired)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var first = reassembler.Process(Fragment(6, 0, true, Payload[..16]))!;
        reassembler.Discard(first.DatagramId);
        if (expired) reassembler.Expire(first.DatagramId);
        var tail = Fragment(6, 16, false, Payload[16..]);
        long? expected = expired ? null : first.DatagramId;

        // Act
        var result = reassembler.FindDatagram(tail);

        // Assert
        await Assert.That(result).IsEqualTo(expected);
    }

    [Test]
    public async Task Caller_buffer_mutation_does_not_change_reassembled_bytes()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var first = Fragment(4, 0, true, Payload[..16]);
        reassembler.Process(first);
        Array.Fill(first, (byte)0xff);

        // Act
        var completed = reassembler.Process(Fragment(4, 16, false, Payload[16..]))!;

        // Assert
        await Assert.That(completed.Packet!.Bytes.Span[20..].SequenceEqual(Payload)).IsTrue();
    }

    [Test]
    public async Task Disposal_does_not_change_previously_returned_bytes()
    {
        // Arrange
        var reassembler = new IpFragmentReassembler();
        reassembler.Process(Fragment(4, 0, true, Payload[..16]));
        var completed = reassembler.Process(Fragment(4, 16, false, Payload[16..]))!;

        // Act
        reassembler.Dispose();

        // Assert
        await Assert.That(completed.Packet!.Bytes.Span[20..].SequenceEqual(Payload)).IsTrue();
    }

    [Test]
    public async Task Finish_reports_missing_bytes_without_assuming_a_capture_end_reason()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        reassembler.Process(Fragment(4, 16, false, Payload[16..]));

        // Act
        var result = reassembler.Finish();

        // Assert
        await Assert.That(result.Single().Status).IsEqualTo(IpReassemblyStatus.Incomplete);
    }

    [Test]
    public async Task Finished_datagrams_are_no_longer_retained()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var pending = reassembler.Process(Fragment(4, 16, false, Payload[16..]))!;
        reassembler.Finish();

        // Act
        var retained = reassembler.IsRetained(pending.DatagramId);

        // Assert
        await Assert.That(retained).IsFalse();
    }

    [Test]
    public async Task Finishing_an_already_finished_reassembler_returns_no_updates()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        reassembler.Process(Fragment(4, 16, false, Payload[16..]));
        reassembler.Finish();

        // Act
        var result = reassembler.Finish();

        // Assert
        await Assert.That(result.IsEmpty).IsTrue();
    }

    private static IpReassemblyUpdate MaximumDatagram(int version, int payloadLength)
    {
        var payload = new byte[payloadLength];
        Payload.CopyTo(payload, 0);
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
    public async Task Explicit_expiry_reports_the_requested_identity()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        reassembler.Process(Fragment(4, 0, true, Payload[..16], 1));
        var second = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;

        // Act
        var result = reassembler.Expire(second.DatagramId);

        // Assert
        await Assert.That(result!.DatagramId).IsEqualTo(second.DatagramId);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Explicit_expiry_only_removes_the_selected_identity(bool selected)
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var first = reassembler.Process(Fragment(4, 0, true, Payload[..16], 1))!;
        var second = reassembler.Process(Fragment(4, 0, true, Payload[..16], 2))!;
        reassembler.Expire(second.DatagramId);
        long id = selected ? second.DatagramId : first.DatagramId;

        // Act
        var retained = reassembler.IsRetained(id);

        // Assert
        await Assert.That(retained).IsEqualTo(!selected);
    }

    [Test]
    public async Task Expiring_an_already_expired_identity_returns_no_update()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var pending = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.Expire(pending.DatagramId);

        // Act
        var result = reassembler.Expire(pending.DatagramId);

        // Assert
        await Assert.That(result).IsNull();
    }

    [Test]
    public async Task Discarding_an_expired_identity_returns_no_update()
    {
        // Arrange
        using var reassembler = new IpFragmentReassembler();
        var pending = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.Expire(pending.DatagramId);

        // Act
        var result = reassembler.Discard(pending.DatagramId);

        // Assert
        await Assert.That(result).IsNull();
    }

    [Test]
    public async Task Disposed_reassembler_retains_no_identities()
    {
        // Arrange
        var reassembler = new IpFragmentReassembler();
        var first = reassembler.Process(Fragment(4, 0, true, Payload[..16]))!;
        reassembler.Dispose();

        // Act
        var retained = reassembler.IsRetained(first.DatagramId);

        // Assert
        await Assert.That(retained).IsFalse();
    }

    [Test]
    public async Task Processing_after_disposal_throws()
    {
        // Arrange
        var reassembler = new IpFragmentReassembler();
        reassembler.Dispose();

        // Act
        Action act = () => reassembler.Process(Fragment(4, 0, true, Payload[..16]));

        // Assert
        await Assert.That(act).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Advancing_time_after_disposal_throws()
    {
        // Arrange
        var reassembler = new IpFragmentReassembler();
        reassembler.Dispose();

        // Act
        Action act = () => reassembler.AdvanceTime(1);

        // Assert
        await Assert.That(act).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Expiring_after_disposal_throws()
    {
        // Arrange
        var reassembler = new IpFragmentReassembler();
        reassembler.Dispose();

        // Act
        Action act = () => reassembler.Expire(1);

        // Assert
        await Assert.That(act).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Discarding_after_disposal_throws()
    {
        // Arrange
        var reassembler = new IpFragmentReassembler();
        reassembler.Dispose();

        // Act
        Action act = () => reassembler.Discard(1);

        // Assert
        await Assert.That(act).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Looking_up_after_disposal_throws()
    {
        // Arrange
        var reassembler = new IpFragmentReassembler();
        reassembler.Dispose();

        // Act
        Action act = () => reassembler.FindDatagram(ReadOnlyMemory<byte>.Empty);

        // Assert
        await Assert.That(act).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Finishing_after_disposal_throws()
    {
        // Arrange
        var reassembler = new IpFragmentReassembler();
        reassembler.Dispose();

        // Act
        Action act = () => reassembler.Finish();

        // Assert
        await Assert.That(act).Throws<ObjectDisposedException>();
    }

    // Feeds explicit IP byte arrays into the public reassembler, with no capture format or link layer.
    private sealed class FragmentSequence(byte[][] packets, IpReassemblyOptions? options = null) : IDisposable
    {
        private readonly IpFragmentReassembler reassembler = new(options);
        private int index;
        internal System.Collections.Immutable.ImmutableArray<IpReassemblyUpdate> Updates { get; private set; } = [];
        internal void Next()
        {
            if (index == packets.Length)
            {
                Updates = reassembler.Finish();
                return;
            }

            Updates = reassembler.Process(packets[index++]) is { } update ? [update] : [];
        }

        public void Dispose() => reassembler.Dispose();
    }

    private static byte[] Fragment(int version, int offset, bool more, byte[] payload, ushort id = 1,
        byte nextHeader = 17, bool hopByHop = false)
    {
        var header = version switch
        {
            4 => 20,
            _ when hopByHop => 56,
            _ => 48
        };
        var frame = new byte[header + payload.Length];
        var ip = frame.AsSpan();
        if (version == 4)
        {
            ip[0] = 0x45;
            ip[8] = 64;
            ip[9] = nextHeader;
            ip[12] = 10;
            ip[16] = 11;
            BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)(20 + payload.Length));
            BinaryPrimitives.WriteUInt16BigEndian(ip[4..], id);
            BinaryPrimitives.WriteUInt16BigEndian(ip[6..], (ushort)(offset / 8 | (more ? 0x2000 : 0)));
        }
        else
        {
            ip[0] = 0x60;
            ip[6] = hopByHop ? (byte)0 : (byte)44;
            ip[7] = 64;
            ip[23] = 1;
            ip[39] = 2;
            BinaryPrimitives.WriteUInt16BigEndian(ip[4..], (ushort)(header - 40 + payload.Length));
            if (hopByHop)
                ip[40] = 44;
            var fragment = ip[(header - 8)..];
            fragment[0] = nextHeader;
            BinaryPrimitives.WriteUInt16BigEndian(fragment[2..], (ushort)(offset | (more ? 1 : 0)));
            BinaryPrimitives.WriteUInt32BigEndian(fragment[4..], id);
        }
        payload.CopyTo(frame, header);
        return frame;
    }
}
