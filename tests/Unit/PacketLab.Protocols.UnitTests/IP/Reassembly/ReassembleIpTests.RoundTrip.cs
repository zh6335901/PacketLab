using System.Buffers.Binary;
using FsCheck;
using FsCheck.Fluent;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Protocols.UnitTests.IP.Reassembly;

public partial class ReassembleIpTests
{
    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Duplicate_boundary_fragments_do_not_fill_a_missing_middle(int version)
    {
        using var reassembler = new IpFragmentReassembler();
        var first = Fragment(version, 0, true, Payload[..8]);
        var last = Fragment(version, 16, false, Payload[16..]);
        await Assert.That(reassembler.Process(first)!.Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(reassembler.Process(last)!.Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(reassembler.Process(first)!.Status).IsEqualTo(IpReassemblyStatus.Duplicate);
        await Assert.That(reassembler.Process(last)!.Status).IsEqualTo(IpReassemblyStatus.Duplicate);
        var complete = reassembler.Process(Fragment(version, 8, true, Payload[8..16]))!;
        await Assert.That(complete.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(Udp(complete).Payload.Span.SequenceEqual(Payload[8..])).IsTrue();
    }

    private sealed record Delivery(int[] Lengths, int[] Order, int? DuplicateAfter, byte[] UdpPayload)
    {
        public override string ToString() =>
            $"lengths=[{string.Join(",", Lengths)}], order=[{string.Join(",", Order)}], " +
            $"duplicateAfter={DuplicateAfter?.ToString() ?? "none"}, payload={Convert.ToHexString(UdpPayload)}";
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Reassembly_restores_the_original_udp_datagram_across_partitions_and_arrival_orders(int version)
    {
        var tailTwiceThenFirst = new Delivery([16, 8], [1, 0], 0, Payload[8..]);
        VerifyDelivery(version, tailTwiceThenFirst);

        var deliveries =
            from count in Gen.Choose(2, 8)
            from blocks in Gen.Choose(1, 4).ArrayOf(count - 1)
            from tailLength in Gen.Choose(1, 24)
            let lengths = blocks.Select(block => block * 8).Append(tailLength).ToArray()
            from order in Gen.Shuffle(Enumerable.Range(0, count))
            from repeat in Gen.Choose(-1, count - 2)
            from payload in Gen.Choose(0, 255).Select(i => (byte)i).ArrayOf(lengths.Sum() - 8)
            select new Delivery(lengths, [.. order], repeat < 0 ? null : repeat, payload);

        Prop.ForAll(Arb.From(deliveries, ShrinkDelivery), (Delivery delivery) => VerifyDelivery(version, delivery))
            .Check(Config.QuickThrowOnFailure.WithMaxTest(1000));
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
    [Arguments(4)]
    [Arguments(6)]
    public void Capture_bytes_after_fragment_declarations_do_not_enter_the_datagram(int version) =>
        Prop.ForAll((byte[] payload, byte[] tail) =>
        {
            byte[] udpPayload = [0xaa, .. payload];
            var original = CreateUdpDatagram(version, udpPayload);
            var fragments = SplitDatagram(version, original, [8, udpPayload.Length]);
            byte[][] padded = fragments.Select(fragment => fragment.Concat(tail).ToArray()).ToArray();
            return Deliver(padded, [1, 0], null).Packet!.Bytes.Span.SequenceEqual(original);
        }).Check(Config.QuickThrowOnFailure);

    private static IEnumerable<Delivery> ShrinkDelivery(Delivery delivery)
    {
        if (delivery.DuplicateAfter.HasValue) yield return delivery with { DuplicateAfter = null };
        if (delivery.Lengths.Length > 2 || delivery.Lengths.Sum() > 9)
        {
            bool tailFirst = delivery.Order[0] != 0;
            yield return new Delivery([8, 1], tailFirst ? [1, 0] : [0, 1],
                delivery.DuplicateAfter.HasValue ? 0 : null, delivery.UdpPayload[..1]);
        }
        if (!delivery.Order.SequenceEqual(delivery.Order.Order()))
            yield return delivery with { Order = [.. delivery.Order.Order()] };
        if (delivery.UdpPayload.Any(b => b != 0))
            yield return delivery with { UdpPayload = new byte[delivery.UdpPayload.Length] };
    }

    private static void VerifyDelivery(int version, Delivery delivery)
    {
        var original = CreateUdpDatagram(version, delivery.UdpPayload);
        var fragments = SplitDatagram(version, original, delivery.Lengths);
        var complete = Deliver(fragments, delivery.Order, delivery.DuplicateAfter);

        if (!complete.Packet!.Bytes.Span.SequenceEqual(original))
            throw new InvalidOperationException("Reassembled bytes differ from the original IP datagram.");
        var decoded = Udp(complete);
        if (!decoded.IsComplete || !decoded.Payload.Span.SequenceEqual(delivery.UdpPayload))
            throw new InvalidOperationException("Decoded UDP payload differs from the original payload.");
    }

    private static byte[] CreateUdpDatagram(int version, byte[] payload)
    {
        var ipHeader = version == 4
            ? Convert.FromHexString("4500000000010000401100000A0000000B000000")
            : Convert.FromHexString("60000000000011400000000000000000000000000000000100000000000000000000000000000002");
        byte[] udp = [0x04, 0xd2, 0x00, 0x35, 0, 0, 0, 0, .. payload];
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(4), (ushort)udp.Length);
        int addressOffset = version == 4 ? 12 : 8;
        int pseudoHeaderSum = WordSum(ipHeader.AsSpan(addressOffset)) + 17 + udp.Length;
        ushort udpChecksum = Complement(pseudoHeaderSum + WordSum(udp));
        BinaryPrimitives.WriteUInt16BigEndian(udp.AsSpan(6), udpChecksum == 0 ? ushort.MaxValue : udpChecksum);
        if (version == 4)
        {
            BinaryPrimitives.WriteUInt16BigEndian(ipHeader.AsSpan(2), (ushort)(ipHeader.Length + udp.Length));
            BinaryPrimitives.WriteUInt16BigEndian(ipHeader.AsSpan(10), Complement(WordSum(ipHeader)));
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(ipHeader.AsSpan(4), (ushort)udp.Length);
        }

        return [.. ipHeader, .. udp];
    }

    private static byte[][] SplitDatagram(int version, ReadOnlySpan<byte> original, int[] lengths)
    {
        int headerLength = version == 4 ? 20 : 40;
        var header = original[..headerLength];
        var payload = original[headerLength..];
        var fragments = new byte[lengths.Length][];
        int offset = 0;
        for (int i = 0; i < lengths.Length; i++)
        {
            var piece = payload.Slice(offset, lengths[i]);
            bool more = i < lengths.Length - 1;
            if (version == 4)
            {
                byte[] fragment = [.. header, .. piece];
                var fragmentHeader = fragment.AsSpan(0, headerLength);
                BinaryPrimitives.WriteUInt16BigEndian(fragmentHeader[2..], (ushort)fragment.Length);
                BinaryPrimitives.WriteUInt16BigEndian(fragmentHeader[6..], (ushort)(offset / 8 | (more ? 0x2000 : 0)));
                fragmentHeader.Slice(10, 2).Clear();
                BinaryPrimitives.WriteUInt16BigEndian(fragmentHeader[10..], Complement(WordSum(fragmentHeader)));
                fragments[i] = fragment;
            }
            else
            {
                // The Fragment header carries the original Next Header and a common identification of 1.
                byte[] fragment = [.. header, header[6], 0, 0, 0, 0, 0, 0, 1, .. piece];
                fragment[6] = 44;
                BinaryPrimitives.WriteUInt16BigEndian(fragment.AsSpan(4), (ushort)(8 + piece.Length));
                BinaryPrimitives.WriteUInt16BigEndian(fragment.AsSpan(headerLength + 2), (ushort)(offset | (more ? 1 : 0)));
                fragments[i] = fragment;
            }
            offset += piece.Length;
        }
        return fragments;
    }

    private static IpReassemblyUpdate Deliver(byte[][] fragments, int[] order, int? duplicateAfter)
    {
        using var reassembler = new IpFragmentReassembler();
        for (int i = 0; i < order.Length - 1; i++)
        {
            var fragment = fragments[order[i]];
            ExpectStatus(reassembler.Process(fragment), IpReassemblyStatus.Pending);
            if (i == duplicateAfter)
                ExpectStatus(reassembler.Process(fragment), IpReassemblyStatus.Duplicate);
        }
        return ExpectStatus(reassembler.Process(fragments[order[^1]]), IpReassemblyStatus.Complete);
    }

    private static IpReassemblyUpdate ExpectStatus(IpReassemblyUpdate? update, IpReassemblyStatus expected) =>
        update?.Status == expected ? update :
            throw new InvalidOperationException($"Expected {expected}, got {update?.Status.ToString() ?? "no update"}.");

    private static int WordSum(ReadOnlySpan<byte> bytes)
    {
        int sum = 0;
        for (int i = 0; i < bytes.Length; i++)
            sum += i % 2 == 0 ? bytes[i] << 8 : bytes[i];
        return sum;
    }

    private static ushort Complement(int sum)
    {
        while (sum > ushort.MaxValue) sum = (sum & ushort.MaxValue) + (sum >> 16);
        return (ushort)~sum;
    }
}
