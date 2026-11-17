using FsCheck;
using FsCheck.Fluent;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Analysis.UnitTests.IpReassembly;

public partial class AnalyzeIpReassemblyTests
{
    [Test]
    public async Task Out_of_order_fragments_preserve_bytes_and_nonconsecutive_record_numbers()
    {
        using var analyzer = new IpReassemblyAnalyzer();
        var tail = IPv4Fragment(16, false, Payload[16..]);
        var first = IPv4Fragment(0, true, Payload[..16]);
        analyzer.AddIPv4Fragment(100, tail.Bytes, tail.Packet, tail.Payload);

        var complete = analyzer.AddIPv4Fragment(102, first.Bytes, first.Packet, first.Payload).Single();

        await Assert.That(complete.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(complete.DatagramNumber).IsEqualTo(100L);
        await Assert.That(complete.RecordNumbers.SequenceEqual(new long[] { 100, 102 })).IsTrue();
        await Assert.That(complete.Packet!.Bytes.Span[20..].SequenceEqual(Payload)).IsTrue();
    }

    [Test]
    public async Task IPv6_fragments_preserve_record_associations_and_payload()
    {
        using var analyzer = new IpReassemblyAnalyzer();
        var tail = IPv6Fragment(16, false, Payload[16..]);
        var first = IPv6Fragment(0, true, Payload[..16]);
        analyzer.AddIPv6Fragment(1, tail.Bytes, tail.Packet, tail.Extension, tail.Fragment);

        var complete = analyzer.AddIPv6Fragment(3, first.Bytes, first.Packet, first.Extension, first.Fragment).Single();

        await Assert.That(complete.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(complete.RecordNumbers.SequenceEqual(new long[] { 1, 3 })).IsTrue();
        await Assert.That(complete.Packet!.Bytes.Span[40..].SequenceEqual(Payload)).IsTrue();
    }

    [Test]
    public void Interleaved_identities_keep_their_own_records() =>
        Prop.ForAll((byte count, byte[] order) =>
        {
            int total = 2 + count % 7;
            using var analyzer = new IpReassemblyAnalyzer();
            for (int i = 0; i < total; i++)
            {
                var first = IPv4Fragment(0, true, Payload[..16], (ushort)(i + 1));
                analyzer.AddIPv4Fragment(i + 1, first.Bytes, first.Packet, first.Payload);
            }
            var ids = Enumerable.Range(1, total).OrderBy(id => order.ElementAtOrDefault(id - 1)).ToArray();
            for (int i = 0; i < total; i++)
            {
                var tail = IPv4Fragment(16, false, Payload[16..], (ushort)ids[i]);
                var complete = analyzer.AddIPv4Fragment(total + i + 1, tail.Bytes, tail.Packet, tail.Payload).Single();
                if (complete.Status != IpReassemblyStatus.Complete || complete.DatagramNumber != ids[i] ||
                    !complete.RecordNumbers.SequenceEqual(new long[] { ids[i], total + i + 1 }))
                    return false;
            }

            return true;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task Duplicate_records_are_included_in_the_completed_datagram()
    {
        using var analyzer = new IpReassemblyAnalyzer();
        var first = IPv4Fragment(0, true, Payload[..16]);
        var tail = IPv4Fragment(16, false, Payload[16..]);
        analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);
        var duplicate = analyzer.AddIPv4Fragment(2, first.Bytes, first.Packet, first.Payload).Single();

        var complete = analyzer.AddIPv4Fragment(3, tail.Bytes, tail.Packet, tail.Payload).Single();

        await Assert.That(duplicate.Status).IsEqualTo(IpReassemblyStatus.Duplicate);
        await Assert.That(complete.RecordNumbers.SequenceEqual(new long[] { 1, 2, 3 })).IsTrue();
    }

    [Test]
    public void Duplicate_flood_bounds_retained_record_associations() =>
        Prop.ForAll((byte size, byte extra) =>
        {
            int limit = 1 + size % 16;
            int preceding = limit + extra % 8;
            var fragment = IPv4Fragment(0, true, Payload[..16]);
            using var analyzer = new IpReassemblyAnalyzer(new(maxRecordsPerDatagram: limit));
            for (int i = 1; i <= preceding; i++)
                analyzer.AddIPv4Fragment(i, fragment.Bytes, fragment.Packet, fragment.Payload);
            long[] expected = preceding == limit ? Enumerable.Range(1, limit + 1).Select(i => (long)i).ToArray() : [preceding + 1];

            var events = analyzer.AddIPv4Fragment(preceding + 1, fragment.Bytes, fragment.Packet, fragment.Payload);

            return events.All(item => item.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit
                    && item.RecordNumbers.Length <= limit)
                && events.SelectMany(item => item.RecordNumbers).Order().SequenceEqual(expected);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task Record_limit_discards_a_completing_fragment_and_preserves_the_reason_for_later_records()
    {
        using var analyzer = new IpReassemblyAnalyzer(new(maxRecordsPerDatagram: 1));
        var first = IPv4Fragment(0, true, Payload[..16]);
        var tail = IPv4Fragment(16, false, Payload[16..]);
        analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);

        var discarded = analyzer.AddIPv4Fragment(2, tail.Bytes, tail.Packet, tail.Payload);
        var later = analyzer.AddIPv4Fragment(3, tail.Bytes, tail.Packet, tail.Payload).Single();

        await Assert.That(discarded.SelectMany(item => item.RecordNumbers).Order().SequenceEqual(new long[] { 1, 2 })).IsTrue();
        await Assert.That(discarded.All(item => item.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit && item.Packet is null)).IsTrue();
        await Assert.That(later.Reason).IsEqualTo(IpReassemblyAnalysisReason.RecordAssociationLimit);
        await Assert.That(later.RecordNumbers.SequenceEqual(new long[] { 3 })).IsTrue();
        await Assert.That(analyzer.Finish(IpReassemblyAnalysisReason.EndOfCapture).IsEmpty).IsTrue();
    }

    [Test]
    public async Task Atomic_datagram_does_not_inherit_another_identitys_record_limit()
    {
        using var analyzer = new IpReassemblyAnalyzer(new(maxRecordsPerDatagram: 1));
        var first = IPv4Fragment(0, true, Payload[..16]);
        var tail = IPv4Fragment(16, false, Payload[16..]);
        analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);
        analyzer.AddIPv4Fragment(2, tail.Bytes, tail.Packet, tail.Payload);
        var atomic = IPv6Fragment(0, false, Payload);

        var result = analyzer.AddIPv6Fragment(3, atomic.Bytes, atomic.Packet, atomic.Extension, atomic.Fragment).Single();

        await Assert.That(result.Status).IsEqualTo(IpReassemblyStatus.Atomic);
        await Assert.That(result.RecordNumbers.SequenceEqual(new long[] { 3 })).IsTrue();
    }

    [Test]
    public async Task Conflicted_datagrams_release_prior_associations_and_are_not_reported_again_at_finish()
    {
        using var analyzer = new IpReassemblyAnalyzer();
        var first = IPv4Fragment(0, true, Payload[..16]);
        var overlap = IPv4Fragment(8, true, Payload[8..]);
        var tail = IPv4Fragment(16, false, Payload[16..]);
        analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);
        analyzer.AddIPv4Fragment(2, overlap.Bytes, overlap.Packet, overlap.Payload);

        var later = analyzer.AddIPv4Fragment(3, tail.Bytes, tail.Packet, tail.Payload).Single();
        var finished = analyzer.Finish(IpReassemblyAnalysisReason.EndOfCapture);

        await Assert.That(later.Status).IsEqualTo(IpReassemblyStatus.Conflict);
        await Assert.That(later.RecordNumbers.SequenceEqual(new long[] { 3 })).IsTrue();
        await Assert.That(finished.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments(IpReassemblyAnalysisReason.Aborted)]
    [Arguments(IpReassemblyAnalysisReason.EndOfCapture)]
    [Arguments(IpReassemblyAnalysisReason.EndOfSection)]
    public async Task Finish_reports_pending_records_once_with_the_supplied_reason(IpReassemblyAnalysisReason reason)
    {
        using var analyzer = new IpReassemblyAnalyzer();
        var first = IPv4Fragment(0, true, Payload[..8]);
        var tail = IPv4Fragment(16, false, Payload[16..]);
        analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);
        analyzer.AddIPv4Fragment(3, tail.Bytes, tail.Packet, tail.Payload);

        var ended = analyzer.Finish(reason).Single();

        await Assert.That(ended.Status).IsEqualTo(IpReassemblyStatus.Incomplete);
        await Assert.That(ended.Reason).IsEqualTo(reason);
        await Assert.That(ended.RecordNumbers.SequenceEqual(new long[] { 1, 3 })).IsTrue();
        await Assert.That(analyzer.Finish(reason).IsEmpty).IsTrue();
    }

    [Test]
    public async Task Completed_bytes_survive_disposal()
    {
        var analyzer = new IpReassemblyAnalyzer();
        var first = IPv4Fragment(0, true, Payload[..16]);
        var tail = IPv4Fragment(16, false, Payload[16..]);
        analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);
        var completed = analyzer.AddIPv4Fragment(2, tail.Bytes, tail.Packet, tail.Payload).Single();

        analyzer.Dispose();

        await Assert.That(completed.Packet!.Bytes.Span[20..].SequenceEqual(Payload)).IsTrue();
    }

    [Test]
    public async Task Finish_rejects_non_terminal_reasons()
    {
        using var analyzer = new IpReassemblyAnalyzer();
        Action finish = () => analyzer.Finish(IpReassemblyAnalysisReason.RecordAgeLimit);

        await Assert.That(finish).Throws<ArgumentOutOfRangeException>();
    }
}
