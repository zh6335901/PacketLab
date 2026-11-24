using FsCheck;
using FsCheck.Fluent;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Analysis.UnitTests.IpReassembly;

public partial class AnalyzeIpReassemblyTests
{
    [Test]
    public async Task Advancing_time_and_adding_fragments_do_not_implicitly_expire_state()
    {
        using var analyzer = new IpReassemblyAnalyzer(new(maxRecordAge: 2, reassembly: IpReassemblyOptions.Default, maxRecordsPerDatagram: 1024));
        var first = IPv4Fragment(0, true, Payload[..16]);
        var tail = IPv4Fragment(16, false, Payload[16..]);
        analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);

        analyzer.AdvanceTime(60_000_000_000);
        var completed = analyzer.AddIPv4Fragment(100, tail.Bytes, tail.Packet, tail.Payload).Single();

        await Assert.That(completed.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(completed.RecordNumbers.SequenceEqual(new long[] { 1, 100 })).IsTrue();
    }

    [Test]
    public void Duplicate_arrivals_never_extend_the_original_deadline() =>
        Prop.ForAll((byte[] delays, ushort start) =>
        {
            var times = delays.Take(24).Select(t => t % 60).Append(59).Order().ToArray();
            var first = IPv4Fragment(0, true, Payload[..16]);
            using var analyzer = new IpReassemblyAnalyzer(IpReassemblyAnalysisOptions.Default);
            analyzer.AdvanceTime((ulong)start * 1_000_000_000);
            analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);
            for (int i = 0; i < times.Length; i++)
            {
                analyzer.AdvanceTime((ulong)(start + times[i]) * 1_000_000_000);
                if (!analyzer.Expire(i + 2).IsEmpty)
                    return false;

                analyzer.AddIPv4Fragment(i + 2, first.Bytes, first.Packet, first.Payload);
            }

            analyzer.AdvanceTime((ulong)(start + 60) * 1_000_000_000);
            var expired = analyzer.Expire(times.Length + 2).Single();

            return expired.Status == IpReassemblyStatus.Expired && expired.DatagramNumber == 1
                && expired.RecordNumbers.Count() == times.Length + 1;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task Record_age_expiry_removes_associations_without_advancing_time()
    {
        using var analyzer = new IpReassemblyAnalyzer(new(maxRecordAge: 2, reassembly: IpReassemblyOptions.Default, maxRecordsPerDatagram: 1024));
        var first = IPv4Fragment(0, true, Payload[..16]);
        var tail = IPv4Fragment(16, false, Payload[16..]);
        analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);
        var before = analyzer.Expire(2);

        var expired = analyzer.Expire(3).Single();
        var added = analyzer.AddIPv4Fragment(3, tail.Bytes, tail.Packet, tail.Payload).Single();

        await Assert.That(before.IsEmpty).IsTrue();
        await Assert.That(expired.Reason).IsEqualTo(IpReassemblyAnalysisReason.RecordAgeLimit);
        await Assert.That(expired.RecordNumbers.SequenceEqual(new long[] { 1 })).IsTrue();
        await Assert.That(added.Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(added.DatagramNumber).IsEqualTo(3L);
    }

    [Test]
    public void Reordered_timestamps_never_underflow_the_expiry_clock() =>
        Prop.ForAll((DoNotSize<uint> firstTime, DoNotSize<uint> decrease) =>
        {
            uint high = Math.Max(1u, firstTime.Item);
            uint low = high - 1 - decrease.Item % high;
            var first = IPv4Fragment(0, true, Payload[..16]);
            var tail = IPv4Fragment(16, false, Payload[16..]);
            using var analyzer = new IpReassemblyAnalyzer(IpReassemblyAnalysisOptions.Default);
            analyzer.AdvanceTime((ulong)high * 1_000_000_000);
            analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);

            analyzer.AdvanceTime((ulong)low * 1_000_000_000);
            var expired = analyzer.Expire(2);
            var completed = analyzer.AddIPv4Fragment(2, tail.Bytes, tail.Packet, tail.Payload).Single();

            return expired.IsEmpty && completed.Status == IpReassemblyStatus.Complete;
        }).Check(Config.QuickThrowOnFailure);
    [Test]
    public async Task Expiry_releases_discarded_record_associations_before_reusing_the_identity()
    {
        using var analyzer = new IpReassemblyAnalyzer(new(maxRecordsPerDatagram: 1, reassembly: IpReassemblyOptions.Default, maxRecordAge: 100000));
        var first = IPv4Fragment(0, true, Payload[..16]);
        analyzer.AddIPv4Fragment(1, first.Bytes, first.Packet, first.Payload);
        analyzer.AddIPv4Fragment(2, first.Bytes, first.Packet, first.Payload);

        analyzer.AdvanceTime(60_000_000_000);
        var expired = analyzer.Expire(3);
        var restarted = analyzer.AddIPv4Fragment(3, first.Bytes, first.Packet, first.Payload).Single();

        await Assert.That(expired.IsEmpty).IsTrue();
        await Assert.That(restarted.Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(restarted.Reason).IsEqualTo(IpReassemblyAnalysisReason.Protocol);
        await Assert.That(restarted.DatagramNumber).IsEqualTo(3L);
    }

}
