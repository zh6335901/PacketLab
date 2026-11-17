using PacketLab.Analysis.IpReassembly;
using PacketLab.Protocols;
using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Testing;

namespace PacketLab.Analysis.UnitTests.IpReassembly;

public partial class AnalyzeIpReassemblyTests
{
    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Advancing_time_and_adding_a_fragment_do_not_implicitly_expire_state(int version)
    {
        using var analyzer = new IpReassemblyAnalyzer(new(maxRecordAge: 2));
        var first = ProtocolDecoder.Decode(Fragment(version, 0, true, Payload[..16]), LinkLayerProtocol.Ethernet);
        var tail = ProtocolDecoder.Decode(Fragment(version, 16, false, Payload[16..]), LinkLayerProtocol.Ethernet);
        ReassemblySteps.Add(analyzer, 1, first);

        analyzer.AdvanceTime(60_000_000_000);
        var completed = ReassemblySteps.Add(analyzer, 100, tail).Single();

        await Assert.That(completed.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(completed.RecordNumbers.SequenceEqual(new long[] { 1, 100 })).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Explicit_expiry_removes_old_fragments_before_accepting_new_ones(int version)
    {
        using var analyzer = new IpReassemblyAnalyzer();
        var first = ProtocolDecoder.Decode(Fragment(version, 0, true, Payload[..16]), LinkLayerProtocol.Ethernet);
        var tail = ProtocolDecoder.Decode(Fragment(version, 16, false, Payload[16..]), LinkLayerProtocol.Ethernet);
        ReassemblySteps.Add(analyzer, 1, first);
        analyzer.AdvanceTime(60_000_000_000);

        var expired = analyzer.Expire(2).Single();
        var added = ReassemblySteps.Add(analyzer, 2, tail).Single();

        await Assert.That(expired.Status).IsEqualTo(IpReassemblyStatus.Expired);
        await Assert.That(expired.RecordNumbers.SequenceEqual(new long[] { 1 })).IsTrue();
        await Assert.That(added.Status).IsEqualTo(IpReassemblyStatus.Pending);
        await Assert.That(added.DatagramNumber).IsEqualTo(2L);
    }

    [Test]
    public async Task Explicit_record_expiry_does_not_require_a_timestamp()
    {
        using var analyzer = new IpReassemblyAnalyzer(new(maxRecordAge: 2));
        var first = ProtocolDecoder.Decode(Fragment(4, 0, true, Payload[..16]), LinkLayerProtocol.Ethernet);
        ReassemblySteps.Add(analyzer, 1, first);

        var before = analyzer.Expire(2);
        var expired = analyzer.Expire(3).Single();

        await Assert.That(before.IsEmpty).IsTrue();
        await Assert.That(expired.Reason).IsEqualTo(IpReassemblyAnalysisReason.RecordAgeLimit);
    }

    [Test]
    [Arguments(IpReassemblyAnalysisReason.Aborted)]
    [Arguments(IpReassemblyAnalysisReason.EndOfCapture)]
    [Arguments(IpReassemblyAnalysisReason.EndOfSection)]
    public async Task Explicit_finish_reports_pending_records_once(IpReassemblyAnalysisReason reason)
    {
        using var analyzer = new IpReassemblyAnalyzer();
        var first = ProtocolDecoder.Decode(Fragment(4, 0, true, Payload[..16]), LinkLayerProtocol.Ethernet);
        ReassemblySteps.Add(analyzer, 1, first);

        var ended = analyzer.Finish(reason).Single();
        var repeated = analyzer.Finish(reason);

        await Assert.That(ended.Reason).IsEqualTo(reason);
        await Assert.That(ended.RecordNumbers.SequenceEqual(new long[] { 1 })).IsTrue();
        await Assert.That(repeated.IsEmpty).IsTrue();
    }

    [Test]
    public async Task Disposed_analyzer_rejects_explicit_clock_and_expiry_operations()
    {
        var analyzer = new IpReassemblyAnalyzer();
        analyzer.Dispose();

        Action advance = () => analyzer.AdvanceTime(1);
        Action expire = () => analyzer.Expire(1);

        await Assert.That(advance).Throws<ObjectDisposedException>();
        await Assert.That(expire).Throws<ObjectDisposedException>();
    }
}
