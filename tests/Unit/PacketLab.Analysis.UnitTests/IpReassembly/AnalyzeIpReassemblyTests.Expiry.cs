using System.Buffers.Binary;
using FsCheck;
using FsCheck.Fluent;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Analysis.UnitTests.IpReassembly;

public partial class AnalyzeIpReassemblyTests
{
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
    public void Duplicate_arrivals_never_extend_the_original_deadline() =>
        Prop.ForAll((byte[] delays, ushort start) =>
        {
            var times = delays.Take(24).Select(t => t % 60).Append(59).Order().ToArray();
            var first = Fragment(4, 0, true, Payload[..16]);
            using var stream = Capture([first, .. Enumerable.Repeat(first, times.Length), Fragment(4, 16, false, Payload[16..])]);
            SetSeconds(stream, 1, start);
            for (int i = 0; i < times.Length; i++) SetSeconds(stream, i + 2, (uint)(start + times[i]));
            SetSeconds(stream, times.Length + 2, (uint)(start + 60));
            using var reader = Open(stream);
            Read(reader);
            foreach (var _ in times)
            {
                Read(reader);
                if (reader.ReassemblyEvents.Single().Status != IpReassemblyStatus.Duplicate) return false;
            }
            Read(reader);
            return reader.ReassemblyEvents.Select(e => e.Status).SequenceEqual(new[] { IpReassemblyStatus.Expired, IpReassemblyStatus.Pending })
                && reader.ReassemblyEvents[0].DatagramNumber == 1;
        }).Check(Config.QuickThrowOnFailure);

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
    public async Task Clock_moving_from_100_seconds_back_to_1_keeps_fragments_alive()
    {
        await Assert.That(StatusAfterClockMovesBack(100, 1)).IsEqualTo(IpReassemblyStatus.Complete);
    }

    [Test]
    public void Reordered_timestamps_never_underflow_the_expiry_clock() =>
        Prop.ForAll((DoNotSize<uint> first, DoNotSize<uint> decrease) =>
        {
            uint high = Math.Max(1u, first.Item);
            uint low = high - 1 - decrease.Item % high;
            return StatusAfterClockMovesBack(high, low) == IpReassemblyStatus.Complete;
        }).Check(Config.QuickThrowOnFailure);

    private static IpReassemblyStatus StatusAfterClockMovesBack(uint first, uint second)
    {
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]));
        SetSeconds(stream, 1, first);
        SetSeconds(stream, 2, second);
        using var reader = Open(stream);
        Read(reader);
        Read(reader);
        return reader.ReassemblyEvents.Single().Status;
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
        using var reader = Open(stream, new(reassembly: new(maxDatagrams: 1))); Read(reader); Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.ResourceLimit);
        Read(reader); Read(reader);
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Complete);
    }

    private static void SetSeconds(MemoryStream stream, int record, uint seconds)
    {
        var bytes = stream.GetBuffer(); var position = 24;
        for (var i = 1; i < record; i++) position += 16 + (int)BinaryPrimitives.ReadUInt32LittleEndian(bytes.AsSpan(position + 8));
        BinaryPrimitives.WriteUInt32LittleEndian(bytes.AsSpan(position), seconds);
    }
}
