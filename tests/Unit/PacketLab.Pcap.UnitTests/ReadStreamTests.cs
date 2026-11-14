using FsCheck;
using FsCheck.Fluent;
using static PacketLab.Pcap.UnitTests.ReaderAssertions;

namespace PacketLab.Pcap.UnitTests;

public class ReadStreamTests
{
    [Test]
    public void Error_offsets_are_relative_to_open_at_the_current_stream_position() =>
        Prop.ForAll((byte[] prefix, byte selector) =>
        {
            int received = selector % 3;
            int cut = 40 + received;
            using var stream = new MemoryStream([.. prefix, .. PcapSamples.Single("little-micro")[..cut]]);
            stream.Position = prefix.Length;
            return PcapReader.Open(stream) is PcapReader reader && reader.ReadNext() is PcapError error
                && Equals(error.Value, new PcapError.IncompletePacketData(40, 1, 3, received))
                && error.Offset == cut && error.RecordNumber == 1 && stream.Position == prefix.Length + cut;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public void Short_reads_on_nonseekable_streams_preserve_records_and_terminal_result() =>
        Prop.ForAll((byte[] sizes, DoNotSize<ushort> selector) =>
        {
            var bytes = Convert.FromHexString(PcapSamples.Multiple);
            int[] chunks = [1, .. sizes.Select(size => 1 + size % 16)];
            return ReadsKnownCapture(bytes, chunks) && SameReads(bytes, chunks)
                && SameReads(bytes[..(selector.Item % bytes.Length)], chunks);
        }).Check(Config.QuickThrowOnFailure);

    private static bool ReadsKnownCapture(byte[] bytes, int[] chunks)
    {
        using var stream = new ProbeStream(bytes) { ChunkSizes = chunks };
        if (PcapReader.Open(stream) is not PcapReader reader) return false;
        foreach (var expected in new[] { "DEADBE", "AABB", "" })
            if (reader.ReadNext() is not PcapPacket packet || Convert.ToHexString(packet.Data.Span) != expected) return false;
        return reader.ReadNext() is PcapEndOfFile && reader.ReadNext() is PcapEndOfFile && !stream.IsDisposed;
    }

    private static bool SameReads(byte[] bytes, int[] chunks)
    {
        using var stream = new ProbeStream(bytes) { ChunkSizes = chunks };
        using var baseline = new MemoryStream(bytes);
        var expected = PcapReader.Open(baseline);
        var actual = PcapReader.Open(stream);
        if (expected is PcapError openError)
            return actual is PcapError other && Equals(openError.Value, other.Value) && !stream.IsDisposed;
        if (expected is not PcapReader regular || actual is not PcapReader shortReads) return false;
        PcapReadResult terminal;
        while ((terminal = regular.ReadNext()) is PcapPacket packet)
        {
            if (shortReads.ReadNext() is not PcapPacket received || received.Timestamp != packet.Timestamp
                || received.OriginalLength != packet.OriginalLength || !received.Data.Span.SequenceEqual(packet.Data.Span))
                return false;
        }
        return SameTerminal(terminal, shortReads.ReadNext()) && SameTerminal(terminal, shortReads.ReadNext()) && !stream.IsDisposed;
    }

    private static bool SameTerminal(PcapReadResult expected, PcapReadResult actual) => expected switch
    {
        PcapEndOfFile => actual is PcapEndOfFile,
        PcapError error => actual is PcapError other && Equals(error.Value, other.Value) && error.Offset == other.Offset,
        _ => false
    };

    [Test]
    public async Task Opening_propagates_the_original_io_exception_without_closing_the_stream()
    {
        using var stream = new ProbeStream(PcapSamples.Single("little-micro")) { FailAt = 11 };
        var exception = await Assert.That(() => PcapReader.Open(stream)).Throws<IOException>();
        await Assert.That(exception).IsSameReferenceAs(stream.Failure);
        await Assert.That(stream.IsDisposed).IsFalse();
    }

    [Test]
    [Arguments(29)]
    [Arguments(41)]
    public async Task Reading_propagates_the_original_io_exception_and_stops_reading(int failAt)
    {
        using var stream = new ProbeStream(PcapSamples.Single("little-micro")) { FailAt = failAt };
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var exception = await Assert.That(() => reader.ReadNext()).Throws<IOException>();
        await Assert.That(exception).IsSameReferenceAs(stream.Failure);
        var calls = stream.ReadCalls;
        stream.FailAt = null;
        var repeated = await Assert.That(() => reader.ReadNext()).Throws<IOException>();
        await Assert.That(repeated).IsSameReferenceAs(exception);
        await Assert.That(stream.ReadCalls).IsEqualTo(calls);
        await Assert.That(stream.IsDisposed).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Access_and_disposal_exceptions_propagate_unchanged(bool disposed)
    {
        using var stream = new ProbeStream(PcapSamples.Single("little-micro"))
        {
            FailAt = 41,
            Failure = disposed ? new ObjectDisposedException("source") : new UnauthorizedAccessException("denied")
        };
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var exception = await Assert.That(() => reader.ReadNext()).ThrowsException();
        await Assert.That(exception).IsSameReferenceAs(stream.Failure);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Reading_stops_after_structural_or_resource_failure(bool resource)
    {
        var bytes = Convert.FromHexString(PcapSamples.Multiple);
        if (!resource) bytes = PcapSamples.Replace(bytes, 16, "01000000");
        using var stream = new ProbeStream(bytes);
        var openResult = PcapReader.Open(stream, new PcapReaderOptions(resource ? 1 : 10));
        var reader = await openResult.ShouldSucceed();
        var errorResult = reader.ReadNext();
        PcapError expectedError = resource
            ? new PcapError.PacketLimitExceeded(24, 1, 3, 1)
            : new PcapError.CapturedLengthExceedsSnapLen(24, 1, 3, 1);
        var error = await errorResult.ShouldFail(expectedError);
        var calls = stream.ReadCalls;
        var repeatedResult = reader.ReadNext();
        var repeated = await repeatedResult.ShouldFail(expectedError);
        await Assert.That(repeated.Message).IsEqualTo(error.Message);
        await Location(repeated, 32, 1);
        await Assert.That(stream.ReadCalls).IsEqualTo(calls);
        await Assert.That(stream.IsDisposed).IsFalse();
    }

    [Test]
    public async Task Truncation_is_terminal_even_if_more_bytes_become_available()
    {
        using var stream = new MemoryStream();
        var bytes = PcapSamples.Single("little-micro");
        stream.Write(bytes.AsSpan(0, 41));
        stream.Position = 0;
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var errorResult = reader.ReadNext();
        var expectedError = new PcapError.IncompletePacketData(40, 1, 3, 1);
        var error = await errorResult.ShouldFail(expectedError);
        stream.Write(bytes.AsSpan(41));
        stream.Position = 41;
        var repeatedResult = reader.ReadNext();
        var repeated = await repeatedResult.ShouldFail(expectedError);
        await Location(repeated, 41, 1);
        await Assert.That(repeated.Message).IsEqualTo(error.Message);
        await Assert.That(stream.Position).IsEqualTo(41L);
    }
}
