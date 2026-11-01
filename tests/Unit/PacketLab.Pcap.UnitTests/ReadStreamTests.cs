using static PacketLab.Pcap.UnitTests.ReaderAssertions;

namespace PacketLab.Pcap.UnitTests;

public class ReadStreamTests
{
    [Test]
    public async Task Error_offsets_are_relative_to_open_at_the_current_stream_position()
    {
        using var stream = new MemoryStream([0xaa, 0xbb, 0xcc, .. PcapSamples.Single("little-micro")[..42]]);
        stream.Position = 3;
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var result = reader.ReadNext();
        var error = await result.ShouldFail(new PcapError.IncompletePacketData(40, 1, 3, 2));
        await Assert.That(error.Offset).IsEqualTo(42L);
        await Assert.That(error.RecordNumber).IsEqualTo((long?)1);
        await Assert.That(stream.Position).IsEqualTo(45L);
    }

    [Test]
    [Arguments(1)]
    [Arguments(7)]
    public async Task Short_reads_on_nonseekable_streams_return_all_packets_and_eof(int chunkSize)
    {
        using var stream = new ProbeStream(Convert.FromHexString(PcapSamples.Multiple)) { ChunkSize = chunkSize };
        var openResult = PcapReader.Open(stream);
        var reader = await openResult.ShouldSucceed();
        var firstResult = reader.ReadNext();
        var first = await firstResult.ShouldSucceed();
        await Assert.That(Convert.ToHexString(first.Data.Span)).IsEqualTo("DEADBE");
        var secondResult = reader.ReadNext();
        var second = await secondResult.ShouldSucceed();
        await Assert.That(Convert.ToHexString(second.Data.Span)).IsEqualTo("AABB");
        var thirdResult = reader.ReadNext();
        var third = await thirdResult.ShouldSucceed();
        await Assert.That(third.Data.IsEmpty).IsTrue();
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
        await Assert.That(stream.IsDisposed).IsFalse();
    }

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
