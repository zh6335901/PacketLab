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
            // Arrange
            int received = selector % 3;
            int cut = 40 + received;
            using var stream = new MemoryStream([.. prefix, .. PcapSamples.Single("little-micro")[..cut]]);
            stream.Position = prefix.Length;
            var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();

            // Act
            var result = reader.ReadNext();

            // Assert
            return result is PcapError error
                && Equals(error.Value, new PcapError.IncompletePacketData(40, 1, 3, received))
                && error.Offset == cut && error.RecordNumber == 1 && stream.Position == prefix.Length + cut;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public void Opening_on_short_reads_matches_a_seekable_stream() =>
        Prop.ForAll((byte[] sizes, DoNotSize<ushort> selector) =>
        {
            // Arrange
            var bytes = Convert.FromHexString(PcapSamples.Multiple);
            var capture = bytes[..(selector.Item % (bytes.Length + 1))];
            using var baseline = new MemoryStream(capture);
            var expected = PcapReader.Open(baseline);
            using var stream = new ProbeStream(capture) { ChunkSizes = [1, .. sizes.Select(size => 1 + size % 16)] };

            // Act
            var actual = PcapReader.Open(stream);

            // Assert
            return (expected, actual) switch
            {
                (PcapReader regular, PcapReader chunked) => regular.Header == chunked.Header && !stream.IsDisposed,
                (PcapError error, PcapError other) => Equals(error.Value, other.Value) && !stream.IsDisposed,
                _ => false
            };
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public void Reading_on_short_reads_matches_a_seekable_stream() =>
        Prop.ForAll((byte[] sizes, DoNotSize<ushort> selector, byte preceding) =>
        {
            // Arrange
            var bytes = Convert.FromHexString(PcapSamples.Multiple);
            var capture = bytes[..(24 + selector.Item % (bytes.Length - 23))];
            using var baseline = new MemoryStream(capture);
            using var stream = new ProbeStream(capture) { ChunkSizes = [1, .. sizes.Select(size => 1 + size % 16)] };
            var regular = PcapReader.Open(baseline) is PcapReader r ? r : throw new InvalidOperationException();
            var chunked = PcapReader.Open(stream) is PcapReader c ? c : throw new InvalidOperationException();
            for (int i = 0; i < preceding % 5; i++)
            {
                regular.ReadNext();
                chunked.ReadNext();
            }
            var expected = regular.ReadNext();

            // Act
            var actual = chunked.ReadNext();

            // Assert
            return (expected, actual) switch
            {
                (PcapPacket packet, PcapPacket received) => received.Timestamp == packet.Timestamp
                    && received.OriginalLength == packet.OriginalLength
                    && received.Data.Span.SequenceEqual(packet.Data.Span) && !stream.IsDisposed,
                (PcapEndOfFile, PcapEndOfFile) => !stream.IsDisposed,
                (PcapError error, PcapError other) => Equals(error.Value, other.Value)
                    && error.Offset == other.Offset && !stream.IsDisposed,
                _ => false
            };
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task Opening_propagates_the_original_io_exception_without_closing_the_stream()
    {
        // Arrange
        using var stream = new ProbeStream(PcapSamples.Single("little-micro")) { FailAt = 11 };

        // Act
        Action act = () => PcapReader.Open(stream);

        // Assert
        var exception = await Assert.That(act).Throws<IOException>();
        await Assert.That(exception).IsSameReferenceAs(stream.Failure);
        await Assert.That(stream.IsDisposed).IsFalse();
    }

    [Test]
    [Arguments(29)]
    [Arguments(41)]
    public async Task Reading_propagates_the_original_io_exception(int failAt)
    {
        // Arrange
        using var stream = new ProbeStream(PcapSamples.Single("little-micro")) { FailAt = failAt };
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        Action act = () => reader.ReadNext();

        // Assert
        var exception = await Assert.That(act).Throws<IOException>();
        await Assert.That(exception).IsSameReferenceAs(stream.Failure);
        await Assert.That(stream.IsDisposed).IsFalse();
    }

    [Test]
    [Arguments(29)]
    [Arguments(41)]
    public async Task Reading_after_an_io_failure_rethrows_without_touching_the_stream(int failAt)
    {
        // Arrange
        using var stream = new ProbeStream(PcapSamples.Single("little-micro")) { FailAt = failAt };
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();
        try { reader.ReadNext(); } catch (IOException) { }
        var calls = stream.ReadCalls;
        stream.FailAt = null;

        // Act
        Action act = () => reader.ReadNext();

        // Assert
        var exception = await Assert.That(act).Throws<IOException>();
        await Assert.That(exception).IsSameReferenceAs(stream.Failure);
        await Assert.That(stream.ReadCalls).IsEqualTo(calls);
        await Assert.That(stream.IsDisposed).IsFalse();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Access_and_disposal_exceptions_propagate_unchanged(bool disposed)
    {
        // Arrange
        using var stream = new ProbeStream(PcapSamples.Single("little-micro"))
        {
            FailAt = 41,
            Failure = disposed ? new ObjectDisposedException("source") : new UnauthorizedAccessException("denied")
        };
        var openResult = PcapReader.Open(stream);
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();

        // Act
        Action act = () => reader.ReadNext();

        // Assert
        var exception = await Assert.That(act).ThrowsException();
        await Assert.That(exception).IsSameReferenceAs(stream.Failure);
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task Reading_stops_after_structural_or_resource_failure(bool resource)
    {
        // Arrange
        var bytes = Convert.FromHexString(PcapSamples.Multiple);
        if (!resource) bytes = PcapSamples.Replace(bytes, 16, "01000000");
        using var stream = new ProbeStream(bytes);
        var openResult = PcapReader.Open(stream, new PcapReaderOptions(resource ? 1 : 10));
        var reader = openResult is PcapReader opened ? opened : throw new InvalidOperationException();
        var error = reader.ReadNext() is PcapError initial ? initial : throw new InvalidOperationException();
        PcapError expectedError = resource
            ? new PcapError.PacketLimitExceeded(24, 1, 3, 1)
            : new PcapError.CapturedLengthExceedsSnapLen(24, 1, 3, 1);
        var calls = stream.ReadCalls;

        // Act
        var repeatedResult = reader.ReadNext();

        // Assert
        var repeated = await repeatedResult.ShouldFail(expectedError);
        await Assert.That(repeated.Message).IsEqualTo(error.Message);
        await Location(repeated, 32, 1);
        await Assert.That(stream.ReadCalls).IsEqualTo(calls);
        await Assert.That(stream.IsDisposed).IsFalse();
    }

    [Test]
    public async Task Truncation_is_terminal_even_if_more_bytes_become_available()
    {
        // Arrange
        using var stream = new MemoryStream();
        var bytes = PcapSamples.Single("little-micro");
        stream.Write(bytes.AsSpan(0, 41));
        stream.Position = 0;
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new InvalidOperationException();
        var error = reader.ReadNext() is PcapError initial ? initial : throw new InvalidOperationException();
        var expectedError = new PcapError.IncompletePacketData(40, 1, 3, 1);
        stream.Write(bytes.AsSpan(41));
        stream.Position = 41;

        // Act
        var repeatedResult = reader.ReadNext();

        // Assert
        var repeated = await repeatedResult.ShouldFail(expectedError);
        await Location(repeated, 41, 1);
        await Assert.That(repeated.Message).IsEqualTo(error.Message);
        await Assert.That(stream.Position).IsEqualTo(41L);
    }
}
