using TUnit.Assertions.Exceptions;

namespace PacketLab.Pcap.IntegrationTests;

public class ReadPcapFileTests
{
    [Test]
    public async Task Reading_a_file_to_eof_preserves_caller_ownership()
    {
        // Arrange
        var path = Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "multiple.pcap");
        using var stream = File.OpenRead(path);
        var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new AssertionException("Expected a PCAP reader.");

        for (int i = 0; i < 3; i++) reader.ReadNext();

        // Act
        var result = reader.ReadNext();

        // Assert
        await Assert.That(result is PcapEndOfFile).IsTrue();
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Disposing_the_caller_stream_allows_exclusive_reopening()
    {
        // Arrange
        var source = Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "multiple.pcap");
        var path = Path.Combine(Path.GetTempPath(), $"packetlab-{Guid.NewGuid():N}.pcap");

        File.Copy(source, path);
        try
        {
            using (var stream = File.OpenRead(path))
            {
                var reader = PcapReader.Open(stream) is PcapReader opened ? opened : throw new AssertionException("Expected a PCAP reader.");
                for (int i = 0; i < 4; i++) reader.ReadNext();
            }

            // Act
            using var reopened = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);

            // Assert
            await Assert.That(reopened.Length).IsEqualTo(77L);
        }
        finally
        {
            File.Delete(path);
        }
    }
}
