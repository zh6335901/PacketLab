using TUnit.Assertions.Exceptions;

namespace PacketLab.Pcap.IntegrationTests;

public class ReadPcapFileTests
{
    [Test]
    public async Task Reading_a_file_preserves_caller_ownership_and_allows_exclusive_reopening()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "multiple.pcap");
        using (var stream = File.OpenRead(path))
        {
            var openResult = PcapReader.Open(stream);
            var reader = openResult is PcapReader opened ? opened : throw new AssertionException("Expected a PCAP reader.");
            int count = 0;
            while (true)
            {
                var result = reader.ReadNext();
                if (result is PcapEndOfFile) break;
                await Assert.That(result is PcapPacket).IsTrue();
                count++;
            }
            await Assert.That(count).IsEqualTo(3);
            await Assert.That(stream.CanRead).IsTrue();
            stream.Position = 0;
            await Assert.That(stream.ReadByte()).IsEqualTo(0xd4);
        }
        using var reopened = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.None);
        await Assert.That(reopened.Length).IsEqualTo(77L);
    }
}
