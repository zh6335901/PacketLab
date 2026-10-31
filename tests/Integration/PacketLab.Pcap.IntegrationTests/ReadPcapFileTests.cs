using PacketLab.Tests;

namespace PacketLab.Pcap.IntegrationTests;

public class ReadPcapFileTests
{
    [Test]
    public async Task Reading_a_file_preserves_caller_ownership_and_allows_exclusive_reopening()
    {
        var path = Path.Combine(AppContext.BaseDirectory, "samples", "multiple.pcap");
        using (var stream = File.OpenRead(path))
        {
            var openResult = PcapReader.Open(stream);
            var reader = await openResult.ShouldSucceed();
            int count = 0;
            while (true)
            {
                var result = reader.ReadNext();
                if (result is PcapEndOfFile) break;
                await result.ShouldSucceed();
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
