using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzePcapFileTests
{
    [Test]
    public async Task Valid_record_before_truncation_preserves_packet_fields()
    {
        // Arrange
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "record-truncated.pcap"));
        using var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened
            : throw new InvalidOperationException("Expected an analysis reader.");

        // Act
        var result = reader.ReadNext();

        // Assert
        var packet = result is AnalyzedPacket read ? read : throw new InvalidOperationException("Expected the first record.");
        await Assert.That(packet.RecordNumber).IsEqualTo(1L);
        await Assert.That(packet.Packet.Timestamp).IsEqualTo(PcapTimestamp.FromMicroseconds(100, 1500000));
        await Assert.That(packet.Packet.CapturedLength).IsEqualTo(3u);
        await Assert.That(packet.Packet.OriginalLength).IsEqualTo(5u);
        await Assert.That(Convert.ToHexString(packet.Packet.Data.Span)).IsEqualTo("DEADBE");
    }

    [Test]
    public async Task Truncated_record_reports_file_error_after_the_preceding_packet()
    {
        // Arrange
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "record-truncated.pcap"));
        using var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened
            : throw new InvalidOperationException("Expected an analysis reader.");
        reader.ReadNext();

        // Act
        var result = reader.ReadNext();

        // Assert
        var error = result is PcapError failure ? failure : throw new InvalidOperationException("Expected a file error for the second record.");
        await Assert.That(error.Value).IsEqualTo(new PcapError.IncompletePacketData(59, 2, 2, 1));
    }
}
