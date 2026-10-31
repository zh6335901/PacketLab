namespace PacketLab.Pcap.UnitTests;

internal static class ReaderAssertions
{
    internal static async Task Location(PcapError error, long offset, long? record)
    {
        await Assert.That(error.Offset).IsEqualTo(offset);
        await Assert.That(error.RecordNumber).IsEqualTo(record);
        await Assert.That(string.IsNullOrWhiteSpace(error.Message)).IsFalse();
    }
}
