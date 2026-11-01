namespace PacketLab.Cli.E2ETests;

internal static class PcapSamples
{
    internal static byte[] Multiple() => File.ReadAllBytes(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", "multiple.pcap"));

    internal static byte[] Replace(byte[] bytes, int offset, string hex)
    {
        Convert.FromHexString(hex).CopyTo(bytes, offset);
        return bytes;
    }
}
