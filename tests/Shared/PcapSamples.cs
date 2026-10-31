namespace PacketLab.Tests;

internal static class PcapSamples
{
    // Literal wire bytes, independent of the reader and of any PCAP writer.
    internal const string LittleMicroHeader = "D4C3B2A1020004000000000000000000FFFF000001000000";
    internal const string LittleNanoHeader = "4D3CB2A1020004000000000000000000FFFF000001000000";
    internal const string BigMicroHeader = "A1B2C3D40002000400000000000000000000FFFF00000001";
    internal const string BigNanoHeader = "A1B23C4D0002000400000000000000000000FFFF00000001";
    internal const string MicroRecord = "0403020140E201000300000005000000DEADBE";
    internal const string NanoRecord = "0403020115CD5B070300000005000000DEADBE";
    internal const string BigMicroRecord = "010203040001E2400000000300000005DEADBE";
    internal const string BigNanoRecord = "01020304075BCD150000000300000005DEADBE";
    internal const string Multiple = LittleMicroHeader
        + "6400000060E316000300000005000000DEADBE"
        + "63000000000000000200000001000000AABB"
        + "62000000000000000000000000000000";

    internal static byte[] Single(string name) => Convert.FromHexString(name switch
    {
        "little-micro" => LittleMicroHeader + MicroRecord,
        "little-nano" => LittleNanoHeader + NanoRecord,
        "big-micro" => BigMicroHeader + BigMicroRecord,
        "big-nano" => BigNanoHeader + BigNanoRecord,
        _ => throw new ArgumentOutOfRangeException(nameof(name))
    });

    internal static byte[] Replace(byte[] bytes, int offset, string hex)
    {
        var copy = (byte[])bytes.Clone();
        Convert.FromHexString(hex).CopyTo(copy, offset);
        return copy;
    }
}
