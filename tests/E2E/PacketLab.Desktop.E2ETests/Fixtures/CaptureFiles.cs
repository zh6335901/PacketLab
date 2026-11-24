using System.Buffers.Binary;

namespace PacketLab.Desktop.E2ETests.Fixtures;

internal static class CaptureFiles
{
    internal static string Fixture(string name) => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);

    internal static void WriteRepeatedCapture(string file, int count)
    {
        using var output = File.Create(file);
        output.Write(Convert.FromHexString("D4C3B2A1020004000000000000000000FFFF000001000000"));
        const int size = 16 + 1024;
        var record = new byte[size];
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(8), 1024);
        BinaryPrimitives.WriteUInt32LittleEndian(record.AsSpan(12), 1024);
        var arp = Convert.FromHexString("FFFFFFFFFFFF0200000000010806000108000604000102000000000100000000000000000000C0000202");
        arp.CopyTo(record, 16);
        const int blockCount = 512;
        var block = new byte[blockCount * size];
        for (var i = 0; i < blockCount; i++)
            record.CopyTo(block, i * size);

        for (var done = 0; done < count; done += blockCount)
            output.Write(block.AsSpan(0, Math.Min(count - done, blockCount) * size));
    }
}
