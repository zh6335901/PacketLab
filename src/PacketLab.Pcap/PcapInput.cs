namespace PacketLab.Pcap;

internal sealed class PcapInput(Stream stream)
{
    internal long Offset { get; private set; }

    internal BlockReadResult ReadBlock(Span<byte> destination)
    {
        var received = 0;
        while (received < destination.Length)
        {
            int count = stream.Read(destination[received..]);

            if (count == 0)
                return new BlockReadResult.Incomplete(received);

            received += count;
            Offset = checked(Offset + count);
        }

        return BlockReadResult.Complete.Instance;
    }
}

internal union BlockReadResult(BlockReadResult.Complete, BlockReadResult.Incomplete)
{
    internal sealed record Complete
    {
        internal static Complete Instance { get; } = new();
    }
    internal sealed record Incomplete(int ReadBytes);
}
