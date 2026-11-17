namespace PacketLab.Pcap;

public sealed class CaptureReaderOptions
{
    public const int DefaultMaxPacketBytes = 16 * 1024 * 1024;
    public static CaptureReaderOptions Default { get; } = new();

    public CaptureReaderOptions(int maxPacketBytes = DefaultMaxPacketBytes,
        int maxBlockBytes = 32 * 1024 * 1024, int maxMetadataBytes = 64 * 1024 * 1024,
        int maxOptionsPerBlock = 65536)
    {
        if (maxPacketBytes <= 0 || maxPacketBytes > Array.MaxLength)
            throw new ArgumentOutOfRangeException(nameof(maxPacketBytes),
                $"The packet limit must be between 1 and {Array.MaxLength}.");
        if (maxBlockBytes < 28 || maxBlockBytes > Array.MaxLength)
            throw new ArgumentOutOfRangeException(nameof(maxBlockBytes));
        if (maxMetadataBytes < 28)
            throw new ArgumentOutOfRangeException(nameof(maxMetadataBytes));

        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxOptionsPerBlock);
        MaxPacketBytes = maxPacketBytes;
        MaxBlockBytes = maxBlockBytes;
        MaxMetadataBytes = maxMetadataBytes;
        MaxOptionsPerBlock = maxOptionsPerBlock;
    }

    public int MaxPacketBytes { get; }
    public int MaxBlockBytes { get; }
    public int MaxMetadataBytes { get; }
    public int MaxOptionsPerBlock { get; }
}
