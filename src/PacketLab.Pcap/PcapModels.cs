namespace PacketLab.Pcap;

public enum PcapByteOrder { LittleEndian, BigEndian }

public enum PcapTimestampPrecision { Microseconds, Nanoseconds }

// Fractions are preserved without normalization; default is zero seconds/microseconds.
public readonly record struct PcapTimestamp
{
    private PcapTimestamp(uint seconds, uint fraction, PcapTimestampPrecision precision)
    {
        Seconds = seconds;
        Fraction = fraction;
        Precision = precision;
    }

    public uint Seconds { get; }
    public uint Fraction { get; }
    public PcapTimestampPrecision Precision { get; }
    public static PcapTimestamp FromMicroseconds(uint seconds, uint microseconds) =>
        new(seconds, microseconds, PcapTimestampPrecision.Microseconds);
    public static PcapTimestamp FromNanoseconds(uint seconds, uint nanoseconds) =>
        new(seconds, nanoseconds, PcapTimestampPrecision.Nanoseconds);
}

public sealed record PcapFileHeader
{
    internal PcapFileHeader(PcapByteOrder byteOrder, PcapTimestampPrecision timestampPrecision,
        uint reserved1, uint reserved2, uint snapLen, uint rawLinkType)
    {
        ByteOrder = byteOrder;
        TimestampPrecision = timestampPrecision;
        Reserved1 = reserved1;
        Reserved2 = reserved2;
        SnapLen = snapLen;
        RawLinkType = rawLinkType;
    }

    public ushort MajorVersion => 2;
    public ushort MinorVersion => 4;
    public PcapByteOrder ByteOrder { get; }
    public PcapTimestampPrecision TimestampPrecision { get; }
    public uint Reserved1 { get; }
    public uint Reserved2 { get; }
    public uint SnapLen { get; }
    public uint RawLinkType { get; }
    public ushort LinkType => (ushort)(RawLinkType & 0xffff);
    public bool HasFcsLength => (RawLinkType & 0x04000000) != 0;
    public byte RawFcsLengthWords => (byte)(RawLinkType >> 28);
    // Absence of P means unspecified, not a zero-length FCS.
    public int? FcsLengthBytes => HasFcsLength ? RawFcsLengthWords * 2 : null;
}

public sealed class PcapPacket
{
    internal PcapPacket(PcapTimestamp timestamp, uint originalLength, byte[] data)
    {
        Timestamp = timestamp;
        OriginalLength = originalLength;
        Data = data;
    }

    public PcapTimestamp Timestamp { get; }
    public uint CapturedLength => (uint)Data.Length;
    public uint OriginalLength { get; }
    public ReadOnlyMemory<byte> Data { get; }
    public bool OriginalLengthIsLessThanCaptured => OriginalLength < CapturedLength;
}

public sealed class PcapReaderOptions
{
    public const int DefaultMaxPacketBytes = 16 * 1024 * 1024;
    public static PcapReaderOptions Default { get; } = new();

    public PcapReaderOptions(int maxPacketBytes = DefaultMaxPacketBytes)
    {
        if (maxPacketBytes <= 0 || maxPacketBytes > Array.MaxLength)
            throw new ArgumentOutOfRangeException(nameof(maxPacketBytes),
                $"The packet limit must be between 1 and {Array.MaxLength}.");

        MaxPacketBytes = maxPacketBytes;
    }

    public int MaxPacketBytes { get; }
}
