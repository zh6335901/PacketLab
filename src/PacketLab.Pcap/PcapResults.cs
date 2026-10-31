namespace PacketLab.Pcap;

public union PcapError(
    PcapError.UnsupportedFormat,
    PcapError.PcapNgNotSupported,
    PcapError.UnsupportedVersion,
    PcapError.IncompleteFileHeader,
    PcapError.IncompleteRecordHeader,
    PcapError.IncompletePacketData,
    PcapError.InvalidSnapLen,
    PcapError.InvalidLinkTypeReservedBits,
    PcapError.CapturedLengthExceedsSnapLen,
    PcapError.PacketLimitExceeded)
{
    public sealed record UnsupportedFormat(uint Magic);
    public sealed record PcapNgNotSupported;
    public sealed record UnsupportedVersion(ushort Major, ushort Minor);
    public sealed record IncompleteFileHeader(int ReadBytes);
    public sealed record IncompleteRecordHeader(long RecordOffset, long RecordNumber, int ReadBytes);
    public sealed record IncompletePacketData(long DataOffset, long RecordNumber, int ExpectedBytes, int ReadBytes);
    // Zero is the only invalid SnapLen; there is no arbitrary value to supply.
    public sealed record InvalidSnapLen;
    public sealed record InvalidLinkTypeReservedBits(uint RawLinkType);
    public sealed record CapturedLengthExceedsSnapLen(long RecordOffset, long RecordNumber, uint CapturedLength, uint SnapLen);
    public sealed record PacketLimitExceeded(long RecordOffset, long RecordNumber, uint CapturedLength, int MaxPacketBytes);

    // Offsets are relative to Open; truncation points to the first missing byte.
    public long Offset => this switch
    {
        UnsupportedFormat or PcapNgNotSupported => 0,
        UnsupportedVersion version => version.Major != 2 ? 4 : 6,
        IncompleteFileHeader partial => partial.ReadBytes,
        IncompleteRecordHeader partial => partial.RecordOffset + partial.ReadBytes,
        IncompletePacketData partial => partial.DataOffset + partial.ReadBytes,
        InvalidSnapLen => 16,
        InvalidLinkTypeReservedBits => 20,
        CapturedLengthExceedsSnapLen length => length.RecordOffset + 8,
        PacketLimitExceeded limit => limit.RecordOffset + 8,
        null => throw new InvalidOperationException("Uninitialized PCAP error.")
    };

    // Record numbers start at one; file-header failures have none.
    public long? RecordNumber => this switch
    {
        UnsupportedFormat or PcapNgNotSupported or UnsupportedVersion or IncompleteFileHeader
            or InvalidSnapLen or InvalidLinkTypeReservedBits => null,
        IncompleteRecordHeader partial => partial.RecordNumber,
        IncompletePacketData partial => partial.RecordNumber,
        CapturedLengthExceedsSnapLen length => length.RecordNumber,
        PacketLimitExceeded limit => limit.RecordNumber,
        null => throw new InvalidOperationException("Uninitialized PCAP error.")
    };

    public string Message => this switch
    {
        UnsupportedFormat format => $"Unknown PCAP magic number 0x{format.Magic:X8}.",
        PcapNgNotSupported => "PCAPNG is not supported.",
        UnsupportedVersion version => $"PCAP version {version.Major}.{version.Minor} is not supported; expected 2.4.",
        IncompleteFileHeader partial => $"Incomplete file header: expected 24 bytes, received {partial.ReadBytes}.",
        IncompleteRecordHeader partial => $"Incomplete record header: expected 16 bytes, received {partial.ReadBytes}.",
        IncompletePacketData partial => $"Incomplete packet data: expected {partial.ExpectedBytes} bytes, received {partial.ReadBytes}.",
        InvalidSnapLen => "SnapLen must be nonzero.",
        InvalidLinkTypeReservedBits link => $"LinkType R and Reserved3 bits must be zero (raw value 0x{link.RawLinkType:X8}).",
        CapturedLengthExceedsSnapLen length => $"Captured length {length.CapturedLength} exceeds SnapLen {length.SnapLen}.",
        PacketLimitExceeded limit => $"Captured length {limit.CapturedLength} exceeds the single-packet limit {limit.MaxPacketBytes}.",
        null => throw new InvalidOperationException("Uninitialized PCAP error.")
    };
}

public union PcapOpenResult(PcapReader, PcapError);

// A default union has null contents, not EOF.
public union PcapReadResult(PcapPacket, PcapEndOfFile, PcapError);

public sealed record PcapEndOfFile;
