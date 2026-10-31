using System.Buffers.Binary;

namespace PacketLab.Pcap;

internal static class PcapParser
{
    internal static HeaderParseResult ParseHeader(ReadOnlySpan<byte> bytes)
    {
        var magic = BinaryPrimitives.ReadUInt32BigEndian(bytes);
        if (magic == 0x0a0d0d0a)
            return (PcapError)new PcapError.PcapNgNotSupported();
        if (magic is not (0xa1b2c3d4 or 0xd4c3b2a1 or 0xa1b23c4d or 0x4d3cb2a1))
            return (PcapError)new PcapError.UnsupportedFormat(magic);

        var order = magic is 0xd4c3b2a1 or 0x4d3cb2a1 ? PcapByteOrder.LittleEndian : PcapByteOrder.BigEndian;
        var precision = magic is 0xa1b23c4d or 0x4d3cb2a1
            ? PcapTimestampPrecision.Nanoseconds : PcapTimestampPrecision.Microseconds;
        var major = ReadUInt16(bytes[4..], order);
        var minor = ReadUInt16(bytes[6..], order);
        if (major != 2 || minor != 4)
            return (PcapError)new PcapError.UnsupportedVersion(major, minor);

        var snapLen = ReadUInt32(bytes[16..], order);
        if (snapLen == 0)
            return (PcapError)new PcapError.InvalidSnapLen();

        var rawLinkType = ReadUInt32(bytes[20..], order);
        if ((rawLinkType & 0x0bff0000) != 0)
            return (PcapError)new PcapError.InvalidLinkTypeReservedBits(rawLinkType);

        return new PcapFileHeader(order, precision, ReadUInt32(bytes[8..], order),
            ReadUInt32(bytes[12..], order), snapLen, rawLinkType);
    }

    private static ushort ReadUInt16(ReadOnlySpan<byte> bytes, PcapByteOrder order) =>
        order == PcapByteOrder.LittleEndian
            ? BinaryPrimitives.ReadUInt16LittleEndian(bytes)
            : BinaryPrimitives.ReadUInt16BigEndian(bytes);

    private static uint ReadUInt32(ReadOnlySpan<byte> bytes, PcapByteOrder order) =>
        order == PcapByteOrder.LittleEndian
            ? BinaryPrimitives.ReadUInt32LittleEndian(bytes)
            : BinaryPrimitives.ReadUInt32BigEndian(bytes);

    internal sealed class ValidatedPacketHeader
    {
        internal static RecordParseResult Parse(
            ReadOnlySpan<byte> bytes, PcapFileHeader fileHeader, long offset, long recordNumber,
            PcapReaderOptions options)
        {
            var order = fileHeader.ByteOrder;
            var capturedLength = ReadUInt32(bytes[8..], order);
            if (capturedLength > fileHeader.SnapLen)
                return (PcapError)new PcapError.CapturedLengthExceedsSnapLen(
                    offset, recordNumber, capturedLength, fileHeader.SnapLen);

            // Compare unsigned values BEFORE converting to int or allocating the payload.
            if (capturedLength > (uint)options.MaxPacketBytes)
                return (PcapError)new PcapError.PacketLimitExceeded(
                    offset, recordNumber, capturedLength, options.MaxPacketBytes);

            var seconds = ReadUInt32(bytes, order);
            var fraction = ReadUInt32(bytes[4..], order);
            var timestamp = fileHeader.TimestampPrecision switch
            {
                PcapTimestampPrecision.Microseconds => PcapTimestamp.FromMicroseconds(seconds, fraction),
                PcapTimestampPrecision.Nanoseconds => PcapTimestamp.FromNanoseconds(seconds, fraction),
                _ => throw new InvalidOperationException("Invalid precision in a validated file header.")
            };
            return new ValidatedPacketHeader(timestamp, (int)capturedLength, ReadUInt32(bytes[12..], order));
        }

        private ValidatedPacketHeader(PcapTimestamp timestamp, int capturedLength, uint originalLength)
        {
            Timestamp = timestamp;
            CapturedLength = capturedLength;
            OriginalLength = originalLength;
        }

        internal PcapTimestamp Timestamp { get; }
        internal int CapturedLength { get; }
        internal uint OriginalLength { get; }
    }

    internal union HeaderParseResult(PcapFileHeader, PcapError);
    internal union RecordParseResult(ValidatedPacketHeader, PcapError);
}
