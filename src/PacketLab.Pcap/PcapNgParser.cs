using System.Buffers.Binary;
using System.Collections.Immutable;

namespace PacketLab.Pcap;

internal sealed record PcapNgBlock(long Offset, uint Type, PcapByteOrder Order, ReadOnlyMemory<byte> Body)
{
    internal PcapError Error(int bodyOffset, string detail) =>
        new PcapError.InvalidPcapNg(Offset, Offset + 8 + bodyOffset, null, detail);
    internal ushort UInt16(int offset) => PcapNgParser.UInt16(Body.Span[offset..], Order);
    internal uint UInt32(int offset) => PcapNgParser.UInt32(Body.Span[offset..], Order);
    internal long Int64(int offset) => PcapNgParser.Int64(Body.Span[offset..], Order);
}

internal static class PcapNgParser
{
    internal static ushort UInt16(ReadOnlySpan<byte> bytes, PcapByteOrder order) =>
        order == PcapByteOrder.LittleEndian ? BinaryPrimitives.ReadUInt16LittleEndian(bytes) : BinaryPrimitives.ReadUInt16BigEndian(bytes);
    internal static uint UInt32(ReadOnlySpan<byte> bytes, PcapByteOrder order) =>
        order == PcapByteOrder.LittleEndian ? BinaryPrimitives.ReadUInt32LittleEndian(bytes) : BinaryPrimitives.ReadUInt32BigEndian(bytes);
    internal static long Int64(ReadOnlySpan<byte> bytes, PcapByteOrder order) =>
        order == PcapByteOrder.LittleEndian ? BinaryPrimitives.ReadInt64LittleEndian(bytes) : BinaryPrimitives.ReadInt64BigEndian(bytes);

    internal static SectionResult Section(PcapNgBlock block, long number, int maxOptions)
    {
        if (block.Body.Length < 16)
            return block.Error(0, "Section header requires a 16-byte body.");

        var major = block.UInt16(4);
        var minor = block.UInt16(6);
        if (major != 1 || minor is not (0 or 2))
            return block.Error(4, $"Unsupported section version {major}.{minor}; expected 1.0 or 1.2.");

        var length = block.Int64(8);
        if (length < -1 || (length >= 0 && length % 4 != 0))
            return block.Error(8, $"Invalid section length {length}.");

        return Options(block, 16, maxOptions) switch
        {
            ImmutableArray<PcapNgOption> options => new PcapNgSection(number, block.Offset, block.Order, major, minor, length, options),
            PcapError error => error,
            null => throw new InvalidOperationException("Uninitialized options result.")
        };
    }

    internal static InterfaceResult Interface(PcapNgBlock block, PcapNgSection section, uint id, int maxOptions)
    {
        if (block.Body.Length < 8)
            return block.Error(0, "Interface description requires an 8-byte body.");

        var optionResult = Options(block, 8, maxOptions);
        if (optionResult is PcapError error)
            return error;
        if (optionResult is not ImmutableArray<PcapNgOption> options)
            throw new InvalidOperationException("Uninitialized options result.");
        if (ValidateInterfaceOptions(block, options) is { } failure)
            return failure;

        var resolutionOption = options.FirstOrDefault(option => option.Code == 9);
        var offsetOption = options.FirstOrDefault(option => option.Code == 14);
        byte resolution = resolutionOption is null ? (byte)6 : resolutionOption.Value.Span[0];
        long offset = offsetOption is null ? 0 : Int64(offsetOption.Value.Span, block.Order);

        return new PcapNgInterface(section, id,
            block.UInt16(0),
            block.UInt32(4), resolution, offset, options);
    }

    private static PcapError? ValidateInterfaceOptions(PcapNgBlock block, ImmutableArray<PcapNgOption> options)
    {
        var seen = new HashSet<ushort>();
        foreach (var option in options)
        {
            int? length = option.Code switch
            {
                4 or 7 or 8 or 14 or 16 or 17 => 8,
                5 => 17,
                6 => 6,
                9 or 13 => 1,
                10 => 4,
                _ => null
            };
            if (length is { } required && option.Value.Length != required)
                return block.Error(8, $"Interface option {option.Code} requires {required} bytes.");
            if (option.Code is >= 2 and <= 18 and not (4 or 5) && !seen.Add(option.Code))
                return block.Error(8, $"Duplicate interface option {option.Code}.");
            if (option.Code == 11 && option.Value.IsEmpty)
                return block.Error(8, "Interface filter option requires a filter type.");
        }

        return null;
    }

    internal static PacketResult Packet(PcapNgBlock block, IReadOnlyList<PcapNgInterface> interfaces, int maxPacketBytes, int maxOptions)
    {
        var simple = block.Type == 3;
        var headerLength = simple ? 4 : 20;
        if (block.Body.Length < headerLength)
            return block.Error(0, $"Packet block requires at least {headerLength} body bytes.");

        uint id = block.Type switch { 3 => 0, 2 => block.UInt16(0), _ => block.UInt32(0) };
        if (id >= interfaces.Count)
            return block.Error(0, $"Interface {id} has not been defined in this section.");

        var captureInterface = interfaces[(int)id];
        uint original = block.UInt32(simple ? 0 : 16);
        uint captured = simple ? SimpleCapturedLength(original, captureInterface.SnapLen) : block.UInt32(12);
        if (ValidatePacketLength(block, captured, original, captureInterface.SnapLen, maxPacketBytes) is { } failure)
            return failure;

        int padded = (int)(((long)captured + 3) & ~3L);
        if (padded > block.Body.Length - headerLength)
            return block.Error(headerLength, "Captured packet data and padding exceed the block body.");

        int optionsStart = headerLength + padded;
        if (simple && optionsStart != block.Body.Length)
            return block.Error(optionsStart, "Simple Packet Blocks cannot contain options or extra packet bytes.");

        var optionResult = Options(block, optionsStart, maxOptions);
        if (optionResult is PcapError error)
            return error;
        if (optionResult is not ImmutableArray<PcapNgOption> options)
            throw new InvalidOperationException("Uninitialized options result.");
        if (ValidatePacketOptions(block, options) is { } optionError)
            return optionError;

        return MakePacket(block, captureInterface, original, captured, options);
    }

    private static uint SimpleCapturedLength(uint original, uint snapLen) => snapLen == 0 ? original : Math.Min(original, snapLen);

    private static PcapError? ValidatePacketLength(PcapNgBlock block, uint captured, uint original, uint snapLen, int limit)
    {
        if (captured > original)
            return block.Error(12, $"Captured length {captured} exceeds original length {original}.");
        if (snapLen != 0 && captured > snapLen)
            return block.Error(12, $"Captured length {captured} exceeds interface SnapLen {snapLen}.");
        if (captured > limit)
            return block.Error(block.Type == 3 ? 0 : 12, $"Captured length {captured} exceeds the single-packet limit {limit}.");

        return null;
    }

    private static PcapError? ValidatePacketOptions(PcapNgBlock block, ImmutableArray<PcapNgOption> options)
    {
        foreach (var option in options)
        {
            int? required = option.Code switch
            {
                2 => 4,
                4 or 5 when block.Type == 6 => 8,
                6 when block.Type == 6 => 4,
                _ => null
            };
            if (required is { } length && option.Value.Length != length)
                return block.Error(20, $"Packet option {option.Code} requires {length} bytes.");
        }

        return null;
    }

    private static PcapNgPacket MakePacket(PcapNgBlock block, PcapNgInterface captureInterface,
        uint original, uint captured, ImmutableArray<PcapNgOption> options)
    {
        PcapNgPacketDetails details = new PcapNgPacketDetails.Simple();
        if (block.Type != 3)
        {
            var timestamp = new PcapNgTimestamp(((ulong)block.UInt32(4) << 32) | block.UInt32(8),
                captureInterface.TimestampResolution, captureInterface.TimestampOffsetSeconds);
            details = block.Type == 2
                ? new PcapNgPacketDetails.Obsolete(timestamp, block.UInt16(2))
                : new PcapNgPacketDetails.Enhanced(timestamp);
        }
        var bodyOffset = block.Type == 3 ? 4 : 20;
        var data = block.Body.Slice(bodyOffset, (int)captured);

        return new PcapNgPacket(captureInterface, original, data, options, details, block.Offset + 8 + bodyOffset);
    }

    private static OptionsResult Options(PcapNgBlock block, int start, int maxOptions)
    {
        var options = ImmutableArray.CreateBuilder<PcapNgOption>();
        int position = start;
        while (position < block.Body.Length)
        {
            if (block.Body.Length - position < 4)
                return block.Error(position, "Incomplete option header.");

            ushort code = block.UInt16(position);
            ushort length = block.UInt16(position + 2);
            position += 4;
            if (code == 0)
            {
                if (length != 0 || position != block.Body.Length)
                    return block.Error(position - 4, "End-of-options must have zero length and terminate the options.");

                return options.ToImmutable();
            }

            int padded = (length + 3) & ~3;
            if (padded > block.Body.Length - position)
                return block.Error(position - 2, $"Option {code} data and padding exceed the block body.");

            if (options.Count >= maxOptions)
                return block.Error(position - 4, $"Option count exceeds the configured per-block limit {maxOptions}.");

            options.Add(new PcapNgOption(code, block.Body.Slice(position, length)));
            position += padded;
        }

        return options.ToImmutable();
    }

    internal union SectionResult(PcapNgSection, PcapError);
    internal union InterfaceResult(PcapNgInterface, PcapError);
    internal union PacketResult(PcapNgPacket, PcapError);
    private union OptionsResult(ImmutableArray<PcapNgOption>, PcapError);
}
