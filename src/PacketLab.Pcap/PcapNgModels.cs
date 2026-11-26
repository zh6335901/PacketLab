using System.Collections.Immutable;
using System.Globalization;
using System.Numerics;
using System.Text;

namespace PacketLab.Pcap;

public sealed record PcapNgOption(ushort Code, ReadOnlyMemory<byte> Value)
{
    public string Text => Encoding.UTF8.GetString(Value.Span);
}

public sealed record PcapNgSection(long Number, long Offset, PcapByteOrder ByteOrder,
    ushort MajorVersion, ushort MinorVersion, long Length, ImmutableArray<PcapNgOption> Options);

public sealed record PcapNgInterface(PcapNgSection Section, uint Id, ushort LinkType, uint SnapLen,
    byte TimestampResolution, long TimestampOffsetSeconds, ImmutableArray<PcapNgOption> Options)
{
    public string? Name => Options.FirstOrDefault(option => option.Code == 2)?.Text;
    public string? Description => Options.FirstOrDefault(option => option.Code == 3)?.Text;
}

public readonly record struct PcapNgTimestamp(ulong RawValue, byte Resolution, long OffsetSeconds)
{
    public bool IsBinary => (Resolution & 0x80) != 0;
    public int Exponent => Resolution & 0x7f;
    public BigInteger UnitsPerSecond => BigInteger.Pow(IsBinary ? 2 : 10, Exponent);
    public BigInteger UnixTimeNumerator => RawValue + (BigInteger)OffsetSeconds * UnitsPerSecond;

    // Reassembly has nanosecond granularity; the original timestamp remains exact.
    public ulong? GetNanoseconds()
    {
        var numerator = UnixTimeNumerator;
        var nanoseconds = numerator * 1_000_000_000 / UnitsPerSecond;

        return numerator >= 0 && nanoseconds <= ulong.MaxValue ? (ulong)nanoseconds : null;
    }

    public override string ToString()
    {
        int digits = Exponent;
        var scaled = IsBinary ? UnixTimeNumerator * BigInteger.Pow(5, digits) : UnixTimeNumerator;
        var text = BigInteger.Abs(scaled).ToString(CultureInfo.InvariantCulture).PadLeft(digits + 1, '0');
        var number = digits == 0 ? text : text.Insert(text.Length - digits, ".");

        return (scaled.Sign < 0 ? "-" : "") + number + " s since Unix epoch";
    }
}

public enum PcapNgPacketKind { Enhanced, Simple, Obsolete }

public sealed class PcapNgPacket
{
    internal PcapNgPacket(PcapNgInterface captureInterface, uint originalLength, ReadOnlyMemory<byte> data,
        ImmutableArray<PcapNgOption> options, PcapNgPacketDetails details, long dataOffset)
    {
        Interface = captureInterface;
        OriginalLength = originalLength;
        Data = data;
        Options = options;
        Details = details;
        DataOffset = dataOffset;
    }

    public PcapNgInterface Interface { get; }
    public uint OriginalLength { get; }
    public ReadOnlyMemory<byte> Data { get; }
    public long DataOffset { get; }
    public ImmutableArray<PcapNgOption> Options { get; }
    public PcapNgPacketDetails Details { get; }
    public PcapNgTimestamp? Timestamp => Details switch
    {
        PcapNgPacketDetails.Enhanced enhanced => enhanced.Timestamp,
        PcapNgPacketDetails.Obsolete obsolete => obsolete.Timestamp,
        PcapNgPacketDetails.Simple => null,
        null => throw new InvalidOperationException("Uninitialized packet details.")
    };
    public PcapNgPacketKind Kind => Details switch
    {
        PcapNgPacketDetails.Enhanced => PcapNgPacketKind.Enhanced,
        PcapNgPacketDetails.Obsolete => PcapNgPacketKind.Obsolete,
        PcapNgPacketDetails.Simple => PcapNgPacketKind.Simple,
        null => throw new InvalidOperationException("Uninitialized packet details.")
    };
    public uint CapturedLength => (uint)Data.Length;
    public IEnumerable<string> Comments => Options.Where(option => option.Code == 1).Select(option => option.Text);
}

public union PcapNgPacketDetails(PcapNgPacketDetails.Enhanced, PcapNgPacketDetails.Simple, PcapNgPacketDetails.Obsolete)
{
    public sealed record Enhanced(PcapNgTimestamp Timestamp);
    public sealed record Simple;
    public sealed record Obsolete(PcapNgTimestamp Timestamp, ushort DropsCount);
}
