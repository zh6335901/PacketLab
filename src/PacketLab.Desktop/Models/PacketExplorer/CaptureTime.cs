using PacketLab.Desktop.Localization;
using System.Globalization;
using System.Numerics;
using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;

namespace PacketLab.Desktop.Models.PacketExplorer;

internal enum TimeKind : byte { Missing, Present, Invalid }

internal readonly record struct CaptureTime(ulong Raw, byte Resolution, long Offset, TimeKind Kind)
{
    internal static CaptureTime From(PcapTimestamp value)
    {
        var digits = value.Precision == PcapTimestampPrecision.Microseconds ? (byte)6 : (byte)9;
        var scale = digits == 6 ? 1_000_000UL : 1_000_000_000UL;
        if (PcapAnalysis.GetTimestampNanoseconds(value) is null)
            return new(value.Fraction, digits, value.Seconds, TimeKind.Invalid);

        return new(value.Seconds * scale + value.Fraction, digits, 0, TimeKind.Present);
    }

    internal static CaptureTime From(PcapNgTimestamp? value) => value is { } stamp
        ? new(stamp.RawValue, stamp.Resolution, stamp.OffsetSeconds, TimeKind.Present) : default;

    private PcapNgTimestamp Timestamp => new(Raw, Resolution, Offset);

    internal ulong? Nanoseconds()
    {
        if (Kind != TimeKind.Present)
            return null;
        if (Offset != 0)
            return Timestamp.GetNanoseconds();

        return Resolution switch
        {
            6 when Raw <= ulong.MaxValue / 1_000 => Raw * 1_000,
            9 => Raw,
            _ => Timestamp.GetNanoseconds()
        };
    }

    internal int CompareTo(CaptureTime other)
    {
        if (Resolution == other.Resolution && Offset == other.Offset)
            return Raw.CompareTo(other.Raw);

        var left = Timestamp;
        var right = other.Timestamp;

        return (left.UnixTimeNumerator * right.UnitsPerSecond).CompareTo(right.UnixTimeNumerator * left.UnitsPerSecond);
    }

    internal string Format(bool date = false)
    {
        if (Kind == TimeKind.Missing)
            return Strings.NotProvided;
        if (Kind == TimeKind.Invalid)
            return UIText.Format(Strings.InvalidTimestampValue, Offset, (Resolution == 6 ? Strings.Microseconds : Strings.Nanoseconds), Raw);

        var timestamp = Timestamp;
        var units = timestamp.UnitsPerSecond;
        var seconds = BigInteger.DivRem(timestamp.UnixTimeNumerator, units, out var fraction);
        if (fraction.Sign < 0)
        {
            seconds--;
            fraction += units;
        }
        if (seconds < -62_135_596_800L || seconds > 253_402_300_799L)
            return timestamp.ToString();

        var time = DateTimeOffset.FromUnixTimeSeconds((long)seconds);
        var digits = timestamp.Exponent;
        if (timestamp.IsBinary)
            fraction *= BigInteger.Pow(5, digits);
        var clock = time.ToString(date ? "yyyy-MM-dd HH:mm:ss" : "HH:mm:ss", CultureInfo.InvariantCulture);
        if (digits > 0)
            clock += "." + fraction.ToString(CultureInfo.InvariantCulture).PadLeft(digits, '0');

        return date ? clock + " UTC" : clock;
    }
}
