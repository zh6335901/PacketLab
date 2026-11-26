using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Protocols.IP.Reassembly;

public enum IpReassemblyStatus
{
    Pending, Duplicate, Complete, Atomic, Truncated, Invalid, Conflict, Expired,
    ResourceLimit, Incomplete, Discarded
}

public sealed record IpReassemblyUpdate(long DatagramId, int IpVersion, uint Identification,
    string Message, IpReassemblyOutcome Outcome)
{
    public IpReassemblyDiagnosticCode DiagnosticCode { get; init; }

    public IpReassemblyStatus Status => Outcome switch
    {
        IpReassemblyDiagnostic diagnostic => diagnostic.Status,
        IpReassemblyComplete => IpReassemblyStatus.Complete,
        IpReassemblyAtomic => IpReassemblyStatus.Atomic,
        null => throw new InvalidOperationException("Uninitialized reassembly outcome.")
    };
    public ReassembledIpPacket? Packet => Outcome switch
    {
        IpReassemblyComplete complete => complete.Packet,
        IpReassemblyAtomic atomic => atomic.Packet,
        _ => null
    };
}

public union IpReassemblyOutcome(IpReassemblyDiagnostic, IpReassemblyComplete, IpReassemblyAtomic);
public sealed record IpReassemblyDiagnostic
{
    public IpReassemblyDiagnostic(IpReassemblyStatus status)
    {
        if (status is IpReassemblyStatus.Complete or IpReassemblyStatus.Atomic || !Enum.IsDefined(status))
            throw new ArgumentOutOfRangeException(nameof(status));

        Status = status;
    }
    public IpReassemblyStatus Status { get; }
}
public sealed record IpReassemblyComplete(ReassembledIpPacket Packet);
public sealed record IpReassemblyAtomic(ReassembledIpPacket Packet);

public union ReassembledIpDecoding(IPv4DecodeResult, IPv6DecodeResult);
// Owned IP bytes, independent of input buffers and the reassembler's lifetime.
public sealed record ReassembledIpPacket(ReadOnlyMemory<byte> Bytes, ReassembledIpDecoding Decoding);

public sealed class IpReassemblyOptions
{
    public static IpReassemblyOptions Default { get; } = new(
        maxDatagrams: 1024, maxBufferedBytes: 16 * 1024 * 1024, maxDatagramBytes: 65575,
        maxFragmentsPerDatagram: 1024, timeoutSeconds: 60);

    public IpReassemblyOptions(int maxDatagrams, int maxBufferedBytes,
        int maxDatagramBytes, int maxFragmentsPerDatagram, int timeoutSeconds)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxDatagrams);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBufferedBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxDatagramBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxDatagramBytes, 65575);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxFragmentsPerDatagram);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(timeoutSeconds);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(timeoutSeconds, 60);
        MaxDatagrams = maxDatagrams;
        MaxBufferedBytes = maxBufferedBytes;
        MaxDatagramBytes = maxDatagramBytes;
        MaxFragmentsPerDatagram = maxFragmentsPerDatagram;
        TimeoutSeconds = timeoutSeconds;
    }

    public int MaxDatagrams { get; }
    public int MaxBufferedBytes { get; }
    public int MaxDatagramBytes { get; }
    public int MaxFragmentsPerDatagram { get; }
    public int TimeoutSeconds { get; }
}
