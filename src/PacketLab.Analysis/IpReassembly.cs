using System.Collections.Immutable;
using PacketLab.Protocols;

namespace PacketLab.Analysis;

public enum IpReassemblyStatus
{
    Pending, Duplicate, Complete, Atomic, Truncated, Invalid, Conflict, Expired,
    ResourceLimit, IncompleteAtEndOfFile, Aborted
}

// Datagram numbers are the first observed record number, scoped to one reader/capture.
public sealed record IpReassemblyEvent(long DatagramNumber, int IpVersion, uint Identification,
    ImmutableArray<long> RecordNumbers, string Message, IpReassemblyOutcome Outcome)
{
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

// Owned bytes, independent of both the original records and the reader's cache lifetime.
public sealed record ReassembledIpPacket(ReadOnlyMemory<byte> Frame, ProtocolDecodeResult Decoding);

public sealed class IpReassemblyOptions
{
    public IpReassemblyOptions(int maxDatagrams = 1024, int maxBufferedBytes = 16 * 1024 * 1024,
        int maxDatagramBytes = 65575, int maxRecordsPerDatagram = 1024,
        int timeoutSeconds = 60, int maxRecordAge = 100000)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxDatagrams);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxBufferedBytes);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxDatagramBytes);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(maxDatagramBytes, 65575);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxRecordsPerDatagram);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(timeoutSeconds);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(timeoutSeconds, 60);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxRecordAge);
        MaxDatagrams = maxDatagrams;
        MaxBufferedBytes = maxBufferedBytes;
        MaxDatagramBytes = maxDatagramBytes;
        MaxRecordsPerDatagram = maxRecordsPerDatagram;
        TimeoutSeconds = timeoutSeconds;
        MaxRecordAge = maxRecordAge;
    }

    public int MaxDatagrams { get; }
    public int MaxBufferedBytes { get; }
    public int MaxDatagramBytes { get; }
    public int MaxRecordsPerDatagram { get; }
    public int TimeoutSeconds { get; }
    public int MaxRecordAge { get; }
}
