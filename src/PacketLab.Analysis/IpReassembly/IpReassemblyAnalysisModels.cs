using System.Collections.Immutable;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Analysis.IpReassembly;

public enum IpReassemblyAnalysisReason { Protocol, EndOfCapture, Aborted, RecordAgeLimit, RecordAssociationLimit, EndOfSection }

// Protocol outcomes are preserved; capture-specific reasons and record associations are added here.
public sealed record IpReassemblyEvent(long DatagramNumber, ImmutableArray<long> RecordNumbers,
    IpReassemblyUpdate Reassembly, IpReassemblyAnalysisReason Reason)
{
    public int IpVersion => Reassembly.IpVersion;
    public uint Identification => Reassembly.Identification;
    public IpReassemblyStatus Status => Reassembly.Status;
    public ReassembledIpPacket? Packet => Reassembly.Packet;
}

public sealed class IpReassemblyAnalysisOptions
{
    public static IpReassemblyAnalysisOptions Default { get; } =
        new(IpReassemblyOptions.Default, maxRecordsPerDatagram: 1024, maxRecordAge: 100_000);

    public IpReassemblyAnalysisOptions(IpReassemblyOptions? reassembly,
        int maxRecordsPerDatagram, int maxRecordAge)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxRecordsPerDatagram);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxRecordAge);
        Reassembly = reassembly ?? IpReassemblyOptions.Default;
        MaxRecordsPerDatagram = maxRecordsPerDatagram;
        MaxRecordAge = maxRecordAge;
    }

    public IpReassemblyOptions Reassembly { get; }
    public int MaxRecordsPerDatagram { get; }
    public int MaxRecordAge { get; }
}
