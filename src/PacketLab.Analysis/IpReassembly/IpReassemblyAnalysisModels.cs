using System.Collections.Immutable;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Analysis.IpReassembly;

public enum IpReassemblyAnalysisReason { Protocol, EndOfCapture, Aborted, RecordAgeLimit, RecordAssociationLimit }

// Protocol outcomes are preserved; capture-specific reasons and record associations are added here.
public sealed record IpReassemblyEvent(long DatagramNumber, ImmutableArray<long> RecordNumbers,
    IpReassemblyUpdate Reassembly, IpReassemblyAnalysisReason Reason = IpReassemblyAnalysisReason.Protocol)
{
    public int IpVersion => Reassembly.IpVersion;
    public uint Identification => Reassembly.Identification;
    public IpReassemblyStatus Status => Reassembly.Status;
    public ReassembledIpPacket? Packet => Reassembly.Packet;
}

public sealed class IpReassemblyAnalysisOptions
{
    public IpReassemblyAnalysisOptions(IpReassemblyOptions? reassembly = null,
        int maxRecordsPerDatagram = 1024, int maxRecordAge = 100000)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxRecordsPerDatagram);
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(maxRecordAge);
        Reassembly = reassembly ?? new();
        MaxRecordsPerDatagram = maxRecordsPerDatagram;
        MaxRecordAge = maxRecordAge;
    }

    public IpReassemblyOptions Reassembly { get; }
    public int MaxRecordsPerDatagram { get; }
    public int MaxRecordAge { get; }
}
