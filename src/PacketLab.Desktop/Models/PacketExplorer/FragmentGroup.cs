using PacketLab.Analysis.IpReassembly;
using PacketLab.Analyzers.Annotations;
using PacketLab.Protocols.IP.Reassembly;
using System.Collections.Immutable;

namespace PacketLab.Desktop.Models.PacketExplorer;

[TransportModel]
internal sealed record FragmentGroup(int Version, uint Identification, ImmutableArray<int> Records,
    IpReassemblyStatus Status, IpReassemblyAnalysisReason Reason, IpReassemblyDiagnosticCode DiagnosticCode, long DerivedOffset, int DerivedLength,
    FragmentSlice? DerivedSlice, PacketSummary DerivedSummary)
{
    internal string Identity => Version == 4 ? $"IPv4 / 0x{Identification:X4}" : $"IPv6 / 0x{Identification:X8}";
    internal bool HasResult => DerivedLength > 0;
    internal bool Failed => Status is not (IpReassemblyStatus.Pending or IpReassemblyStatus.Duplicate
        or IpReassemblyStatus.Complete or IpReassemblyStatus.Atomic);
}
