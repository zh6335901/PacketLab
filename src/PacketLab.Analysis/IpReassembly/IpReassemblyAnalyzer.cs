using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using System.Collections.Immutable;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Analysis.IpReassembly;

public sealed class IpReassemblyAnalyzer : IDisposable
{
    private readonly IpFragmentReassembler reassembler;
    private readonly IpReassemblyAnalysisOptions options;
    private readonly Dictionary<long, Association> associations = [];
    private bool disposed;

    public IpReassemblyAnalyzer(IpReassemblyAnalysisOptions? options = null)
    {
        this.options = options ?? new();
        reassembler = new(this.options.Reassembly);
    }

    // Record numbers are increasing within one capture. Time is normalized by the input adapter.
    public ImmutableArray<IpReassemblyEvent> Process(long recordNumber, ulong? timestampNanoseconds,
        ProtocolDecodeResult decoding)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var events = ImmutableArray.CreateBuilder<IpReassemblyEvent>();
        if (timestampNanoseconds is { } time)
        {
            foreach (var expired in reassembler.AdvanceTime(time))
                EndAssociation(expired, IpReassemblyAnalysisReason.Protocol, events);
        }
        foreach (var (id, association) in associations.ToArray())
        {
            if (recordNumber - association.FirstRecord < options.MaxRecordAge) continue;
            if (reassembler.Expire(id) is { } expired)
                EndAssociation(expired, IpReassemblyAnalysisReason.RecordAgeLimit, events);
        }
        if (decoding is not EthernetDecodeResult ethernet || ethernet is not DecodedEthernet frame ||
            frame.Frame.EtherType is not (0x0800 or 0x86dd)) return events.ToImmutable();
        if (!(frame.Payload is IPv4DecodeResult ipv4 && ipv4 is DecodedIPv4) &&
            !(frame.Payload is IPv6DecodeResult ipv6 && ipv6 is DecodedIPv6)) return events.ToImmutable();
        var ipBytes = frame.Frame.RemainingBytes;
        if (reassembler.FindDatagram(ipBytes) is { } existing && associations.TryGetValue(existing, out var prior) &&
            prior.Pending && prior.Records.Count >= options.MaxRecordsPerDatagram)
        {
            var discarded = reassembler.Discard(existing) ?? throw new InvalidOperationException("Missing reassembly state.");
            events.Add(new(prior.FirstRecord, [recordNumber], discarded, IpReassemblyAnalysisReason.RecordAssociationLimit));
            events.Add(new(prior.FirstRecord, [.. prior.Records], discarded, IpReassemblyAnalysisReason.RecordAssociationLimit));
            prior.Records.Clear();
            prior.Pending = false;
            prior.Reason = IpReassemblyAnalysisReason.RecordAssociationLimit;
            return events.ToImmutable();
        }
        if (reassembler.Process(ipBytes) is not { } update) return events.ToImmutable();
        if (!associations.TryGetValue(update.DatagramId, out var state)) state = new(recordNumber);
        var records = state.Pending ? Append(state.Records, recordNumber) : [recordNumber];
        events.Add(new(state.FirstRecord, records, update, state.Reason));
        if (!reassembler.IsRetained(update.DatagramId))
            associations.Remove(update.DatagramId);
        else
        {
            if (update.Status is not (IpReassemblyStatus.Pending or IpReassemblyStatus.Duplicate))
            {
                state.Pending = false;
                state.Records.Clear();
            }
            associations[update.DatagramId] = state;
        }
        return events.ToImmutable();
    }

    public ImmutableArray<IpReassemblyEvent> Finish(IpReassemblyAnalysisReason reason)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (reason is not (IpReassemblyAnalysisReason.EndOfCapture or IpReassemblyAnalysisReason.Aborted))
            throw new ArgumentOutOfRangeException(nameof(reason));
        var events = reassembler.Finish().Select(update =>
        {
            var state = associations[update.DatagramId];
            return new IpReassemblyEvent(state.FirstRecord, [.. state.Records], update, reason);
        }).ToImmutableArray();
        associations.Clear();
        return events;
    }

    public void Dispose()
    {
        reassembler.Dispose();
        associations.Clear();
        disposed = true;
    }

    private void EndAssociation(IpReassemblyUpdate update, IpReassemblyAnalysisReason reason,
        ImmutableArray<IpReassemblyEvent>.Builder events)
    {
        if (!associations.Remove(update.DatagramId, out var state)) return;
        if (state.Pending) events.Add(new(state.FirstRecord, [.. state.Records], update, reason));
    }

    private static ImmutableArray<long> Append(List<long> records, long record)
    {
        records.Add(record);
        return [.. records];
    }

    private sealed class Association(long firstRecord)
    {
        internal long FirstRecord { get; } = firstRecord;
        internal List<long> Records { get; } = [];
        internal bool Pending { get; set; } = true;
        internal IpReassemblyAnalysisReason Reason { get; set; } = IpReassemblyAnalysisReason.Protocol;
    }
}
