using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using System.Collections.Immutable;
using PacketLab.Protocols.IP.Reassembly;

namespace PacketLab.Analysis.IpReassembly;

public sealed class IpReassemblyAnalyzer : IDisposable
{
    private readonly IpFragmentReassembler reassembler;
    private readonly IpReassemblyAnalysisOptions options;
    private readonly Dictionary<long, Association> associations = [];
    private bool disposed;

    public IpReassemblyAnalyzer(IpReassemblyAnalysisOptions? options)
    {
        this.options = options ?? IpReassemblyAnalysisOptions.Default;
        reassembler = new(this.options.Reassembly);
    }

    public void AdvanceTime(ulong timestampNanoseconds)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        reassembler.AdvanceTime(timestampNanoseconds);
    }

    public ImmutableArray<IpReassemblyEvent> Expire(long recordNumber)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var events = ImmutableArray.CreateBuilder<IpReassemblyEvent>();
        foreach (var expired in reassembler.Expire())
            EndAssociation(expired, IpReassemblyAnalysisReason.Protocol, events);
        foreach (var (id, association) in associations.ToArray())
        {
            if (recordNumber - association.FirstRecord < options.MaxRecordAge)
                continue;

            if (reassembler.Expire(id) is { } expired)
                EndAssociation(expired, IpReassemblyAnalysisReason.RecordAgeLimit, events);
        }

        return events.ToImmutable();
    }

    public ImmutableArray<IpReassemblyEvent> AddIPv4Fragment(long recordNumber, ReadOnlyMemory<byte> bytes,
        DecodedIPv4 packet, IPv4FragmentPayload fragment)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var events = ImmutableArray.CreateBuilder<IpReassemblyEvent>();
        var existing = reassembler.FindDatagram(packet, fragment);
        if (!DiscardAtRecordLimit(existing, recordNumber, events))
        {
            var update = reassembler.AddIPv4Fragment(bytes, packet, fragment);
            AssociateRecord(update, recordNumber, events);
        }

        return events.ToImmutable();
    }

    public ImmutableArray<IpReassemblyEvent> AddIPv6Fragment(long recordNumber, ReadOnlyMemory<byte> bytes,
        DecodedIPv6 packet, IPv6ExtensionHeader extension, IPv6Fragment fragment)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var events = ImmutableArray.CreateBuilder<IpReassemblyEvent>();
        var existing = reassembler.FindDatagram(packet, fragment);
        if (!DiscardAtRecordLimit(existing, recordNumber, events))
        {
            var update = reassembler.AddIPv6Fragment(bytes, packet, extension, fragment);
            AssociateRecord(update, recordNumber, events);
        }

        return events.ToImmutable();
    }

    private bool DiscardAtRecordLimit(long? datagramId, long recordNumber,
        ImmutableArray<IpReassemblyEvent>.Builder events)
    {
        if (datagramId is { } existing && associations.TryGetValue(existing, out var prior) &&
            prior.Pending && prior.Records.Count >= options.MaxRecordsPerDatagram)
        {
            var discarded = reassembler.Discard(existing) ?? throw new InvalidOperationException("Missing reassembly state.");
            events.Add(new(prior.FirstRecord, [recordNumber], discarded, IpReassemblyAnalysisReason.RecordAssociationLimit));
            events.Add(new(prior.FirstRecord, [.. prior.Records], discarded, IpReassemblyAnalysisReason.RecordAssociationLimit));
            prior.Records.Clear();
            prior.Pending = false;
            prior.Reason = IpReassemblyAnalysisReason.RecordAssociationLimit;

            return true;
        }

        return false;
    }

    private void AssociateRecord(IpReassemblyUpdate update, long recordNumber,
        ImmutableArray<IpReassemblyEvent>.Builder events)
    {
        if (!associations.TryGetValue(update.DatagramId, out var state))
            state = new(recordNumber);
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
    }

    public ImmutableArray<IpReassemblyEvent> Finish(IpReassemblyAnalysisReason reason)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (reason is not (IpReassemblyAnalysisReason.EndOfCapture or IpReassemblyAnalysisReason.EndOfSection or IpReassemblyAnalysisReason.Aborted))
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
        if (!associations.Remove(update.DatagramId, out var state))
            return;

        if (state.Pending)
            events.Add(new(state.FirstRecord, [.. state.Records], update, reason));
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
