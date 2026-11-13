using System.Buffers.Binary;
using System.Collections.Immutable;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Protocols.IP.Reassembly;

public sealed class IpFragmentReassembler : IDisposable
{
    private readonly Dictionary<Key, Datagram> datagrams = [];
    private ulong clock;
    private int bufferedBytes;

    private readonly IpReassemblyOptions options;
    private long nextId;
    private bool disposed;

    public IpFragmentReassembler(IpReassemblyOptions? options = null) => this.options = options ?? new();

    // The caller supplies IP bytes, without a link-layer header. IDs are local to this instance.
    public IpReassemblyUpdate? Process(ReadOnlyMemory<byte> ipPacket)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (Extract(ipPacket) is not { } fragment) return null;
        var events = ImmutableArray.CreateBuilder<IpReassemblyUpdate>();
        Accept(fragment, ++nextId, events);
        return events.Single();
    }

    // A monotonic high-water mark makes reordered input timestamps safe.
    public ImmutableArray<IpReassemblyUpdate> AdvanceTime(ulong nanoseconds)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        clock = Math.Max(clock, nanoseconds);
        var events = ImmutableArray.CreateBuilder<IpReassemblyUpdate>();
        foreach (var (key, state) in datagrams.ToArray())
        {
            if (clock - state.StartTime < (ulong)options.TimeoutSeconds * 1_000_000_000UL) continue;
            events.Add(Event(state, IpReassemblyStatus.Expired, "reassembly timeout reached"));
            Remove(key, state);
        }
        return events.ToImmutable();
    }

    // Hosts may expire state according to their own input/lifecycle policy.
    public IpReassemblyUpdate? Expire(long datagramId)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        foreach (var (key, state) in datagrams)
        {
            if (state.Id != datagramId) continue;
            var result = Event(state, IpReassemblyStatus.Expired, "datagram expired by caller");
            Remove(key, state);
            return result;
        }
        return null;
    }

    public IpReassemblyUpdate? Discard(long datagramId)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var state = datagrams.Values.FirstOrDefault(x => x.Id == datagramId);
        if (state is null) return null;
        var events = ImmutableArray.CreateBuilder<IpReassemblyUpdate>();
        Fail(state, IpReassemblyStatus.Discarded, "datagram discarded by caller", events);
        return events.Single();
    }

    // Allows a host to enforce bounded input associations before accepting another fragment.
    public long? FindDatagram(ReadOnlyMemory<byte> ipPacket)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        return Extract(ipPacket) is { Atomic: false } fragment && datagrams.TryGetValue(fragment.Key, out var state)
            ? state.Id : null;
    }

    public bool IsRetained(long datagramId) => datagrams.Values.Any(x => x.Id == datagramId);

    public ImmutableArray<IpReassemblyUpdate> Finish()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var events = datagrams.Values.Where(x => x.Buffer is Collecting)
            .Select(x => Event(x, IpReassemblyStatus.Incomplete, "missing fragments")).ToImmutableArray();
        datagrams.Clear();
        bufferedBytes = 0;
        return events;
    }

    public void Dispose()
    {
        datagrams.Clear();
        bufferedBytes = 0;
        disposed = true;
    }

    private void Accept(Fragment fragment, long datagramId, ImmutableArray<IpReassemblyUpdate>.Builder events)
    {
        if (fragment.Atomic)
        {
            var atomic = new Datagram(fragment, datagramId, clock);
            var atomicFailure = Validate(fragment);
            if (atomicFailure is { } invalid)
                events.Add(Event(atomic, invalid.Status, invalid.Message));
            else
            {
                var packet = BuildPacket(fragment.Prefix, fragment, fragment.Bytes.Span);
                events.Add(Event(atomic, IpReassemblyStatus.Atomic, "independent atomic fragment",
                    Decode(packet, fragment.Key.Version)));
            }
            return;
        }

        if (!datagrams.TryGetValue(fragment.Key, out var state))
        {
            state = new Datagram(fragment, datagramId, clock);
            if (datagrams.Count >= options.MaxDatagrams)
            {
                events.Add(Event(state, IpReassemblyStatus.ResourceLimit, "datagram table limit reached (including discarded identities)"));
                return;
            }
            datagrams.Add(fragment.Key, state);
        }
        if (state.Buffer is Discarded discarded)
        {
            events.Add(new(state.Id, state.Version, state.Identification,
                "datagram already discarded; identity retained until expiry", new IpReassemblyDiagnostic(discarded.Status)));
            return;
        }
        var buffer = state.Buffer is Collecting collecting ? collecting : throw new InvalidOperationException();
        if (Validate(fragment) is { } failure)
        {
            Fail(state, failure.Status, failure.Message, events);
            return;
        }
        if (state.NextHeader != fragment.NextHeader || !Compatible(state, fragment))
        {
            Fail(state, IpReassemblyStatus.Conflict, "incompatible IP or extension header context", events);
            return;
        }
        var end = fragment.Offset + fragment.Bytes.Length;
        if ((buffer.Length is FinalLength { Value: var length } && (end > length || (fragment.More && end >= length) || (!fragment.More && end != length))) ||
            (!fragment.More && buffer.Parts.Any(x => x.Offset + x.Bytes.Length > end || (x.More && x.Offset + x.Bytes.Length >= end))))
        {
            Fail(state, IpReassemblyStatus.Conflict, "inconsistent final fragment length", events);
            return;
        }
        foreach (var part in buffer.Parts)
        {
            if (part.Offset >= end || part.Offset + part.Bytes.Length <= fragment.Offset) continue;
            if (part.Offset == fragment.Offset && part.More == fragment.More &&
                part.Bytes.AsSpan().SequenceEqual(fragment.Bytes.Span))
            {
                events.Add(Event(state, IpReassemblyStatus.Duplicate, "exact duplicate ignored"));
                return;
            }
            Fail(state, IpReassemblyStatus.Conflict, "overlap: entire datagram discarded", events);
            return;
        }

        if (buffer.Parts.Count >= options.MaxFragmentsPerDatagram)
        {
            Fail(state, IpReassemblyStatus.ResourceLimit, "fragment count limit reached", events);
            return;
        }

        var prefixBytes = buffer.Context is null ? fragment.Prefix.Length : 0;
        // Preserve the offset-zero header independently; it supplies the reconstructed IP context.
        var firstBytes = fragment.Offset == 0 ? fragment.Prefix.Length : 0;
        var needed = fragment.Bytes.Length + prefixBytes + firstBytes;
        if (needed > options.MaxBufferedBytes - bufferedBytes)
        {
            Fail(state, IpReassemblyStatus.ResourceLimit, "buffered byte limit reached", events);
            return;
        }
        buffer.Context ??= fragment.Prefix.ToArray();
        if (fragment.Offset == 0) buffer.First = new FirstHeader(fragment.Prefix.ToArray());
        buffer.Parts.Add(new(fragment.Offset, fragment.More, fragment.Bytes.ToArray()));
        buffer.Bytes += needed;
        bufferedBytes += needed;
        if (!fragment.More) buffer.Length = new FinalLength(end);
        if (buffer.First is FirstHeader { Bytes: var first } && buffer.Length is FinalLength { Value: var total })
        {
            var ipLength = first.Length + total;
            if (ipLength > (state.Version == 4 ? 65535 : 65575))
            {
                Fail(state, IpReassemblyStatus.Invalid, "reassembled IP length exceeds limit", events);
                return;
            }
            if (ipLength > options.MaxDatagramBytes)
            {
                Fail(state, IpReassemblyStatus.ResourceLimit, "single datagram byte limit reached", events);
                return;
            }
            var position = 0;
            foreach (var part in buffer.Parts.OrderBy(x => x.Offset))
            {
                if (part.Offset != position) break;
                position += part.Bytes.Length;
            }
            if (position == total)
            {
                var payload = new byte[total];
                foreach (var part in buffer.Parts) part.Bytes.CopyTo(payload, part.Offset);
                var packet = BuildPacket(first, fragment, payload);
                events.Add(Event(state, IpReassemblyStatus.Complete, "all fragment bytes captured", Decode(packet, fragment.Key.Version)));
                Remove(fragment.Key, state);
                return;
            }
        }
        events.Add(Event(state, IpReassemblyStatus.Pending, "waiting for contiguous fragments and final length"));
    }

    private (IpReassemblyStatus Status, string Message)? Validate(Fragment fragment)
    {
        if (fragment.Validity is InvalidFragment { Message: var invalid }) return (IpReassemblyStatus.Invalid, invalid);
        if (fragment.Bytes.Length != fragment.DeclaredLength)
            return (IpReassemblyStatus.Truncated, "fragment payload was not fully captured");
        if ((!fragment.Atomic && fragment.Bytes.Length == 0) || (fragment.More && fragment.Bytes.Length % 8 != 0))
            return (IpReassemblyStatus.Invalid, "invalid fragment length or eight-byte alignment");
        var size = (long)fragment.Offset + fragment.DeclaredLength + fragment.Prefix.Length;
        if (size > (fragment.Key.Version == 4 ? 65535 : 65575))
            return (IpReassemblyStatus.Invalid, "fragment range exceeds IP length limit");
        if (size > options.MaxDatagramBytes)
            return (IpReassemblyStatus.ResourceLimit, "single datagram byte limit reached");
        return null;
    }

    private static bool Compatible(Datagram state, Fragment fragment)
    {
        if (state.Buffer is not Collecting buffer || buffer.Context is not { } context) return true;
        if (fragment.Key.Version == 6)
        {
            // Payload length and hop limit may differ, but extension layout and context must agree.
            return context.Length == fragment.Prefix.Length &&
                context.AsSpan(0, 4).SequenceEqual(fragment.Prefix.Span.Slice(0, 4)) &&
                context[6] == fragment.Prefix.Span[6] &&
                context.AsSpan(40).SequenceEqual(fragment.Prefix.Span[40..]);
        }
        // IPv4 copied options may legitimately differ between first and subsequent fragments.
        return fragment.Offset != 0 || buffer.First is not FirstHeader { Bytes: var first } ||
            (first.Length == fragment.Prefix.Length && first.AsSpan(20).SequenceEqual(fragment.Prefix.Span[20..]));
    }

    private void Fail(Datagram state, IpReassemblyStatus status, string message,
        ImmutableArray<IpReassemblyUpdate>.Builder events)
    {
        events.Add(Event(state, status, message));
        if (state.Buffer is Collecting buffer) bufferedBytes -= buffer.Bytes;
        // A bounded tombstone prevents later fragments from reviving an ambiguous datagram.
        state.Buffer = new Discarded(status);
    }

    private void Remove(Key key, Datagram state)
    {
        if (state.Buffer is Collecting buffer) bufferedBytes -= buffer.Bytes;
        datagrams.Remove(key);
    }

    private static IpReassemblyUpdate Event(Datagram state, IpReassemblyStatus status, string message,
        ReassembledIpPacket? packet = null) =>
        new(state.Id, state.Version, state.Identification,
            message,
            packet is null ? new IpReassemblyDiagnostic(status) : status == IpReassemblyStatus.Atomic
                ? new IpReassemblyAtomic(packet) : new IpReassemblyComplete(packet));

    private static Fragment? Extract(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.IsEmpty) return null;
        var version = bytes.Span[0] >> 4;
        if (version == 4 && DecodedIPv4.Decode(bytes) is DecodedIPv4 v4 && v4.Payload is IPv4FragmentPayload f4)
        {
            var header = v4.Packet.Header;
            return new(new(4, header.Source.ToString(), header.Destination.ToString(), f4.Identification, f4.Protocol),
                f4.Offset * 8, f4.MoreFragments, false, f4.Protocol, f4.DeclaredLength, f4.Bytes,
                bytes[..header.HeaderLength], 0,
                header.DontFragment || header.ReservedFlag ? new InvalidFragment("invalid IPv4 fragmentation flags") : new ValidFragment());
        }
        if (version != 6 || DecodedIPv6.Decode(bytes) is not DecodedIPv6 v6) return null;
        var extension = v6.Extensions.FirstOrDefault(x => x.Fragment is not null);
        if (extension?.Fragment is not { } f6 || v6.Capture is not IPv6Payload.KnownLength capture) return null;
        var offset = extension.Offset + 8;
        var declared = (long)capture.DeclaredLength - (offset - 40);
        if (declared < 0) return null;
        var available = Math.Min((int)declared, Math.Max(0, bytes.Length - offset));
        var previous = v6.Extensions.LastOrDefault(x => x.Offset < extension.Offset);
        var fragment = new Fragment(new(6, v6.Header.Source.ToString(), v6.Header.Destination.ToString(), f6.Identification, 0),
            f6.OffsetBytes, f6.MoreFragments, f6.IsAtomic, f6.NextHeader, (uint)declared,
            bytes.Slice(offset, available), bytes[..extension.Offset],
            previous is null ? 6 : previous.Offset, new ValidFragment());
        if (v6.Diagnostics.Any(x => x.Code is not (IPv6DiagnosticCode.ReassemblyRequired or
                IPv6DiagnosticCode.PayloadTruncated or IPv6DiagnosticCode.FinalDestinationUnavailable or
                IPv6DiagnosticCode.SourceAddressUnavailable)))
            return fragment with { Validity = new InvalidFragment("invalid or incomplete IPv6 extension chain") };
        if (f6.Offset == 0 && fragment.Bytes.Length == declared && !FirstHeadersComplete(fragment))
            return fragment with { Validity = new InvalidFragment("IPv6 first fragment lacks a complete upper-layer header chain") };
        return fragment;
    }

    private static bool FirstHeadersComplete(Fragment fragment)
    {
        if (fragment.NextHeader == 0) return false; // Hop-by-Hop cannot follow the Fragment header.
        var packet = BuildPacket(fragment.Prefix, fragment, fragment.Bytes.Span);
        if (IPv6Parser.Parse(packet) is not IPv6Packet parsed) return false;
        if (parsed.Extensions.Headers.Any(x => x.Type == 44)) return false;
        if (parsed.Extensions.Result is IPv6NoNextHeader) return true;
        if (parsed.Extensions.Result is not IPv6UpperLayer upper) return false;
        var bytes = upper.Bytes.Span;
        return upper.Protocol switch
        {
            6 => bytes.Length >= 20 && (bytes[12] >> 4) >= 5 && bytes.Length >= (bytes[12] >> 4) * 4,
            17 => bytes.Length >= 8,
            58 => bytes.Length >= 4,
            132 => bytes.Length >= 12,
            4 => bytes.Length >= 20 && (bytes[0] & 15) >= 5 && bytes.Length >= (bytes[0] & 15) * 4,
            41 => bytes.Length >= 40,
            _ => true
        };
    }

    private static byte[] BuildPacket(ReadOnlyMemory<byte> prefix, Fragment fragment, ReadOnlySpan<byte> payload)
    {
        var bytes = new byte[prefix.Length + payload.Length];
        prefix.Span.CopyTo(bytes);
        payload.CopyTo(bytes.AsSpan(prefix.Length));
        var ip = bytes.AsSpan();
        if (fragment.Key.Version == 4)
        {
            BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)ip.Length);
            ip[6] = ip[7] = ip[10] = ip[11] = 0;
            uint sum = 0;
            for (var i = 0; i < prefix.Length; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(ip[i..]);
            while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
            BinaryPrimitives.WriteUInt16BigEndian(ip[10..], (ushort)~sum);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(ip[4..], (ushort)(ip.Length - 40));
            bytes[fragment.PreviousNextHeader] = fragment.NextHeader;
        }
        return bytes;
    }

    private static ReassembledIpPacket Decode(byte[] bytes, int version) =>
        new(bytes, version == 4 ? DecodedIPv4.Decode(bytes) : DecodedIPv6.Decode(bytes));

    private readonly record struct Key(int Version, string Source, string Destination, uint Identification, byte Protocol);
    private sealed record Fragment(Key Key, int Offset, bool More, bool Atomic, byte NextHeader,
        uint DeclaredLength, ReadOnlyMemory<byte> Bytes, ReadOnlyMemory<byte> Prefix, int PreviousNextHeader, FragmentValidity Validity);
    private union FragmentValidity(ValidFragment, InvalidFragment);
    private sealed record ValidFragment;
    private sealed record InvalidFragment(string Message);
    private sealed record Part(int Offset, bool More, byte[] Bytes);
    private sealed class Datagram(Fragment fragment, long id, ulong time)
    {
        internal long Id { get; } = id;
        internal ulong StartTime { get; } = time;
        internal int Version { get; } = fragment.Key.Version;
        internal uint Identification { get; } = fragment.Key.Identification;
        internal byte NextHeader { get; } = fragment.NextHeader;
        internal BufferState Buffer { get; set; } = new Collecting();
    }
    private union BufferState(Collecting, Discarded);
    private sealed record Discarded(IpReassemblyStatus Status);
    private union FirstHeaderState(MissingFirstHeader, FirstHeader);
    private sealed record MissingFirstHeader;
    private sealed record FirstHeader(byte[] Bytes);
    private union LengthState(UnknownLength, FinalLength);
    private sealed record UnknownLength;
    private sealed record FinalLength(int Value);
    private sealed class Collecting
    {
        internal List<Part> Parts { get; } = [];
        internal byte[]? Context { get; set; }
        internal FirstHeaderState First { get; set; } = new MissingFirstHeader();
        internal LengthState Length { get; set; } = new UnknownLength();
        internal int Bytes { get; set; }
    }
}
