using System.Buffers.Binary;
using System.Collections.Immutable;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Protocols.IP.Reassembly;

public sealed class IpFragmentReassembler : IDisposable
{
    private readonly Dictionary<Key, Datagram> datagrams = [];
    private ulong clock;
    private ulong oldestStartTime;
    private int bufferedBytes;

    private readonly IpReassemblyOptions options;
    private long nextId;
    private bool disposed;

    public IpFragmentReassembler(IpReassemblyOptions? options = null) => this.options = options ?? new();

    // The caller supplies IP bytes, without a link-layer header. IDs are local to this instance.
    public IpReassemblyUpdate? Process(ReadOnlyMemory<byte> ipPacket)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (Extract(ipPacket) is not { } fragment)
            return null;

        return Accept(fragment, ++nextId);
    }

    public IpReassemblyUpdate AddIPv4Fragment(ReadOnlyMemory<byte> bytes, DecodedIPv4 packet,
        IPv4FragmentPayload fragment)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var input = ExtractIPv4(bytes, packet, fragment);

        return Accept(input, ++nextId);
    }

    public IpReassemblyUpdate AddIPv6Fragment(ReadOnlyMemory<byte> bytes, DecodedIPv6 packet,
        IPv6ExtensionHeader extension, IPv6Fragment fragment)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var input = ExtractIPv6(bytes, packet, extension, fragment)
            ?? throw new ArgumentException("The fragment must have a known, valid payload length.", nameof(packet));

        return Accept(input, ++nextId);
    }

    // A monotonic high-water mark makes reordered input timestamps safe.
    public void AdvanceTime(ulong nanoseconds)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        clock = Math.Max(clock, nanoseconds);
    }

    public ImmutableArray<IpReassemblyUpdate> Expire()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        if (datagrams.Count == 0)
            return [];

        var timeout = (ulong)options.TimeoutSeconds * 1_000_000_000UL;

        return clock - oldestStartTime < timeout ? [] : ExpireDatagrams(timeout);
    }

    private ImmutableArray<IpReassemblyUpdate> ExpireDatagrams(ulong timeout)
    {
        var nextOldest = clock;
        ImmutableArray<IpReassemblyUpdate>.Builder? events = null;
        // Dictionary.Remove preserves enumeration on .NET Core 3.0 and later.
        foreach (var (key, state) in datagrams)
        {
            if (clock - state.StartTime < timeout)
            {
                nextOldest = Math.Min(nextOldest, state.StartTime);
                continue;
            }

            (events ??= ImmutableArray.CreateBuilder<IpReassemblyUpdate>())
                .Add(Event(state, IpReassemblyStatus.Expired, IpReassemblyDiagnosticCode.TimedOut));
            Remove(key, state);
        }
        oldestStartTime = nextOldest;

        return events?.ToImmutable() ?? [];
    }

    // Hosts may expire state according to their own input/lifecycle policy.
    public IpReassemblyUpdate? Expire(long datagramId)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        foreach (var (key, state) in datagrams)
        {
            if (state.Id != datagramId)
                continue;

            var result = Event(state, IpReassemblyStatus.Expired, IpReassemblyDiagnosticCode.ExpiredByCaller);
            Remove(key, state);

            return result;
        }

        return null;
    }

    public IpReassemblyUpdate? Discard(long datagramId)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var state = datagrams.Values.FirstOrDefault(x => x.Id == datagramId);
        if (state is null)
            return null;

        return Fail(state, IpReassemblyStatus.Discarded, IpReassemblyDiagnosticCode.DiscardedByCaller);
    }

    // Allows a host to enforce bounded input associations before accepting another fragment.
    public long? FindDatagram(ReadOnlyMemory<byte> ipPacket)
    {
        ObjectDisposedException.ThrowIf(disposed, this);

        return Extract(ipPacket) is { Atomic: false } fragment && datagrams.TryGetValue(fragment.Key, out var state)
            ? state.Id : null;
    }

    public long? FindDatagram(DecodedIPv4 packet, IPv4FragmentPayload fragment)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var key = GetKey(packet, fragment);

        return datagrams.TryGetValue(key, out var state) ? state.Id : null;
    }

    public long? FindDatagram(DecodedIPv6 packet, IPv6Fragment fragment)
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var key = new Key(6, packet.Header.Source, packet.Header.Destination, fragment.Identification, 0);

        return !fragment.IsAtomic && datagrams.TryGetValue(key, out var state) ? state.Id : null;
    }

    public bool IsRetained(long datagramId) => datagrams.Values.Any(x => x.Id == datagramId);

    public ImmutableArray<IpReassemblyUpdate> Finish()
    {
        ObjectDisposedException.ThrowIf(disposed, this);
        var events = datagrams.Values.Where(x => x.Buffer is Collecting)
            .Select(x => Event(x, IpReassemblyStatus.Incomplete, IpReassemblyDiagnosticCode.MissingFragments)).ToImmutableArray();
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

    private IpReassemblyUpdate Accept(Fragment fragment, long datagramId)
    {
        if (fragment.Atomic)
            return AcceptAtomic(fragment, datagramId);

        if (!datagrams.TryGetValue(fragment.Key, out var state))
        {
            state = new Datagram(fragment, datagramId, clock);
            if (datagrams.Count >= options.MaxDatagrams)
                return Event(state, IpReassemblyStatus.ResourceLimit, IpReassemblyDiagnosticCode.DatagramTableLimit);

            // Starts are monotonic. Removing the oldest entry can only cause an extra early scan.
            if (datagrams.Count == 0)
                oldestStartTime = clock;
            datagrams.Add(fragment.Key, state);
        }
        if (state.Buffer is Discarded discarded)
            return Event(state, discarded.Status, IpReassemblyDiagnosticCode.AlreadyDiscarded);

        var buffer = state.Buffer is Collecting collecting ? collecting : throw new InvalidOperationException();

        return AcceptFragment(state, buffer, fragment);
    }

    private IpReassemblyUpdate AcceptAtomic(Fragment fragment, long datagramId)
    {
        var state = new Datagram(fragment, datagramId, clock);
        if (Validate(fragment) is { } invalid)
            return Event(state, invalid.Status, invalid.Code);

        var packet = BuildPacket(fragment.Prefix, fragment, fragment.Bytes.Span);
        var decodedPacket = Decode(packet, fragment.Key.Version);

        return Event(state, IpReassemblyStatus.Atomic, IpReassemblyDiagnosticCode.AtomicFragment, decodedPacket);
    }

    private IpReassemblyUpdate AcceptFragment(Datagram state, Collecting buffer, Fragment fragment)
    {
        if (ValidateForDatagram(state, buffer, fragment) is { } failure)
            return Fail(state, failure.Status, failure.Code);

        var end = fragment.Offset + fragment.Bytes.Length;
        foreach (var part in buffer.Parts)
        {
            if (part.Offset >= end || part.Offset + part.Bytes.Length <= fragment.Offset)
                continue;
            if (part.Offset == fragment.Offset && part.More == fragment.More &&
                part.Bytes.AsSpan().SequenceEqual(fragment.Bytes.Span))
            {
                return Event(state, IpReassemblyStatus.Duplicate, IpReassemblyDiagnosticCode.DuplicateIgnored);
            }

            return Fail(state, IpReassemblyStatus.Conflict, IpReassemblyDiagnosticCode.OverlapDiscarded);
        }

        if (BufferFragment(buffer, fragment, end) is { } limit)
            return Fail(state, limit.Status, limit.Code);

        return CompleteOrWait(state, buffer, fragment);
    }

    private IpReassemblyUpdate CompleteOrWait(Datagram state, Collecting buffer, Fragment fragment)
    {
        if (buffer.First is FirstHeader { Bytes: var first } && buffer.Length is FinalLength { Value: var total })
        {
            var ipLength = first.Length + total;
            if (ipLength > (state.Version == 4 ? 65535 : 65575))
                return Fail(state, IpReassemblyStatus.Invalid, IpReassemblyDiagnosticCode.IpLengthLimit);
            if (ipLength > options.MaxDatagramBytes)
                return Fail(state, IpReassemblyStatus.ResourceLimit, IpReassemblyDiagnosticCode.DatagramByteLimit);
            // Accepted parts cannot overlap or exceed the final length, so equal byte counts prove coverage.
            if (buffer.PayloadBytes == total)
            {
                var payload = new byte[total];
                foreach (var part in buffer.Parts)
                    part.Bytes.CopyTo(payload, part.Offset);
                var packet = BuildPacket(first, fragment, payload, (buffer.EcnCodepoints & 0b1000) != 0);
                var decodedPacket = Decode(packet, fragment.Key.Version);
                var update = Event(state, IpReassemblyStatus.Complete, IpReassemblyDiagnosticCode.CompleteCoverage, decodedPacket);
                Remove(fragment.Key, state);

                return update;
            }
        }

        return Event(state, IpReassemblyStatus.Pending, IpReassemblyDiagnosticCode.AwaitingFragments);
    }

    private (IpReassemblyStatus Status, IpReassemblyDiagnosticCode Code)? ValidateForDatagram(
        Datagram state, Collecting buffer, Fragment fragment)
    {
        if (Validate(fragment) is { } failure)
            return failure;
        if (state.NextHeader != fragment.NextHeader || !Compatible(state, fragment))
            return (IpReassemblyStatus.Conflict, IpReassemblyDiagnosticCode.IncompatibleHeaders);

        if (state.Version == 4)
        {
            // RFC 3168 §5.3: even duplicate fragments may carry a new CE marking.
            buffer.EcnCodepoints |= 1 << (fragment.Prefix.Span[1] & 3);
            if ((buffer.EcnCodepoints & 0b1001) == 0b1001)
                return (IpReassemblyStatus.Conflict, IpReassemblyDiagnosticCode.IncompatibleEcn);
        }
        var end = fragment.Offset + fragment.Bytes.Length;
        if (ConflictsWithFinalLength(buffer, end, fragment.More))
            return (IpReassemblyStatus.Conflict, IpReassemblyDiagnosticCode.InconsistentFinalLength);

        return null;
    }

    private (IpReassemblyStatus Status, IpReassemblyDiagnosticCode Code)? BufferFragment(Collecting buffer, Fragment fragment, int end)
    {
        if (buffer.Parts.Count >= options.MaxFragmentsPerDatagram)
            return (IpReassemblyStatus.ResourceLimit, IpReassemblyDiagnosticCode.FragmentCountLimit);

        var prefixBytes = buffer.Context is null ? fragment.Prefix.Length : 0;
        // Preserve the offset-zero header independently; it supplies the reconstructed IP context.
        var firstBytes = fragment.Offset == 0 ? fragment.Prefix.Length : 0;
        var needed = fragment.Bytes.Length + prefixBytes + firstBytes;
        if (needed > options.MaxBufferedBytes - bufferedBytes)
            return (IpReassemblyStatus.ResourceLimit, IpReassemblyDiagnosticCode.BufferLimit);

        buffer.Context ??= fragment.Prefix.ToArray();
        if (fragment.Offset == 0)
            buffer.First = new FirstHeader(fragment.Prefix.ToArray());
        buffer.Parts.Add(new(fragment.Offset, fragment.More, fragment.Bytes.ToArray()));
        buffer.PayloadBytes += fragment.Bytes.Length;
        buffer.Bytes += needed;
        bufferedBytes += needed;
        if (!fragment.More)
            buffer.Length = new FinalLength(end);

        return null;
    }

    private static bool ConflictsWithFinalLength(Collecting buffer, int end, bool more)
    {
        if (buffer.Length is FinalLength final && (more ? end >= final.Value : end != final.Value))
            return true;

        if (!more)
        {
            foreach (var part in buffer.Parts)
            {
                var partEnd = part.Offset + part.Bytes.Length;
                if (partEnd > end || (partEnd == end && part.More))
                    return true;
            }
        }

        return false;
    }

    private (IpReassemblyStatus Status, IpReassemblyDiagnosticCode Code)? Validate(Fragment fragment)
    {
        if (fragment.Validity is InvalidFragment { Code: var invalid })
            return (IpReassemblyStatus.Invalid, invalid);
        if (fragment.Bytes.Length != fragment.DeclaredLength)
            return (IpReassemblyStatus.Truncated, IpReassemblyDiagnosticCode.TruncatedPayload);
        if ((!fragment.Atomic && fragment.Bytes.Length == 0) || (fragment.More && fragment.Bytes.Length % 8 != 0))
            return (IpReassemblyStatus.Invalid, IpReassemblyDiagnosticCode.InvalidLengthOrAlignment);

        var size = (long)fragment.Offset + fragment.DeclaredLength + fragment.Prefix.Length;
        if (size > (fragment.Key.Version == 4 ? 65535 : 65575))
            return (IpReassemblyStatus.Invalid, IpReassemblyDiagnosticCode.RangeExceedsIpLength);
        if (size > options.MaxDatagramBytes)
            return (IpReassemblyStatus.ResourceLimit, IpReassemblyDiagnosticCode.DatagramByteLimit);

        return null;
    }

    private static bool Compatible(Datagram state, Fragment fragment)
    {
        if (state.Buffer is not Collecting buffer || buffer.Context is not { } context)
            return true;
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

    private IpReassemblyUpdate Fail(Datagram state, IpReassemblyStatus status, IpReassemblyDiagnosticCode code)
    {
        var update = Event(state, status, code);
        if (state.Buffer is Collecting buffer)
            bufferedBytes -= buffer.Bytes;
        // A bounded tombstone prevents later fragments from reviving an ambiguous datagram.
        state.Buffer = new Discarded(status);

        return update;
    }

    private void Remove(Key key, Datagram state)
    {
        if (state.Buffer is Collecting buffer)
            bufferedBytes -= buffer.Bytes;
        datagrams.Remove(key);
    }

    private static IpReassemblyUpdate Event(Datagram state, IpReassemblyStatus status, IpReassemblyDiagnosticCode code,
        ReassembledIpPacket? packet = null)
    {
        IpReassemblyOutcome outcome = packet switch
        {
            null => new IpReassemblyDiagnostic(status),
            _ when status == IpReassemblyStatus.Atomic => new IpReassemblyAtomic(packet),
            _ => new IpReassemblyComplete(packet)
        };

        return new(state.Id, state.Version, state.Identification, code.Detail(), outcome) { DiagnosticCode = code };
    }

    private static Fragment? Extract(ReadOnlyMemory<byte> bytes)
    {
        if (bytes.IsEmpty)
            return null;

        return (bytes.Span[0] >> 4) switch
        {
            4 => ExtractIPv4(bytes),
            6 => ExtractIPv6(bytes),
            _ => null
        };
    }

    private static Fragment? ExtractIPv4(ReadOnlyMemory<byte> bytes)
    {
        // Unfragmented IPv4 packets cannot enter reassembly; avoid decoding their transport payload again.
        if (bytes.Length >= 8 && (BinaryPrimitives.ReadUInt16BigEndian(bytes.Span[6..]) & 0x3fff) == 0)
            return null;
        if (DecodedIPv4.Decode(bytes) is not DecodedIPv4 packet || packet.Payload is not IPv4FragmentPayload payload)
            return null;

        return ExtractIPv4(bytes, packet, payload);
    }

    private static Fragment ExtractIPv4(ReadOnlyMemory<byte> bytes, DecodedIPv4 packet, IPv4FragmentPayload payload)
    {
        var header = packet.Packet.Header;
        var key = GetKey(packet, payload);
        FragmentValidity validity = header.DontFragment || header.ReservedFlag
            ? new InvalidFragment(IpReassemblyDiagnosticCode.InvalidIpv4Flags)
            : new ValidFragment();

        return new Fragment(
            Key: key,
            Offset: payload.Offset * 8,
            More: payload.MoreFragments,
            Atomic: false,
            NextHeader: payload.Protocol,
            DeclaredLength: payload.DeclaredLength,
            Bytes: payload.Bytes,
            Prefix: bytes[..header.HeaderLength],
            PreviousNextHeader: 0,
            Validity: validity);
    }

    private static Key GetKey(DecodedIPv4 packet, IPv4FragmentPayload fragment)
    {
        var source = ExtendAddress(packet.Packet.Header.Source);
        var destination = ExtendAddress(packet.Packet.Header.Destination);

        return new Key(4, source, destination, fragment.Identification, fragment.Protocol);
    }

    private static IPv6Address ExtendAddress(IPv4Address address)
    {
        uint value = (uint)address.Octet0 << 24 | (uint)address.Octet1 << 16 | (uint)address.Octet2 << 8 | address.Octet3;

        return new IPv6Address(0, value);
    }

    private static Fragment? ExtractIPv6(ReadOnlyMemory<byte> bytes)
    {
        if (DecodedIPv6.Decode(bytes) is not DecodedIPv6 packet)
            return null;

        var extension = packet.Extensions.FirstOrDefault(x => x.Fragment is not null);

        return extension?.Fragment is { } header ? ExtractIPv6(bytes, packet, extension, header) : null;
    }

    private static Fragment? ExtractIPv6(ReadOnlyMemory<byte> bytes, DecodedIPv6 packet,
        IPv6ExtensionHeader extension, IPv6Fragment header)
    {
        if (packet.Capture is not IPv6Payload.KnownLength capture)
            return null;

        var offset = extension.Offset + 8;
        var declared = (long)capture.DeclaredLength - (offset - 40);
        if (declared < 0)
            return null;

        var available = Math.Min((int)declared, Math.Max(0, bytes.Length - offset));
        var previous = packet.Extensions.LastOrDefault(x => x.Offset < extension.Offset);
        var key = new Key(6, packet.Header.Source, packet.Header.Destination, header.Identification, 0);
        var fragment = new Fragment(
            Key: key,
            Offset: header.OffsetBytes,
            More: header.MoreFragments,
            Atomic: header.IsAtomic,
            NextHeader: header.NextHeader,
            DeclaredLength: (uint)declared,
            Bytes: bytes.Slice(offset, available),
            Prefix: bytes[..extension.Offset],
            PreviousNextHeader: previous?.Offset ?? 6,
            Validity: new ValidFragment());

        if (packet.Diagnostics.Any(x => x.Code is not (IPv6DiagnosticCode.ReassemblyRequired or
                IPv6DiagnosticCode.PayloadTruncated or IPv6DiagnosticCode.FinalDestinationUnavailable or
                IPv6DiagnosticCode.SourceAddressUnavailable)))
            return fragment with { Validity = new InvalidFragment(IpReassemblyDiagnosticCode.InvalidIpv6ExtensionChain) };
        if (header.Offset == 0 && fragment.Bytes.Length == declared && !FirstHeadersComplete(fragment))
            return fragment with { Validity = new InvalidFragment(IpReassemblyDiagnosticCode.MissingIpv6UpperLayerChain) };

        return fragment;
    }

    private static bool FirstHeadersComplete(Fragment fragment)
    {
        // Hop-by-Hop cannot follow the Fragment header.
        if (fragment.NextHeader == 0)
            return false;

        var packet = BuildPacket(fragment.Prefix, fragment, fragment.Bytes.Span);
        if (IPv6Parser.Parse(packet) is not IPv6Packet parsed)
            return false;
        if (parsed.Extensions.Headers.Any(x => x.Type == 44))
            return false;
        if (parsed.Extensions.Result is IPv6NoNextHeader)
            return true;
        if (parsed.Extensions.Result is not IPv6UpperLayer upper)
            return false;

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

    private static byte[] BuildPacket(ReadOnlyMemory<byte> prefix, Fragment fragment, ReadOnlySpan<byte> payload,
        bool congestionExperienced = false)
    {
        var bytes = new byte[prefix.Length + payload.Length];
        prefix.Span.CopyTo(bytes);
        payload.CopyTo(bytes.AsSpan(prefix.Length));
        var ip = bytes.AsSpan();
        if (fragment.Key.Version == 4)
        {
            if (congestionExperienced)
                ip[1] |= 3;
            BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)ip.Length);
            BinaryPrimitives.WriteUInt16BigEndian(ip[6..], 0);
            BinaryPrimitives.WriteUInt16BigEndian(ip[10..], 0);
            uint sum = 0;
            for (var i = 0; i < prefix.Length; i += 2)
                sum += BinaryPrimitives.ReadUInt16BigEndian(ip[i..]);
            while (sum > 65535)
                sum = (sum & 65535) + (sum >> 16);
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

    // IPv4 addresses are zero-extended; Version keeps the address families distinct.
    private readonly record struct Key(int Version, IPv6Address Source, IPv6Address Destination, uint Identification, byte Protocol);
    private sealed record Fragment(Key Key, int Offset, bool More, bool Atomic, byte NextHeader,
        uint DeclaredLength, ReadOnlyMemory<byte> Bytes, ReadOnlyMemory<byte> Prefix, int PreviousNextHeader, FragmentValidity Validity);
    private union FragmentValidity(ValidFragment, InvalidFragment);
    private sealed record ValidFragment;
    private sealed record InvalidFragment(IpReassemblyDiagnosticCode Code);
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
        internal int EcnCodepoints { get; set; }
        internal List<Part> Parts { get; } = [];
        internal byte[]? Context { get; set; }
        internal FirstHeaderState First { get; set; } = new MissingFirstHeader();
        internal LengthState Length { get; set; } = new UnknownLength();
        internal int PayloadBytes { get; set; }
        internal int Bytes { get; set; }
    }
}
