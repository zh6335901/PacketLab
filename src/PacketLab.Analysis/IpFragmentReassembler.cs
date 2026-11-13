using System.Buffers.Binary;
using System.Collections.Immutable;
using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Analysis;

internal sealed class IpFragmentReassembler(IpReassemblyOptions options)
{
    private readonly Dictionary<Key, Datagram> datagrams = [];
    private ulong clock;
    private int bufferedBytes;

    internal ImmutableArray<IpReassemblyEvent> Process(AnalyzedPacket packet)
    {
        var events = ImmutableArray.CreateBuilder<IpReassemblyEvent>();
        var timestamp = packet.Packet.Timestamp;
        var scale = timestamp.Precision == PcapTimestampPrecision.Microseconds ? 1000UL : 1UL;
        // Ignore invalid timestamp fractions; monotonic high-water time handles reordered captures.
        if ((ulong)timestamp.Fraction * scale < 1_000_000_000UL)
            clock = Math.Max(clock, (ulong)timestamp.Seconds * 1_000_000_000UL + timestamp.Fraction * scale);
        foreach (var (key, state) in datagrams.ToArray())
        {
            if (clock - state.StartTime < (ulong)options.TimeoutSeconds * 1_000_000_000UL &&
                packet.RecordNumber - state.Number < options.MaxRecordAge) continue;
            if (state.Buffer is Collecting)
                events.Add(Event(state, IpReassemblyStatus.Expired, "capture time or record age limit reached"));
            Remove(key, state);
        }

        if (Extract(packet) is { } fragment)
            Accept(fragment, packet.RecordNumber, events);
        return events.ToImmutable();
    }

    internal ImmutableArray<IpReassemblyEvent> Finish(IpReassemblyStatus status)
    {
        var events = datagrams.Values.Where(x => x.Buffer is Collecting)
            .Select(x => Event(x, status, status == IpReassemblyStatus.IncompleteAtEndOfFile
                ? "EOF with missing fragments" : "analysis ended before reassembly completed")).ToImmutableArray();
        datagrams.Clear();
        bufferedBytes = 0;
        return events;
    }

    private void Accept(Fragment fragment, long record, ImmutableArray<IpReassemblyEvent>.Builder events)
    {
        if (fragment.Atomic)
        {
            var atomic = new Datagram(fragment, record, clock);
            ((Collecting)atomic.Buffer.Value!).Records.Add(record);
            var atomicFailure = Validate(fragment);
            if (atomicFailure is { } invalid)
                events.Add(Event(atomic, invalid.Status, invalid.Message));
            else
            {
                var frame = BuildFrame(fragment.Prefix, fragment, fragment.Bytes.Span);
                events.Add(Event(atomic, IpReassemblyStatus.Atomic, "independent atomic fragment",
                    new(frame, ProtocolDecoder.Decode(frame, LinkLayerProtocol.Ethernet))));
            }
            return;
        }

        if (!datagrams.TryGetValue(fragment.Key, out var state))
        {
            state = new Datagram(fragment, record, clock);
            if (datagrams.Count >= options.MaxDatagrams)
            {
                ((Collecting)state.Buffer.Value!).Records.Add(record);
                events.Add(Event(state, IpReassemblyStatus.ResourceLimit, "datagram table limit reached (including discarded identities)"));
                return;
            }
            datagrams.Add(fragment.Key, state);
        }
        if (state.Buffer is Discarded discarded)
        {
            events.Add(new(state.Number, state.Version, state.Identification, [record],
                "datagram already discarded; identity retained until expiry", new IpReassemblyDiagnostic(discarded.Status)));
            return;
        }
        var buffer = state.Buffer is Collecting collecting ? collecting : throw new InvalidOperationException();
        if (buffer.Records.Count >= options.MaxRecordsPerDatagram)
        {
            events.Add(new(state.Number, state.Version, state.Identification, [record], "record association limit reached", new IpReassemblyDiagnostic(IpReassemblyStatus.ResourceLimit)));
            Fail(state, IpReassemblyStatus.ResourceLimit, "record association limit reached", events);
            return;
        }
        buffer.Records.Add(record);
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
            var ipLength = first.Length - 14 + total;
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
                var frame = BuildFrame(first, fragment, payload);
                var decoding = ProtocolDecoder.Decode(frame, LinkLayerProtocol.Ethernet);
                events.Add(Event(state, IpReassemblyStatus.Complete, "all fragment bytes captured", new(frame, decoding)));
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
        var size = (long)fragment.Offset + fragment.DeclaredLength + fragment.Prefix.Length - 14;
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
                context.AsSpan(14, 4).SequenceEqual(fragment.Prefix.Span.Slice(14, 4)) &&
                context[20] == fragment.Prefix.Span[20] &&
                context.AsSpan(54).SequenceEqual(fragment.Prefix.Span[54..]);
        }
        // IPv4 copied options may legitimately differ between first and subsequent fragments.
        return fragment.Offset != 0 || buffer.First is not FirstHeader { Bytes: var first } ||
            (first.Length == fragment.Prefix.Length && first.AsSpan(34).SequenceEqual(fragment.Prefix.Span[34..]));
    }

    private void Fail(Datagram state, IpReassemblyStatus status, string message,
        ImmutableArray<IpReassemblyEvent>.Builder events)
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

    private static IpReassemblyEvent Event(Datagram state, IpReassemblyStatus status, string message,
        ReassembledIpPacket? packet = null) =>
        new(state.Number, state.Version, state.Identification,
            state.Buffer is Collecting buffer ? [.. buffer.Records] : [], message,
            packet is null ? new IpReassemblyDiagnostic(status) : status == IpReassemblyStatus.Atomic
                ? new IpReassemblyAtomic(packet) : new IpReassemblyComplete(packet));

    private static Fragment? Extract(AnalyzedPacket packet)
    {
        if (packet.Decoding is not EthernetDecodeResult ethernet || ethernet is not DecodedEthernet frame) return null;
        var bytes = packet.Packet.Data;
        if (frame.Payload is IPv4DecodeResult ipv4 && ipv4 is DecodedIPv4 v4 && v4.Payload is IPv4FragmentPayload f4)
        {
            var header = v4.Packet.Header;
            return new(new(4, header.Source.ToString(), header.Destination.ToString(), f4.Identification, f4.Protocol),
                f4.Offset * 8, f4.MoreFragments, false, f4.Protocol, f4.DeclaredLength, f4.Bytes,
                bytes[..(14 + header.HeaderLength)], 0,
                header.DontFragment || header.ReservedFlag ? new InvalidFragment("invalid IPv4 fragmentation flags") : new ValidFragment());
        }
        if (frame.Payload is not IPv6DecodeResult ipv6 || ipv6 is not DecodedIPv6 v6) return null;
        var extension = v6.Extensions.FirstOrDefault(x => x.Fragment is not null);
        if (extension?.Fragment is not { } f6 || v6.Capture is not IPv6Payload.KnownLength capture) return null;
        var offset = extension.Offset + 8;
        var declared = (long)capture.DeclaredLength - (offset - 40);
        if (declared < 0) return null;
        var available = Math.Min((int)declared, Math.Max(0, bytes.Length - 14 - offset));
        var previous = v6.Extensions.LastOrDefault(x => x.Offset < extension.Offset);
        var fragment = new Fragment(new(6, v6.Header.Source.ToString(), v6.Header.Destination.ToString(), f6.Identification, 0),
            f6.OffsetBytes, f6.MoreFragments, f6.IsAtomic, f6.NextHeader, (uint)declared,
            bytes.Slice(14 + offset, available), bytes[..(14 + extension.Offset)],
            previous is null ? 20 : 14 + previous.Offset, new ValidFragment());
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
        var frame = BuildFrame(fragment.Prefix, fragment, fragment.Bytes.Span);
        if (IPv6Parser.Parse(frame.AsMemory(14)) is not IPv6Packet packet) return false;
        if (packet.Extensions.Headers.Any(x => x.Type == 44)) return false;
        if (packet.Extensions.Result is IPv6NoNextHeader) return true;
        if (packet.Extensions.Result is not IPv6UpperLayer upper) return false;
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

    private static byte[] BuildFrame(ReadOnlyMemory<byte> prefix, Fragment fragment, ReadOnlySpan<byte> payload)
    {
        var frame = new byte[prefix.Length + payload.Length];
        prefix.Span.CopyTo(frame);
        payload.CopyTo(frame.AsSpan(prefix.Length));
        var ip = frame.AsSpan(14);
        if (fragment.Key.Version == 4)
        {
            BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)ip.Length);
            ip[6] = ip[7] = ip[10] = ip[11] = 0;
            uint sum = 0;
            for (var i = 0; i < prefix.Length - 14; i += 2) sum += BinaryPrimitives.ReadUInt16BigEndian(ip[i..]);
            while (sum > 65535) sum = (sum & 65535) + (sum >> 16);
            BinaryPrimitives.WriteUInt16BigEndian(ip[10..], (ushort)~sum);
        }
        else
        {
            BinaryPrimitives.WriteUInt16BigEndian(ip[4..], (ushort)(ip.Length - 40));
            frame[fragment.PreviousNextHeader] = fragment.NextHeader;
        }
        return frame;
    }

    private readonly record struct Key(int Version, string Source, string Destination, uint Identification, byte Protocol);
    private sealed record Fragment(Key Key, int Offset, bool More, bool Atomic, byte NextHeader,
        uint DeclaredLength, ReadOnlyMemory<byte> Bytes, ReadOnlyMemory<byte> Prefix, int PreviousNextHeader, FragmentValidity Validity);
    private union FragmentValidity(ValidFragment, InvalidFragment);
    private sealed record ValidFragment;
    private sealed record InvalidFragment(string Message);
    private sealed record Part(int Offset, bool More, byte[] Bytes);
    private sealed class Datagram(Fragment fragment, long number, ulong time)
    {
        internal long Number { get; } = number;
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
        internal List<long> Records { get; } = [];
        internal List<Part> Parts { get; } = [];
        internal byte[]? Context { get; set; }
        internal FirstHeaderState First { get; set; } = new MissingFirstHeader();
        internal LengthState Length { get; set; } = new UnknownLength();
        internal int Bytes { get; set; }
    }
}
