using System.Buffers.Binary;
using System.Collections.Immutable;

namespace PacketLab.Protocols.IPv6;

internal static class IPv6ExtensionParser
{
    internal static IPv6Packet Parse(IPv6Header header, ReadOnlyMemory<byte> captured)
    {
        uint? declared = header.PayloadLength == 0 && header.NextHeader == 0 ? null : header.PayloadLength;
        var headers = ImmutableArray.CreateBuilder<IPv6ExtensionHeader>();
        var diagnostics = ImmutableArray.CreateBuilder<IPv6Diagnostic>();
        var offset = 0;
        var next = header.NextHeader;
        var addressesKnown = true;
        var sawFragment = false;

        int Available() => (int)Math.Min((ulong)captured.Length, declared ?? (ulong)captured.Length);
        void Diagnose(IPv6DiagnosticCode code, int at, string message) => diagnostics.Add(new(code, 40 + at, message));

        IPv6Packet Finish(IPv6ChainStatus status, IPv6UpperLayer? upper = null)
        {
            var end = Available();
            IPv6Payload payload = declared is uint length
                ? new IPv6Payload.KnownLength(length, captured[..end], captured[end..])
                : new IPv6Payload.UndeterminedLength(captured);
            if (declared is uint expected && captured.Length < expected)
                Diagnose(IPv6DiagnosticCode.PayloadTruncated, end, $"payload declared {expected} bytes, captured {captured.Length}");
            // A transport checksum can cover less than the IP payload (for example, UDP surplus).
            var context = upper is not null && addressesKnown
                ? new IPv6ChecksumContext(header.Source, header.Destination, upper.Protocol, upper.DeclaredLength) : null;
            return new(header, payload, new(headers.ToImmutable(), status, 40 + offset, captured[offset..end],
                upper, context, diagnostics.ToImmutable()));
        }

        IPv6ChainStatus? CheckLength(int required)
        {
            if (declared is uint length && (ulong)offset + (uint)required > length)
            {
                Diagnose(IPv6DiagnosticCode.HeaderExceedsPayload, offset,
                    $"header {next} requires {required} bytes, declared remainder {length - (uint)offset}");
                return IPv6ChainStatus.Invalid;
            }
            if (Available() - offset < required)
            {
                Diagnose(IPv6DiagnosticCode.HeaderTruncated, offset,
                    $"header {next} requires {required} bytes, captured {Available() - offset}");
                return IPv6ChainStatus.Truncated;
            }
            return null;
        }

        while (true)
        {
            if (next == 59)
                return Finish(IPv6ChainStatus.NoNextHeader);
            if (next is 6 or 17 or 58 or 4 or 41 or 132)
                return Finish(IPv6ChainStatus.UpperLayer,
                    new(next, 40 + offset, declared!.Value - (uint)offset, captured[offset..Available()]));
            if (next is not (0 or 60 or 43 or 44 or 51))
            {
                Diagnose(next == 50 ? IPv6DiagnosticCode.EncryptedEsp : IPv6DiagnosticCode.UnsupportedNextHeader,
                    offset, next == 50 ? "ESP encrypted content; upper layer unavailable" : $"unsupported Next Header {next}; upper layer unavailable");
                return Finish(IPv6ChainStatus.Unsupported);
            }

            if (CheckLength(next == 44 ? 8 : 2) is { } shortPrefix)
                return Finish(shortPrefix);
            var bytes = captured.Span[offset..];
            var length = next == 44 ? 8 : next == 51 ? (bytes[1] + 2) * 4 : (bytes[1] + 1) * 8;
            if (next == 51 && (length < 12 || length % 8 != 0))
            {
                Diagnose(IPv6DiagnosticCode.InvalidHeaderLength, offset, $"AH length {length} must include 12 fixed bytes and be a multiple of 8");
                return Finish(IPv6ChainStatus.Invalid);
            }
            if (CheckLength(length) is { } shortHeader)
                return Finish(shortHeader);

            IPv6Fragment? fragment = null;
            if (next == 44)
            {
                var bits = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
                fragment = new((ushort)(bits >> 3), (bits & 1) != 0, BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]), bytes[0]);
            }
            headers.Add(new(next, bytes[0], 40 + offset, captured.Slice(offset, length), fragment));

            if (next == 0 && offset != 0)
            {
                Diagnose(IPv6DiagnosticCode.InvalidHopByHopPosition, offset, "Hop-by-Hop must immediately follow the fixed header");
                offset += length;
                return Finish(IPv6ChainStatus.Invalid);
            }
            if (next is 0 or 60)
            {
                var options = ReadOptions(bytes[..length], next == 0 && offset == 0, header.PayloadLength);
                if (options.Error is { } error)
                {
                    Diagnose(error, offset + options.ErrorOffset, options.Message!);
                    offset += length;
                    return Finish(IPv6ChainStatus.Invalid);
                }
                if (options.HasHomeAddress)
                {
                    addressesKnown = false;
                    Diagnose(IPv6DiagnosticCode.SourceAddressUnavailable, offset, "Home Address option semantics unsupported; checksum context unavailable");
                }
                if (declared is null)
                {
                    if (options.JumboLength is not uint jumbo)
                    {
                        Diagnose(IPv6DiagnosticCode.MissingJumboPayload, offset, "zero Payload Length with Hop-by-Hop requires a Jumbo Payload option");
                        offset += length;
                        return Finish(IPv6ChainStatus.Invalid);
                    }
                    declared = jumbo;
                }
            }
            if (next == 43 && bytes[3] != 0)
            {
                addressesKnown = false;
                Diagnose(IPv6DiagnosticCode.FinalDestinationUnavailable, offset,
                    $"Routing Type {bytes[2]}, Segments Left {bytes[3]}; final destination and checksum context unavailable");
            }
            if (fragment is not null)
            {
                if (declared > ushort.MaxValue || sawFragment)
                {
                    Diagnose(sawFragment ? IPv6DiagnosticCode.DuplicateFragment : IPv6DiagnosticCode.JumboFragment,
                        offset, sawFragment ? "duplicate Fragment header" : "Jumbo Payload cannot be combined with a Fragment header");
                    offset += length;
                    return Finish(IPv6ChainStatus.Invalid);
                }
                sawFragment = true;
                if (!fragment.IsAtomic)
                {
                    Diagnose(IPv6DiagnosticCode.ReassemblyRequired, offset, "fragment requires reassembly; complete upper layer unavailable");
                    offset += length;
                    return Finish(IPv6ChainStatus.ReassemblyRequired);
                }
            }
            next = bytes[0];
            offset += length;
        }
    }

    private sealed record Options(uint? JumboLength = null, bool HasHomeAddress = false,
        IPv6DiagnosticCode? Error = null, int ErrorOffset = 0, string? Message = null);

    private static Options ReadOptions(ReadOnlySpan<byte> header, bool firstHopByHop, ushort fixedLength)
    {
        uint? jumbo = null;
        var homeAddress = false;
        for (var i = 2; i < header.Length;)
        {
            var type = header[i];
            if (type == 0) { i++; continue; }
            if (i + 2 > header.Length || i + 2 + header[i + 1] > header.Length)
                return new(Error: IPv6DiagnosticCode.InvalidOptions, ErrorOffset: i, Message: "option extends beyond its header");
            var length = header[i + 1];
            if (type == 0xc2)
            {
                if (!firstHopByHop || fixedLength != 0 || jumbo is not null || length != 4 || i % 4 != 2)
                    return new(Error: IPv6DiagnosticCode.InvalidJumboPayload, ErrorOffset: i,
                        Message: "Jumbo Payload requires one aligned 4-byte option in the first Hop-by-Hop header and zero Payload Length");
                var value = BinaryPrimitives.ReadUInt32BigEndian(header[(i + 2)..]);
                if (value <= ushort.MaxValue)
                    return new(Error: IPv6DiagnosticCode.InvalidJumboPayload, ErrorOffset: i, Message: "Jumbo Payload length must exceed 65535");
                jumbo = value;
            }
            homeAddress |= type == 0xc9;
            i += 2 + length;
        }
        return new(jumbo, homeAddress);
    }
}
