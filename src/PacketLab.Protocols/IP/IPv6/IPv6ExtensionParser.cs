using System.Buffers.Binary;
using System.Collections.Immutable;

namespace PacketLab.Protocols.IP.IPv6;

internal static class IPv6ExtensionParser
{
    internal static IPv6Packet Parse(IPv6Header header, ReadOnlyMemory<byte> captured)
    {
        uint? declared = header.PayloadLength == 0 && header.NextHeader == 0 ? null : header.PayloadLength;
        var headers = ImmutableArray.CreateBuilder<IPv6ExtensionHeader>();
        ImmutableArray<IPv6Diagnostic>.Builder? diagnostics = null;
        var offset = 0;
        var next = header.NextHeader;
        var addressesKnown = true;
        var sawFragment = false;

        int Available() => (int)Math.Min((ulong)captured.Length, declared ?? (ulong)captured.Length);
        void Diagnose(IPv6DiagnosticCode code, int at, string message) =>
            (diagnostics ??= ImmutableArray.CreateBuilder<IPv6Diagnostic>()).Add(new(code, 40 + at, message));

        IPv6Packet Finish(IPv6ExtensionResult result)
        {
            var end = Available();
            IPv6Payload payload = declared is uint length
                ? new IPv6Payload.KnownLength(length, captured[..end], captured[end..])
                : new IPv6Payload.UndeterminedLength(captured);
            if (declared is uint expected && captured.Length < expected)
                Diagnose(IPv6DiagnosticCode.PayloadTruncated, end, $"payload declared {expected} bytes, captured {captured.Length}");
            var chain = new IPv6ExtensionChain(
                Headers: headers.ToImmutable(),
                RemainingOffset: 40 + offset,
                RemainingBytes: captured[offset..end],
                Diagnostics: diagnostics?.ToImmutable() ?? [],
                Result: result);
            return new(header, payload, chain);
        }

        IPv6PayloadUnavailable? CheckLength(int required)
        {
            if (declared is uint length && (ulong)offset + (uint)required > length)
            {
                Diagnose(IPv6DiagnosticCode.HeaderExceedsPayload, offset,
                    $"header {next} requires {required} bytes, declared remainder {length - (uint)offset}");
                return new IPv6PayloadUnavailable(IPv6PayloadFailure.Invalid);
            }
            if (Available() - offset < required)
            {
                Diagnose(IPv6DiagnosticCode.HeaderTruncated, offset,
                    $"header {next} requires {required} bytes, captured {Available() - offset}");
                return new IPv6PayloadUnavailable(IPv6PayloadFailure.Truncated);
            }
            return null;
        }

        while (true)
        {
            if (next == 59)
                return Finish(new IPv6NoNextHeader());
            if (next is 6 or 17 or 58 or 4 or 41 or 132)
            {
                // Addresses belong only to a located upper layer; protocol and length are stored once.
                IPv6ChecksumContext context = addressesKnown
                    ? new IPv6ChecksumContext.KnownAddresses(header.Source, header.Destination)
                    : new IPv6ChecksumContext.Unavailable();
                var upper = new IPv6UpperLayer(
                    Protocol: next,
                    Offset: 40 + offset,
                    DeclaredLength: declared!.Value - (uint)offset,
                    Bytes: captured[offset..Available()],
                    ChecksumContext: context);
                return Finish(upper);
            }
            if (next is not (0 or 60 or 43 or 44 or 51))
            {
                if (next == 50)
                    Diagnose(IPv6DiagnosticCode.EncryptedEsp, offset, "ESP encrypted content; upper layer unavailable");
                else
                    Diagnose(IPv6DiagnosticCode.UnsupportedNextHeader, offset, $"unsupported Next Header {next}; upper layer unavailable");
                return Finish(new IPv6PayloadUnavailable(IPv6PayloadFailure.Unsupported));
            }

            if (CheckLength(next == 44 ? 8 : 2) is { } shortPrefix)
                return Finish(shortPrefix);
            var bytes = captured.Span[offset..];
            var length = next switch
            {
                44 => 8,
                51 => (bytes[1] + 2) * 4,
                _ => (bytes[1] + 1) * 8
            };
            if (next == 51 && (length < 12 || length % 8 != 0))
            {
                Diagnose(IPv6DiagnosticCode.InvalidHeaderLength, offset, $"AH length {length} must include 12 fixed bytes and be a multiple of 8");
                return Finish(new IPv6PayloadUnavailable(IPv6PayloadFailure.Invalid));
            }
            if (CheckLength(length) is { } shortHeader)
                return Finish(shortHeader);

            IPv6Fragment? fragment = null;
            if (next == 44)
            {
                var bits = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);
                fragment = new IPv6Fragment(
                    Offset: (ushort)(bits >> 3),
                    MoreFragments: (bits & 1) != 0,
                    Identification: BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]),
                    NextHeader: bytes[0]);
            }
            headers.Add(new(
                Type: next,
                NextHeader: bytes[0],
                Offset: 40 + offset,
                Bytes: captured.Slice(offset, length),
                Fragment: fragment));

            if (next == 0 && offset != 0)
            {
                Diagnose(IPv6DiagnosticCode.InvalidHopByHopPosition, offset, "Hop-by-Hop must immediately follow the fixed header");
                offset += length;
                return Finish(new IPv6PayloadUnavailable(IPv6PayloadFailure.Invalid));
            }
            if (next is 0 or 60)
            {
                var firstHopByHop = next == 0 && offset == 0;
                var options = ReadOptions(bytes[..length], firstHopByHop, header.PayloadLength);
                if (options is OptionsResult.Invalid error)
                {
                    Diagnose(error.Code, offset + error.Offset, error.Message);
                    offset += length;
                    return Finish(new IPv6PayloadUnavailable(IPv6PayloadFailure.Invalid));
                }
                if (options.Value is OptionsResult.Regular { HasHomeAddress: true } or OptionsResult.Jumbo { HasHomeAddress: true })
                {
                    addressesKnown = false;
                    Diagnose(IPv6DiagnosticCode.SourceAddressUnavailable, offset, "Home Address option semantics unsupported; checksum context unavailable");
                }
                if (declared is null)
                {
                    if (options is not OptionsResult.Jumbo jumbo)
                    {
                        Diagnose(IPv6DiagnosticCode.MissingJumboPayload, offset, "zero Payload Length with Hop-by-Hop requires a Jumbo Payload option");
                        offset += length;
                        return Finish(new IPv6PayloadUnavailable(IPv6PayloadFailure.Invalid));
                    }
                    declared = jumbo.Length;
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
                    if (sawFragment)
                        Diagnose(IPv6DiagnosticCode.DuplicateFragment, offset, "duplicate Fragment header");
                    else
                        Diagnose(IPv6DiagnosticCode.JumboFragment, offset, "Jumbo Payload cannot be combined with a Fragment header");
                    offset += length;
                    return Finish(new IPv6PayloadUnavailable(IPv6PayloadFailure.Invalid));
                }
                sawFragment = true;
                if (!fragment.IsAtomic)
                {
                    Diagnose(IPv6DiagnosticCode.ReassemblyRequired, offset, "fragment requires reassembly; complete upper layer unavailable");
                    offset += length;
                    return Finish(new IPv6FragmentPayload(fragment, declared!.Value - (uint)offset, captured[offset..Available()]));
                }
            }
            next = bytes[0];
            offset += length;
        }
    }

    private union OptionsResult(OptionsResult.Regular, OptionsResult.Jumbo, OptionsResult.Invalid)
    {
        public sealed record Regular(bool HasHomeAddress);
        public sealed record Jumbo(uint Length, bool HasHomeAddress);
        public sealed record Invalid(IPv6DiagnosticCode Code, int Offset, string Message);
    }

    private static OptionsResult ReadOptions(ReadOnlySpan<byte> header, bool firstHopByHop, ushort fixedLength)
    {
        uint? jumbo = null;
        var homeAddress = false;
        for (var i = 2; i < header.Length;)
        {
            var type = header[i];
            if (type == 0)
            {
                i++;
                continue;
            }
            if (i + 2 > header.Length || i + 2 + header[i + 1] > header.Length)
                return new OptionsResult.Invalid(IPv6DiagnosticCode.InvalidOptions, i, "option extends beyond its header");
            var length = header[i + 1];
            if (type == 0xc2)
            {
                if (!firstHopByHop || fixedLength != 0 || jumbo is not null || length != 4 || i % 4 != 2)
                    return new OptionsResult.Invalid(IPv6DiagnosticCode.InvalidJumboPayload, i,
                        "Jumbo Payload requires one aligned 4-byte option in the first Hop-by-Hop header and zero Payload Length");
                var value = BinaryPrimitives.ReadUInt32BigEndian(header[(i + 2)..]);
                if (value <= ushort.MaxValue)
                    return new OptionsResult.Invalid(IPv6DiagnosticCode.InvalidJumboPayload, i, "Jumbo Payload length must exceed 65535");
                jumbo = value;
            }
            homeAddress |= type == 0xc9;
            i += 2 + length;
        }
        return jumbo is uint jumboLength ? new OptionsResult.Jumbo(jumboLength, homeAddress) : new OptionsResult.Regular(homeAddress);
    }
}
