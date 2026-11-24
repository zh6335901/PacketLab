using System.Buffers.Binary;
using System.Collections.Immutable;

namespace PacketLab.Protocols.IP.IPv6;

internal static class IPv6ExtensionParser
{
    internal static IPv6Packet Parse(IPv6Header header, ReadOnlyMemory<byte> captured) =>
        new ExtensionReader(header, captured).Read();

    private struct ExtensionReader(IPv6Header header, ReadOnlyMemory<byte> captured)
    {
        private readonly IPv6Header header = header;
        private readonly ReadOnlyMemory<byte> captured = captured;
        private readonly ImmutableArray<IPv6ExtensionHeader>.Builder headers = ImmutableArray.CreateBuilder<IPv6ExtensionHeader>();
        private ImmutableArray<IPv6Diagnostic>.Builder? diagnostics;
        private int offset;
        private byte next = header.NextHeader;

        internal IPv6Packet Read()
        {
            uint? declared = header.PayloadLength == 0 && header.NextHeader == 0 ? null : header.PayloadLength;
            var addressesKnown = true;
            var sawFragment = false;
            while (true)
            {
                if (next == 59)
                    return Finish(declared, new IPv6NoNextHeader());
                if (next is 6 or 17 or 58 or 4 or 41 or 132)
                    return Finish(declared, ReadUpperLayer(declared!.Value, addressesKnown));
                if (next is not (0 or 60 or 43 or 44 or 51))
                    return Finish(declared, UnsupportedHeader());
                if (CheckHeaderLength(declared, out var length) is { } failure)
                    return Finish(declared, failure);

                var bytes = captured.Span.Slice(offset, length);
                var fragment = ReadFragment(bytes);
                headers.Add(new(
                    Type: next,
                    NextHeader: bytes[0],
                    Offset: 40 + offset,
                    Bytes: captured.Slice(offset, length),
                    Fragment: fragment));
                if (CheckHopByHopPosition(length) is { } positionFailure)
                    return Finish(declared, positionFailure);

                if (next is 0 or 60)
                {
                    if (ProcessOptions(bytes, ref declared, ref addressesKnown) is { } optionsFailure)
                    {
                        offset += length;

                        return Finish(declared, optionsFailure);
                    }
                }
                if (next == 43 && bytes[3] != 0)
                {
                    addressesKnown = false;
                    var arguments = new IPv6DiagnosticArguments(bytes[2], bytes[3], Third: 0);
                    Diagnose(IPv6DiagnosticCode.FinalDestinationUnavailable, offset,
                        $"Routing Type {arguments.First}, Segments Left {arguments.Second}; final destination and checksum context unavailable",
                        arguments);
                }
                if (fragment is not null && ProcessFragment(fragment, length, declared, ref sawFragment) is { } result)
                    return Finish(declared, result);

                next = bytes[0];
                offset += length;
            }
        }

        private int Available(uint? declared) =>
            (int)Math.Min((ulong)captured.Length, declared ?? (ulong)captured.Length);

        private void Diagnose(IPv6DiagnosticCode code, int at, string message, IPv6DiagnosticArguments arguments)
        {
            var diagnostic = new IPv6Diagnostic(code, 40 + at, message) { Arguments = arguments };
            (diagnostics ??= ImmutableArray.CreateBuilder<IPv6Diagnostic>()).Add(diagnostic);
        }

        private IPv6Packet Finish(uint? declared, IPv6ExtensionResult result)
        {
            var end = Available(declared);
            IPv6Payload payload = declared is uint length
                ? new IPv6Payload.KnownLength(length, captured[..end], captured[end..])
                : new IPv6Payload.UndeterminedLength(captured);
            if (declared is uint expected && captured.Length < expected)
                Diagnose(IPv6DiagnosticCode.PayloadTruncated, end,
                    $"payload declared {expected} bytes, captured {captured.Length}", new(expected, captured.Length, Third: 0));
            var chain = new IPv6ExtensionChain(
                Headers: headers.ToImmutable(),
                RemainingOffset: 40 + offset,
                RemainingBytes: captured[offset..end],
                Diagnostics: diagnostics?.ToImmutable() ?? [],
                Result: result);

            return new(header, payload, chain);
        }

        private IPv6UpperLayer ReadUpperLayer(uint declared, bool addressesKnown)
        {
            // Addresses belong only to a located upper layer; protocol and length are stored once.
            IPv6ChecksumContext context = addressesKnown
                ? new IPv6ChecksumContext.KnownAddresses(header.Source, header.Destination)
                : new IPv6ChecksumContext.Unavailable();

            return new(
                Protocol: next,
                Offset: 40 + offset,
                DeclaredLength: declared - (uint)offset,
                Bytes: captured[offset..Available(declared)],
                ChecksumContext: context);
        }

        private IPv6PayloadUnavailable UnsupportedHeader()
        {
            if (next == 50)
                Diagnose(IPv6DiagnosticCode.EncryptedEsp, offset, "ESP encrypted content; upper layer unavailable", arguments: default);
            else
                Diagnose(IPv6DiagnosticCode.UnsupportedNextHeader, offset, $"unsupported Next Header {next}; upper layer unavailable", new(next, Second: 0, Third: 0));

            return new(IPv6PayloadFailure.Unsupported);
        }

        private IPv6PayloadUnavailable? CheckLength(uint? declared, int required)
        {
            if (declared is uint length && (ulong)offset + (uint)required > length)
            {
                var declaredRemainder = length - (uint)offset;
                Diagnose(IPv6DiagnosticCode.HeaderExceedsPayload, offset,
                    $"header {next} requires {required} bytes, declared remainder {declaredRemainder}", new(next, required, declaredRemainder));

                return new(IPv6PayloadFailure.Invalid);
            }

            var capturedRemainder = Available(declared) - offset;
            if (capturedRemainder < required)
            {
                Diagnose(IPv6DiagnosticCode.HeaderTruncated, offset,
                    $"header {next} requires {required} bytes, captured {capturedRemainder}", new(next, required, capturedRemainder));

                return new(IPv6PayloadFailure.Truncated);
            }

            return null;
        }

        private IPv6PayloadUnavailable? CheckHeaderLength(uint? declared, out int length)
        {
            length = 0;
            if (CheckLength(declared, next == 44 ? 8 : 2) is { } shortPrefix)
                return shortPrefix;

            var bytes = captured.Span[offset..];
            length = next switch
            {
                44 => 8,
                51 => (bytes[1] + 2) * 4,
                _ => (bytes[1] + 1) * 8
            };
            if (next == 51 && (length < 12 || length % 8 != 0))
            {
                Diagnose(IPv6DiagnosticCode.InvalidHeaderLength, offset,
                    $"AH length {length} must include 12 fixed bytes and be a multiple of 8", new(length, Second: 0, Third: 0));

                return new(IPv6PayloadFailure.Invalid);
            }

            return CheckLength(declared, length);
        }

        private readonly IPv6Fragment? ReadFragment(ReadOnlySpan<byte> bytes)
        {
            if (next != 44)
                return null;

            var bits = BinaryPrimitives.ReadUInt16BigEndian(bytes[2..]);

            return new IPv6Fragment(
                Offset: (ushort)(bits >> 3),
                MoreFragments: (bits & 1) != 0,
                Identification: BinaryPrimitives.ReadUInt32BigEndian(bytes[4..]),
                NextHeader: bytes[0]);
        }

        private IPv6PayloadUnavailable? CheckHopByHopPosition(int length)
        {
            if (next != 0 || offset == 0)
                return null;

            Diagnose(IPv6DiagnosticCode.InvalidHopByHopPosition, offset, "Hop-by-Hop must immediately follow the fixed header", arguments: default);
            offset += length;

            return new(IPv6PayloadFailure.Invalid);
        }

        private IPv6PayloadUnavailable? ProcessOptions(ReadOnlySpan<byte> bytes, ref uint? declared, ref bool addressesKnown)
        {
            var firstHopByHop = next == 0 && offset == 0;
            var options = ReadOptions(bytes, firstHopByHop, header.PayloadLength);
            if (options is OptionsResult.Invalid error)
            {
                Diagnose(error.Code, offset + error.Offset, error.Message, arguments: default);

                return new(IPv6PayloadFailure.Invalid);
            }

            if (options.Value is OptionsResult.Regular { HasHomeAddress: true } or OptionsResult.Jumbo { HasHomeAddress: true })
            {
                addressesKnown = false;
                Diagnose(IPv6DiagnosticCode.SourceAddressUnavailable, offset, "Home Address option semantics unsupported; checksum context unavailable", arguments: default);
            }
            if (declared is null)
            {
                if (options is not OptionsResult.Jumbo jumbo)
                {
                    Diagnose(IPv6DiagnosticCode.MissingJumboPayload, offset, "zero Payload Length with Hop-by-Hop requires a Jumbo Payload option", arguments: default);

                    return new(IPv6PayloadFailure.Invalid);
                }

                declared = jumbo.Length;
            }

            return null;
        }

        private IPv6ExtensionResult? ProcessFragment(IPv6Fragment fragment, int length, uint? declared, ref bool sawFragment)
        {
            if (declared > ushort.MaxValue || sawFragment)
            {
                if (sawFragment)
                    Diagnose(IPv6DiagnosticCode.DuplicateFragment, offset, "duplicate Fragment header", arguments: default);
                else
                    Diagnose(IPv6DiagnosticCode.JumboFragment, offset, "Jumbo Payload cannot be combined with a Fragment header", arguments: default);
                offset += length;

                return new IPv6PayloadUnavailable(IPv6PayloadFailure.Invalid);
            }

            sawFragment = true;
            if (fragment.IsAtomic)
                return null;

            Diagnose(IPv6DiagnosticCode.ReassemblyRequired, offset, "fragment requires reassembly; complete upper layer unavailable", arguments: default);
            offset += length;

            return new IPv6FragmentPayload(fragment, declared!.Value - (uint)offset, captured[offset..Available(declared)]);
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
