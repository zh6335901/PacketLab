using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Protocols.IP;

internal static class IpChecksumAddresses
{
    internal static ulong? Sum(IPv4Header header) =>
        FinalDestination(header) is { } destination ? Sum(header.Source) + Sum(destination) : null;

    internal static ulong? Sum(IPv6ChecksumContext context) =>
        context is IPv6ChecksumContext.KnownAddresses known ? Sum(known.Source) + Sum(known.FinalDestination) : null;

    private static ulong Sum(IPv4Address address) =>
        (uint)((address.Octet0 << 8) | address.Octet1) + (uint)((address.Octet2 << 8) | address.Octet3);

    private static ulong Sum(IPv6Address address) =>
        Sum(address.High) + Sum(address.Low);

    private static ulong Sum(ulong value) =>
        (value >> 48) + ((value >> 32) & 0xffff) + ((value >> 16) & 0xffff) + (value & 0xffff);

    private static IPv4Address? FinalDestination(IPv4Header header)
    {
        var options = header.Options.Span;
        var destination = header.Destination;
        var sawRoute = false;
        for (var i = 0; i < options.Length;)
        {
            var type = options[i];
            if (type == 0) break;
            if (type == 1) { i++; continue; }
            if (i + 2 > options.Length || options[i + 1] < 2 || i + options[i + 1] > options.Length)
                return null;
            var length = options[i + 1];
            if (type is 131 or 137)
            {
                if (sawRoute || length < 3 || (length - 3) % 4 != 0) return null;
                sawRoute = true;
                var pointer = options[i + 2];
                if (pointer < 4 || (pointer - 4) % 4 != 0 || pointer > length + 1) return null;
                // An exhausted source route has already installed the final destination.
                if (pointer <= length)
                    destination = IPv4Address.Read(options.Slice(i + length - 4, 4));
            }
            i += length;
        }
        return destination;
    }
}
