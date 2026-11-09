using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Protocols.Udp;

internal static class UdpDecoder
{
    internal static UdpParseResult Decode(IPv4Packet packet)
    {
        var header = packet.Header;
        var length = (uint)(header.TotalLength - header.HeaderLength);
        var destination = FinalDestination(header);
        ulong? addresses = destination is { } final ? Sum(header.Source) + Sum(final) : null;
        return UdpParser.Parse(packet.Payload, length, false, addresses);
    }

    internal static UdpParseResult Decode(IPv6UpperLayer upper, IPv6ChecksumContext? context)
    {
        ulong? addresses = context is { } known ? Sum(known.Source) + Sum(known.FinalDestination) : null;
        return UdpParser.Parse(upper.Bytes, upper.DeclaredLength, true, addresses);
    }

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
