namespace PacketLab.Protocols.UnitTests.IP.IPv6;

internal sealed record ExtensionHeaders(byte First, byte[][] Headers)
{
    internal byte[] Bytes => Headers.SelectMany(header => header).ToArray();

    internal static ExtensionHeaders Create(byte mask, byte[] lengths, byte protocol)
    {
        // Select an ordered subset of Hop-by-Hop, Routing, atomic Fragment and Destination Options.
        byte[] types = [0, 43, 44, 60];
        var selected = types.Where((_, i) => (mask & (1 << i)) != 0).ToArray();
        var headers = new byte[selected.Length][];
        for (int i = 0; i < selected.Length; i++)
        {
            byte units = selected[i] == 44 || lengths.Length == 0 ? (byte)0 : (byte)(lengths[i % lengths.Length] % 5);
            var header = new byte[(units + 1) * 8];
            header[0] = i + 1 < selected.Length ? selected[i + 1] : protocol;
            header[1] = units;
            if (selected[i] == 43) header[2] = 0xfe; // Unknown routing type with zero segments left.
            headers[i] = header;
        }
        return new(selected.FirstOrDefault(protocol), headers);
    }
}
