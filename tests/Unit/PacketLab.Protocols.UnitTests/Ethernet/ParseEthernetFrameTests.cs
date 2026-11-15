using FsCheck;
using FsCheck.Fluent;
using PacketLab.Protocols.Ethernet;

namespace PacketLab.Protocols.UnitTests.Ethernet;

public class ParseEthernetFrameTests
{
    public static IEnumerable<int> ShortLengths() => Enumerable.Range(0, 14);

    [Test]
    [MethodDataSource(nameof(ShortLengths))]
    public async Task Short_headers_report_the_actual_captured_length(int length)
    {
        // Act
        var result = EthernetParser.Parse(new byte[length]);

        // Assert
        await Assert.That(result is EthernetParseResult.IncompleteHeader header && header.CapturedLength == length).IsTrue();
    }

    [Test]
    [Arguments("0000", 0)]
    [Arguments("05DC", 1500)]
    public async Task Length_fields_are_recognized_as_IEEE_802_3(string hex, int length)
    {
        // Act
        var result = EthernetParser.Parse(Convert.FromHexString("00112233445566778899AABB" + hex + "CAFE"));

        // Assert
        var field = result is EthernetParseResult.Ieee8023Length parsed ? parsed : throw new InvalidOperationException("Expected a length field.");
        await Assert.That(field.Length).IsEqualTo((ushort)length);
        await Assert.That(field.Destination.ToString()).IsEqualTo("00:11:22:33:44:55");
        await Assert.That(field.Source.ToString()).IsEqualTo("66:77:88:99:AA:BB");
        await Assert.That(Convert.ToHexString(field.RemainingBytes.Span)).IsEqualTo("CAFE");
    }

    [Test]
    [Arguments("05DD", 1501)]
    [Arguments("05FF", 1535)]
    public async Task Reserved_fields_report_the_invalid_value(string hex, int value)
    {
        // Act
        var result = EthernetParser.Parse(Convert.FromHexString("00112233445566778899AABB" + hex + "CAFE"));

        // Assert
        var field = result is EthernetParseResult.InvalidLengthOrType parsed ? parsed : throw new InvalidOperationException("Expected an invalid field.");
        await Assert.That(field.Value).IsEqualTo((ushort)value);
        await Assert.That(field.Destination.ToString()).IsEqualTo("00:11:22:33:44:55");
        await Assert.That(field.Source.ToString()).IsEqualTo("66:77:88:99:AA:BB");
        await Assert.That(Convert.ToHexString(field.RemainingBytes.Span)).IsEqualTo("CAFE");
    }

    [Test]
    [Arguments(0, 1501)]
    [Arguments(1501, 35)]
    [Arguments(1536, 64000)]
    public void Address_type_and_payload_survive_each_field_range(int minimum, int count) =>
        Prop.ForAll((DoNotSize<ushort> field, (DoNotSize<ulong> Destination, DoNotSize<ulong> Source) mac, byte[] payload) =>
        {
            // Arrange
            var selected = (ushort)(minimum + field.Item % count);

            // Act
            var matches = PreservesFields(selected, mac.Destination.Item, mac.Source.Item, payload);

            // Assert
            return matches;
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    public async Task Minimum_ethernet_ii_type_preserves_broadcast_and_source_addresses()
    {
        // Act
        var matches = PreservesFields(0x0600, 0xffffffffffff, 0x020000000001, []);

        // Assert
        await Assert.That(matches).IsTrue();
    }

    private static bool PreservesFields(ushort field, ulong destination, ulong source, byte[] payload)
    {
        // Arrange
        var dst = Convert.FromHexString(destination.ToString("X16")[4..]);
        var src = Convert.FromHexString(source.ToString("X16")[4..]);
        byte[] frame = [.. dst, .. src, (byte)(field >> 8), (byte)field, .. payload];

        // Act
        var (actual, d, s, rest) = EthernetParser.Parse(frame) switch
        {
            EthernetParseResult.Ieee8023Length item when field <= 1500 =>
                (item.Length, item.Destination, item.Source, item.RemainingBytes),
            EthernetParseResult.InvalidLengthOrType item when field is >= 1501 and <= 1535 =>
                (item.Value, item.Destination, item.Source, item.RemainingBytes),
            EthernetFrame item when field >= 1536 =>
                (item.EtherType, item.Destination, item.Source, item.RemainingBytes),
            _ => throw new InvalidOperationException($"Unexpected Ethernet classification for {field}.")
        };

        // Assert
        return actual == field && d.ToString() == BitConverter.ToString(dst).Replace('-', ':')
            && s.ToString() == BitConverter.ToString(src).Replace('-', ':') && rest.Span.SequenceEqual(payload);
    }

    [Test]
    public async Task Tagged_frame_preserves_tag_data_and_trailing_zeros()
    {
        // Arrange
        var bytes = Convert.FromHexString("0011223344556655443322118100002A0800ABCD0000");

        // Act
        var result = EthernetParser.Parse(bytes);

        // Assert
        var frame = result is EthernetFrame ethernet ? ethernet : throw new InvalidOperationException("Expected Ethernet II.");
        await Assert.That(frame.EtherType).IsEqualTo((ushort)0x8100);
        await Assert.That(Convert.ToHexString(frame.RemainingBytes.Span)).IsEqualTo("002A0800ABCD0000");
    }
}
