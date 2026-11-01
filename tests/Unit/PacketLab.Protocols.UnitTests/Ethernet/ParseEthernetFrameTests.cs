using PacketLab.Protocols.Ethernet;

namespace PacketLab.Protocols.UnitTests.Ethernet;

public class ParseEthernetFrameTests
{
    public static IEnumerable<int> ShortLengths() => Enumerable.Range(0, 14);

    [Test]
    [MethodDataSource(nameof(ShortLengths))]
    public async Task Short_headers_report_the_actual_captured_length(int length)
    {
        var result = EthernetParser.Parse(new byte[length]);
        await Assert.That(result is EthernetParseResult.IncompleteHeader header && header.CapturedLength == length).IsTrue();
    }

    [Test]
    [Arguments("0000", 0)]
    [Arguments("05DC", 1500)]
    public async Task Length_fields_are_recognized_as_IEEE_802_3(string hex, int length)
    {
        var result = EthernetParser.Parse(Convert.FromHexString("00112233445566778899AABB" + hex + "CAFE"));
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
        var result = EthernetParser.Parse(Convert.FromHexString("00112233445566778899AABB" + hex + "CAFE"));
        var field = result is EthernetParseResult.InvalidLengthOrType parsed ? parsed : throw new InvalidOperationException("Expected an invalid field.");
        await Assert.That(field.Value).IsEqualTo((ushort)value);
        await Assert.That(field.Destination.ToString()).IsEqualTo("00:11:22:33:44:55");
        await Assert.That(field.Source.ToString()).IsEqualTo("66:77:88:99:AA:BB");
        await Assert.That(Convert.ToHexString(field.RemainingBytes.Span)).IsEqualTo("CAFE");
    }

    [Test]
    [Arguments("0600", 0x0600)]
    [Arguments("ABCD", 0xABCD)]
    [Arguments("0806", 0x0806)]
    public async Task A_complete_header_preserves_addresses_and_raw_type(string hex, int value)
    {
        var result = EthernetParser.Parse(Convert.FromHexString("FFFFFFFFFFFF020000000001" + hex));
        var frame = result is EthernetFrame ethernet ? ethernet : throw new InvalidOperationException("Expected Ethernet II.");
        await Assert.That(frame.Destination.ToString()).IsEqualTo("FF:FF:FF:FF:FF:FF");
        await Assert.That(frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
        await Assert.That(frame.EtherType).IsEqualTo((ushort)value);
        await Assert.That(frame.RemainingBytes.IsEmpty).IsTrue();
    }

    [Test]
    public async Task Tagged_frame_preserves_tag_data_and_trailing_zeros()
    {
        var bytes = Convert.FromHexString("0011223344556655443322118100002A0800ABCD0000");
        var result = EthernetParser.Parse(bytes);
        var frame = result is EthernetFrame ethernet ? ethernet : throw new InvalidOperationException("Expected Ethernet II.");
        await Assert.That(frame.EtherType).IsEqualTo((ushort)0x8100);
        await Assert.That(Convert.ToHexString(frame.RemainingBytes.Span)).IsEqualTo("002A0800ABCD0000");
    }
}
