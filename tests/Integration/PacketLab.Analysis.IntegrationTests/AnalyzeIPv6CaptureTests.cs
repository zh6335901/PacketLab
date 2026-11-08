using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.IPv6;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeIPv6CaptureTests
{
    [Test]
    [Arguments("ipv6-little", PcapByteOrder.LittleEndian)]
    [Arguments("ipv6-big", PcapByteOrder.BigEndian)]
    public async Task Analysis_preserves_ipv6_fields_boundaries_and_diagnostics_across_records_and_file_byte_orders(string sample, PcapByteOrder byteOrder)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader opened ? opened
            : throw new InvalidOperationException("Expected an analysis reader.");
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(byteOrder);
        var expectedHeader = new IPv6Header(6, 0xab, 0xcdef0, 4, 253, 127,
            new IPv6Address(0x20010db800000000, 1), new IPv6Address(0xff02000000000000, 2));
        for (var number = 1; number <= 7; number++)
        {
            var analyzed = reader.ReadNext() is AnalyzedPacket read ? read
                : throw new InvalidOperationException($"Expected record {number}.");
            await Assert.That(analyzed.RecordNumber).IsEqualTo((long)number);
            await Assert.That(analyzed.Packet.OriginalLength).IsEqualTo(70000u);
            var decoding = analyzed.Decoding is ProtocolDecodeResult.EthernetIPv6 ip ? ip
                : throw new InvalidOperationException("Expected IPv6 dispatch.");
            await Assert.That(decoding.Ethernet.EtherType).IsEqualTo((ushort)0x86dd);
            await Assert.That(decoding.Ethernet.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
            await Assert.That(decoding.Ethernet.Destination.ToString()).IsEqualTo("FF:FF:FF:FF:FF:FF");
            if (number == 1)
            {
                var incomplete = decoding.IPv6 is IPv6ParseResult.IncompleteHeader parsed ? parsed
                    : throw new InvalidOperationException("Expected an incomplete header.");
                await Assert.That(incomplete.RequiredLength).IsEqualTo(40);
                await Assert.That(incomplete.CapturedLength).IsEqualTo(39);
                await Assert.That(incomplete.RemainingBytes.Equals(analyzed.Packet.Data[14..])).IsTrue();
                continue;
            }
            if (number == 2)
            {
                var invalid = decoding.IPv6 is IPv6ParseResult.InvalidVersion parsed ? parsed
                    : throw new InvalidOperationException("Expected an invalid version.");
                await Assert.That(invalid.Version).IsEqualTo((byte)4);
                await Assert.That(invalid.RemainingBytes.Equals(analyzed.Packet.Data[14..])).IsTrue();
                continue;
            }

            var packet = decoding.IPv6 is IPv6Packet complete ? complete
                : throw new InvalidOperationException("Expected complete fixed header fields.");
            var header = number switch
            {
                5 => expectedHeader with { TrafficClass = 0, FlowLabel = 0, PayloadLength = 0, NextHeader = 59, HopLimit = 64 },
                6 => expectedHeader with { PayloadLength = 0, NextHeader = 0 },
                7 => expectedHeader with { TrafficClass = 0, FlowLabel = 0, NextHeader = 43, HopLimit = 64 },
                _ => expectedHeader
            };
            await Assert.That(packet.Header).IsEqualTo(header);
            if (number == 6)
            {
                var unknown = packet.Payload is IPv6Payload.UncheckedJumboPayload value ? value
                    : throw new InvalidOperationException("Expected undetermined length.");
                await Assert.That(Convert.ToHexString(unknown.CapturedBytes.Span)).IsEqualTo("1100C20400010000");
                continue;
            }
            var payload = packet.Payload is IPv6Payload.KnownLength known ? known
                : throw new InvalidOperationException("Expected bounded payload.");
            var expectedPayload = number switch { 3 => "CAFE", 4 => "CAFE0102", 5 => "", 7 => "FFFFFFFF", _ => throw new InvalidOperationException() };
            var expectedTrailing = number switch { 4 => "DEADBEEF", 5 => "AABB", _ => "" };
            await Assert.That(payload.DeclaredDatagramLength).IsEqualTo(number == 5 ? 40 : 44);
            await Assert.That(payload.IsDatagramComplete).IsEqualTo(number != 3);
            await Assert.That(Convert.ToHexString(payload.Bytes.Span)).IsEqualTo(expectedPayload);
            await Assert.That(Convert.ToHexString(payload.TrailingBytes.Span)).IsEqualTo(expectedTrailing);
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }
}
