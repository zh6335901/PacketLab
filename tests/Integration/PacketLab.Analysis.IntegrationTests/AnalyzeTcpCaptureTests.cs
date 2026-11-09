using PacketLab.Pcap;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IPv4;
using PacketLab.Protocols.IPv6;
using PacketLab.Protocols.Tcp;

namespace PacketLab.Analysis.IntegrationTests;

public class AnalyzeTcpCaptureTests
{
    [Test]
    [Arguments("tcp-little", PcapByteOrder.LittleEndian)]
    [Arguments("tcp-big", PcapByteOrder.BigEndian)]
    public async Task Analysis_preserves_tcp_and_outer_layers_and_continues_after_each_failure(string sample, PcapByteOrder order)
    {
        using var stream = File.OpenRead(Path.Combine(AppContext.BaseDirectory, "TestData", "Pcap", sample + ".pcap"));
        var reader = PcapAnalysisReader.Open(stream) is PcapAnalysisReader r ? r : throw new InvalidOperationException();
        await Assert.That(reader.Header.ByteOrder).IsEqualTo(order);
        for (var i = 0; i < Expected.Length; i++)
        {
            var packet = reader.ReadNext() is AnalyzedPacket p ? p : throw new InvalidOperationException();
            await Assert.That(packet.RecordNumber).IsEqualTo(i + 1L);
            await Assert.That(packet.Packet.OriginalLength).IsEqualTo(70000u);
            var frame = packet.Decoding is EthernetDecodeResult e && e is DecodedEthernet f ? f : throw new InvalidOperationException();
            await Assert.That(frame.Frame.Source.ToString()).IsEqualTo("02:00:00:00:00:01");
            var summary = frame.Payload switch
            {
                IPv4DecodeResult ip when ip is DecodedIPv4 decoded => decoded.Payload switch
                {
                    TcpParseResult tcp => Describe(4, tcp),
                    IPv4FragmentPayload fragment when fragment.Protocol == 6 && fragment.MoreFragments => "4:Fragment",
                    _ => throw new InvalidOperationException()
                },
                IPv6DecodeResult ip when ip is DecodedIPv6 decoded => decoded.Payload switch
                {
                    TcpParseResult tcp => Describe(6, tcp),
                    IPv6FragmentPayload fragment when fragment.Fragment.NextHeader == 6 && fragment.Fragment.MoreFragments => "6:Fragment",
                    IPv6PayloadUnavailable { Reason: IPv6PayloadFailure.Invalid } => "6:InvalidChain",
                    _ => throw new InvalidOperationException()
                },
                _ => throw new InvalidOperationException()
            };
            await Assert.That(summary).IsEqualTo(Expected[i]).Because($"record {i + 1} must preserve declared boundaries and independent checksum expectations");
            if (i == 0)
            {
                var ip = frame.Payload is IPv4DecodeResult result && result is DecodedIPv4 decoded ? decoded : throw new InvalidOperationException();
                await Assert.That(ip.Packet.ChecksumStatus).IsEqualTo(IPv4ChecksumStatus.Match);
                await Assert.That(Convert.ToHexString(ip.Packet.TrailingBytes.Span)).IsEqualTo("DEADBEEF");
                var tcp = ip.Payload is TcpParseResult t && t is TcpSegment s ? s : throw new InvalidOperationException();
                await Assert.That(tcp.Options.Items.Length).IsEqualTo(8);
                await Assert.That(tcp.Options.Padding.Length).IsEqualTo(5);
                await Assert.That(tcp.Header.SequenceNumber).IsEqualTo(0x81234567u);
                await Assert.That(tcp.Header.AcknowledgmentNumber).IsEqualTo(0xfedcba98u);
                await Assert.That(tcp.Header.Flags).IsEqualTo((TcpFlags)0x1db);
            }
            if (i == 1)
            {
                var ip = frame.Payload is IPv6DecodeResult result && result is DecodedIPv6 decoded ? decoded : throw new InvalidOperationException();
                await Assert.That(ip.RemainingOffset).IsEqualTo(56);
                await Assert.That(ip.Extensions.Length).IsEqualTo(2);
                await Assert.That(ip.Capture is IPv6Payload.KnownLength known && Convert.ToHexString(known.TrailingBytes.Span) == "DEAD").IsTrue();
            }
            if (i == 6)
            {
                var ip = frame.Payload is IPv4DecodeResult result && result is DecodedIPv4 decoded ? decoded : throw new InvalidOperationException();
                await Assert.That(ip.Payload is TcpParseResult t && t is TcpSegment tcp
                    && tcp.Options.Items.Single().Value is TcpOptionValue.Invalid { Reason: TcpOptionFailure.ExceedsHeader }).IsTrue();
            }
        }
        await Assert.That(reader.ReadNext() is PcapEndOfFile).IsTrue();
    }

    private static string Describe(int version, TcpParseResult result) => $"{version}:" + (result switch
    {
        TcpSegment s => $"{s.Header.SourcePort}>{s.Header.DestinationPort}:header={s.Header.HeaderLength}:length={s.DeclaredLength}:payload={Convert.ToHexString(s.Payload.Span)}:checksum="
            + (s.Checksum.Value is TcpChecksumStatus status ? status.ToString()
                : s.Checksum is TcpChecksumUnavailable unavailable ? unavailable.Reason.ToString() : throw new InvalidOperationException()),
        TcpParseResult.InvalidDataOffset { Header.DataOffset: 4, DeclaredLength: 23 } => "InvalidDataOffset",
        TcpParseResult.HeaderTruncated { DeclaredLength: 23, RemainingBytes.Length: 18 } => "HeaderTruncated",
        TcpParseResult.OptionsTruncated { Header.HeaderLength: 60, DeclaredLength: 63, RemainingBytes.Length: 22 } => "OptionsTruncated",
        _ => throw new InvalidOperationException($"Unexpected TCP result {result.Value}")
    });

    private static readonly string[] Expected =
    [
        "4:43981>65244:header=60:length=63:payload=CAFE01:checksum=Match",
        "6:43981>65244:header=20:length=23:payload=CAFE01:checksum=Match",
        "4:InvalidDataOffset",
        "6:HeaderTruncated",
        "4:OptionsTruncated",
        "6:43981>65244:header=20:length=23:payload=CAFE:checksum=PayloadTruncated",
        "4:43981>65244:header=24:length=27:payload=CAFE01:checksum=Match",
        "6:43981>65244:header=20:length=23:payload=CAFE01:checksum=PseudoHeaderUnavailable",
        "4:43981>65244:header=20:length=23:payload=CAFE01:checksum=Match",
        "6:43981>65244:header=20:length=23:payload=CAFE01:checksum=Match",
        "4:Fragment",
        "6:Fragment",
        "6:InvalidChain",
        "4:43981>65244:header=20:length=23:payload=CAFE00:checksum=Mismatch",
        "4:43981>65244:header=20:length=22:payload=358A:checksum=Match",
        "6:43981>65244:header=20:length=23:payload=CAFE01:checksum=Match"
    ];
}
