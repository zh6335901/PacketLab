using System.Buffers.Binary;
using FsCheck.Fluent;
using FsCheck;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Analysis.Pcap;
using PacketLab.Pcap;
using PacketLab.Protocols.Ethernet;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;
using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Protocols.Udp;

namespace PacketLab.Analysis.UnitTests.IpReassembly;

public partial class AnalyzeIpReassemblyTests
{
    private static readonly byte[] Payload = Convert.FromHexString("04D20035001800000102030405060708090A0B0C0D0E0F10");

    [Test]
    public async Task Eof_does_not_repeat_events_for_a_conflicted_identity()
    {
        // Arrange
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 8, true, Payload[8..]),
            Fragment(4, 16, false, Payload[16..]));
        using var reader = Open(stream);
        Read(reader); Read(reader); Read(reader);

        // Act
        var result = reader.ReadNext();

        // Assert
        await Assert.That(result is PcapEndOfFile).IsTrue();
        await Assert.That(reader.ReassemblyEvents.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Out_of_order_fragments_reconstruct_exact_bytes_and_record_relationships(int version)
    {
        // Arrange
        using var stream = Capture(Fragment(version, 16, false, Payload[16..]), Fragment(version, 0, true, Payload[..16]));
        using var reader = Open(stream);
        Read(reader);

        // Act
        Read(reader);

        // Assert
        var complete = reader.ReassemblyEvents.Single();
        await Assert.That(complete.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(complete.RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 1, 2 });
        await Assert.That(complete.Packet!.Bytes.Span[(version == 4 ? 20 : 40)..].SequenceEqual(Payload)).IsTrue();
        await Assert.That(Udp(complete).IsComplete).IsTrue();
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public void Interleaved_identities_complete_independently(int version) =>
        Prop.ForAll((byte count, (byte FirstOrder, byte TailOrder, bool TailFirst, byte Value)[] choices, byte target) =>
        {
            // Arrange
            int total = 2 + count % 7;
            var deliveries = Enumerable.Range(0, total).Select(i =>
            {
                var choice = choices.ElementAtOrDefault(i);
                var original = (byte[])Payload.Clone();
                original[8] = original[16] = (byte)i;
                original[9] = original[17] = choice.Value;
                var first = Fragment(version, 0, true, original[..16], (ushort)(1 + i));
                var tail = Fragment(version, 16, false, original[16..], (ushort)(1 + i));
                return (Id: (uint)(i + 1), Original: original, choice.FirstOrder, choice.TailOrder,
                    Early: choice.TailFirst ? tail : first, Late: choice.TailFirst ? first : tail);
            }).ToArray();
            var early = deliveries.OrderBy(d => d.FirstOrder).ToArray();
            var late = deliveries.OrderBy(d => d.TailOrder).ToArray();
            int index = target % total;
            var expected = late[index];
            long earlierRecord = Array.FindIndex(early, d => d.Id == expected.Id) + 1;
            using var stream = Capture([.. early.Select(d => d.Early), .. late.Select(d => d.Late)]);
            using var reader = Open(stream);
            for (int i = 0; i < total + index; i++) Read(reader);

            // Act
            Read(reader);

            // Assert
            var completed = reader.ReassemblyEvents.Single();
            return completed.Status == IpReassemblyStatus.Complete && completed.Identification == expected.Id
                && completed.RecordNumbers.SequenceEqual(new long[] { earlierRecord, total + index + 1 })
                && completed.Packet!.Bytes.Span[(version == 4 ? 20 : 40)..].SequenceEqual(expected.Original);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(4, 1, IpReassemblyStatus.Duplicate, 2)]
    [Arguments(4, 2, IpReassemblyStatus.Complete, 3)]
    [Arguments(6, 1, IpReassemblyStatus.Duplicate, 2)]
    [Arguments(6, 2, IpReassemblyStatus.Complete, 3)]
    public async Task Duplicate_records_preserve_reassembly_and_record_associations(int version, int preceding, IpReassemblyStatus expected, int records)
    {
        // Arrange
        var first = Fragment(version, 0, true, Payload[..16]);
        using var stream = Capture(first, first, Fragment(version, 16, false, Payload[16..]));
        using var reader = Open(stream);
        for (int i = 0; i < preceding; i++) Read(reader);

        // Act
        Read(reader);

        // Assert
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(expected);
        await Assert.That(reader.ReassemblyEvents.Single().RecordNumbers.Length).IsEqualTo(records);
    }

    [Test]
    public void Duplicate_flood_hits_the_record_association_limit() =>
        Prop.ForAll((byte size, byte extra) =>
        {
            // Arrange
            int limit = 1 + size % 16;
            var fragment = Fragment(4, 0, true, Payload[..16]);
            int preceding = limit + extra % 8;
            using var stream = Capture(Enumerable.Repeat(fragment, preceding + 1).ToArray());
            using var reader = Open(stream, new(maxRecordsPerDatagram: limit));
            for (int i = 0; i < preceding; i++) Read(reader);
            long[] expected = preceding == limit ? Enumerable.Range(1, limit + 1).Select(i => (long)i).ToArray() : [preceding + 1];

            // Act
            Read(reader);

            // Assert
            return reader.ReassemblyEvents.All(item => item.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit
                    && item.RecordNumbers.Length <= limit)
                && reader.ReassemblyEvents.SelectMany(item => item.RecordNumbers).Order().SequenceEqual(expected);
        }).Check(Config.QuickThrowOnFailure);

    [Test]
    [Arguments(1)]
    [Arguments(2)]
    public async Task Record_limit_is_enforced_before_a_fragment_can_complete_the_datagram(int preceding)
    {
        // Arrange
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]),
            Fragment(4, 16, false, Payload[16..]));
        using var reader = Open(stream, new(maxRecordsPerDatagram: 1));
        for (int i = 0; i < preceding; i++) Read(reader);
        long[] expected = preceding == 1 ? [1, 2] : [3];

        // Act
        Read(reader);

        // Assert
        await Assert.That(reader.ReassemblyEvents.SelectMany(x => x.RecordNumbers).ToArray()).IsEquivalentTo(expected);
        await Assert.That(reader.ReassemblyEvents.All(x => x.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit && x.Packet is null)).IsTrue();
    }

    [Test]
    public async Task Atomic_datagram_is_accepted_after_another_identity_exceeds_the_record_limit()
    {
        // Arrange
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]),
            Fragment(6, 0, false, Payload));
        using var reader = Open(stream, new(maxRecordsPerDatagram: 1));
        Read(reader);
        Read(reader);

        // Act
        Read(reader);

        // Assert
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Atomic);
    }

    [Test]
    public async Task Eof_does_not_report_a_datagram_already_discarded_for_the_record_limit()
    {
        // Arrange
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]));
        using var reader = Open(stream, new(maxRecordsPerDatagram: 1));
        Read(reader);
        Read(reader);

        // Act
        reader.ReadNext();

        // Assert
        await Assert.That(reader.ReassemblyEvents.IsEmpty).IsTrue();
    }

    [Test]
    public async Task Later_fragments_of_a_conflicted_datagram_only_reference_their_own_records()
    {
        // Arrange
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 8, true, Payload[8..]),
            Fragment(4, 16, false, Payload[16..]), Fragment(4, 16, false, Payload[16..]));
        using var reader = Open(stream);
        Read(reader);
        Read(reader);
        Read(reader);

        // Act
        Read(reader);

        // Assert
        await Assert.That(reader.ReassemblyEvents.Single().RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 4 });
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Missing_middle_is_reported_as_incomplete_at_eof(int version)
    {
        // Arrange
        using var stream = Capture(Fragment(version, 0, true, Payload[..8]), Fragment(version, 16, false, Payload[16..]));
        using var reader = Open(stream);
        Read(reader);
        Read(reader);

        // Act
        var result = reader.ReadNext();

        // Assert
        await Assert.That(result is PcapEndOfFile).IsTrue();
        await Assert.That(reader.ReassemblyEvents.Single().Status).IsEqualTo(IpReassemblyStatus.Incomplete);
        await Assert.That(reader.ReassemblyEvents.Single().Reason).IsEqualTo(IpReassemblyAnalysisReason.EndOfCapture);
    }

    [Test]
    [Arguments(4)]
    [Arguments(6)]
    public async Task Repeated_eof_does_not_repeat_incomplete_datagram_events(int version)
    {
        // Arrange
        using var stream = Capture(Fragment(version, 0, true, Payload[..8]), Fragment(version, 16, false, Payload[16..]));
        using var reader = Open(stream);
        Read(reader);
        Read(reader);
        reader.ReadNext();

        // Act
        var result = reader.ReadNext();

        // Assert
        await Assert.That(result is PcapEndOfFile).IsTrue();
        await Assert.That(reader.ReassemblyEvents.IsEmpty).IsTrue();
    }

    [Test]
    public async Task Independent_readers_never_combine_fragments()
    {
        // Arrange
        using var first = Capture(Fragment(4, 0, true, Payload[..16]));
        using var second = Capture(Fragment(4, 16, false, Payload[16..]));
        using var left = Open(first);
        using var right = Open(second);
        Read(left);
        Read(right);

        // Act
        right.ReadNext();

        // Assert
        await Assert.That(right.ReassemblyEvents.Single().Reason).IsEqualTo(IpReassemblyAnalysisReason.EndOfCapture);
    }

    [Test]
    public async Task Disposal_reports_aborted_datagrams_and_keeps_the_caller_stream_open()
    {
        // Arrange
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]));
        var reader = Open(stream);
        Read(reader);

        // Act
        reader.Dispose();

        // Assert
        await Assert.That(reader.ReassemblyEvents.Single().Reason).IsEqualTo(IpReassemblyAnalysisReason.Aborted);
        await Assert.That(stream.CanRead).IsTrue();
    }

    [Test]
    public async Task Reading_a_disposed_analysis_reader_throws()
    {
        // Arrange
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]));
        var reader = Open(stream);
        reader.Dispose();

        // Act
        Action act = () => reader.ReadNext();

        // Assert
        await Assert.That(act).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Completed_bytes_and_original_records_survive_later_reads_and_disposal()
    {
        // Arrange
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]), Fragment(4, 16, false, Payload[16..]), new byte[14]);
        var reader = Open(stream);
        var raw = Read(reader);
        Read(reader);
        var complete = reader.ReassemblyEvents.Single();
        Read(reader);
        reader.ReadNext();

        // Act
        reader.Dispose();

        // Assert
        await Assert.That(complete.Packet!.Bytes.Span[20..].SequenceEqual(Payload)).IsTrue();
        await Assert.That(raw.Packet.Data.Span[34..].SequenceEqual(Payload[..16])).IsTrue();
    }

    [Test]
    public async Task Pcap_failure_reports_aborted_datagrams_without_hiding_the_file_error()
    {
        // Arrange
        using var stream = Capture(Fragment(4, 0, true, Payload[..16]));
        stream.Position = stream.Length;
        stream.WriteByte(1);
        stream.Position = 0;
        using var reader = Open(stream);
        Read(reader);

        // Act
        var result = reader.ReadNext();

        // Assert
        await Assert.That(result is PcapError).IsTrue();
        await Assert.That(reader.ReassemblyEvents.Single().Reason).IsEqualTo(IpReassemblyAnalysisReason.Aborted);
    }

    [Test]
    public async Task IPv6_truncated_fragment_header_remains_a_raw_parse_failure()
    {
        // Arrange
        using var stream = Capture(Fragment(6, 0, true, Payload[..16])[..58]);
        using var reader = Open(stream);

        // Act
        var record = Read(reader);

        // Assert
        await Assert.That(reader.ReassemblyEvents.Length).IsEqualTo(0);
        var ethernet = record.Decoding is EthernetDecodeResult e && e is DecodedEthernet d ? d : throw new InvalidOperationException();
        await Assert.That(ethernet.Payload is IPv6DecodeResult v6 && v6 is DecodedIPv6 parsed && parsed.Payload is IPv6PayloadUnavailable).IsTrue();
    }

    [Test]
    [Arguments(4, 0x86, 0xdd)]
    [Arguments(6, 0x08, 0x00)]
    public async Task Link_layer_protocol_mismatch_does_not_start_reassembly(int version, byte highType, byte lowType)
    {
        // Arrange
        var fragment = Fragment(version, 0, true, Payload[..16]);
        fragment[12] = highType;
        fragment[13] = lowType;
        using var stream = Capture(fragment);
        using var reader = Open(stream);

        // Act
        Read(reader);

        // Assert
        await Assert.That(reader.ReassemblyEvents.Length).IsEqualTo(0);
    }

    [Test]
    public async Task Analysis_coordinator_accepts_decoded_input_without_a_pcap_reader()
    {
        // Arrange
        using var analyzer = new IpReassemblyAnalyzer();
        var first = PacketLab.Protocols.ProtocolDecoder.Decode(Fragment(4, 0, true, Payload[..16]), PacketLab.Protocols.LinkLayerProtocol.Ethernet);
        var tail = PacketLab.Protocols.ProtocolDecoder.Decode(Fragment(4, 16, false, Payload[16..]), PacketLab.Protocols.LinkLayerProtocol.Ethernet);
        analyzer.Process(100, 1_000_000_000, first);

        // Act
        var complete = analyzer.Process(102, 2_000_000_000, tail).Single();

        // Assert
        await Assert.That(complete.Status).IsEqualTo(IpReassemblyStatus.Complete);
        await Assert.That(complete.DatagramNumber).IsEqualTo(100L);
        await Assert.That(complete.RecordNumbers.ToArray()).IsEquivalentTo(new long[] { 100, 102 });
    }

    [Test]
    public async Task Finish_rejects_non_terminal_analysis_reasons()
    {
        // Arrange
        using var analyzer = new IpReassemblyAnalyzer();

        // Act
        Action act = () => analyzer.Finish(IpReassemblyAnalysisReason.RecordAgeLimit);

        // Assert
        await Assert.That(act).Throws<ArgumentOutOfRangeException>();
    }

    [Test]
    public async Task Disposed_coordinator_rejects_processing()
    {
        // Arrange
        var analyzer = new IpReassemblyAnalyzer();
        analyzer.Dispose();
        var input = PacketLab.Protocols.ProtocolDecoder.Decode(new byte[14], PacketLab.Protocols.LinkLayerProtocol.Ethernet);

        // Act
        Action act = () => analyzer.Process(1, null, input);

        // Assert
        await Assert.That(act).Throws<ObjectDisposedException>();
    }

    [Test]
    public async Task Disposed_coordinator_rejects_finishing()
    {
        // Arrange
        var analyzer = new IpReassemblyAnalyzer();
        analyzer.Dispose();

        // Act
        Action act = () => analyzer.Finish(IpReassemblyAnalysisReason.Aborted);

        // Assert
        await Assert.That(act).Throws<ObjectDisposedException>();
    }

    private static UdpDatagram Udp(IpReassemblyEvent item)
    {
        var decoding = item.Packet!.Decoding;
        if (decoding is IPv4DecodeResult v4 && v4 is DecodedIPv4 d4 && d4.Payload is UdpParseResult p4 && p4 is UdpDatagram u4) return u4;
        if (decoding is IPv6DecodeResult v6 && v6 is DecodedIPv6 d6 && d6.Payload is UdpParseResult p6 && p6 is UdpDatagram u6) return u6;
        throw new InvalidOperationException("Expected UDP");
    }

    private static PcapAnalysisReader Open(Stream stream, IpReassemblyAnalysisOptions? options = null) =>
        PcapAnalysisReader.Open(stream, reassemblyOptions: options) is PcapAnalysisReader reader ? reader : throw new InvalidOperationException();

    private static AnalyzedPacket Read(PcapAnalysisReader reader) => reader.ReadNext() is AnalyzedPacket packet ? packet : throw new InvalidOperationException();

    private static byte[] Fragment(int version, int offset, bool more, byte[] payload, ushort id = 1,
        byte nextHeader = 17, bool hopByHop = false)
    {
        var header = version == 4 ? 20 : hopByHop ? 56 : 48;
        var frame = new byte[14 + header + payload.Length];
        frame[12] = version == 4 ? (byte)8 : (byte)0x86; frame[13] = version == 4 ? (byte)0 : (byte)0xdd;
        var ip = frame.AsSpan(14);
        if (version == 4)
        {
            ip[0] = 0x45; ip[8] = 64; ip[9] = nextHeader; ip[12] = 10; ip[16] = 11;
            BinaryPrimitives.WriteUInt16BigEndian(ip[2..], (ushort)(20 + payload.Length));
            BinaryPrimitives.WriteUInt16BigEndian(ip[4..], id);
            BinaryPrimitives.WriteUInt16BigEndian(ip[6..], (ushort)(offset / 8 | (more ? 0x2000 : 0)));
        }
        else
        {
            ip[0] = 0x60; ip[6] = hopByHop ? (byte)0 : (byte)44; ip[7] = 64; ip[23] = 1; ip[39] = 2;
            BinaryPrimitives.WriteUInt16BigEndian(ip[4..], (ushort)(header - 40 + payload.Length));
            if (hopByHop) ip[40] = 44;
            var fragment = ip[(header - 8)..]; fragment[0] = nextHeader;
            BinaryPrimitives.WriteUInt16BigEndian(fragment[2..], (ushort)(offset | (more ? 1 : 0)));
            BinaryPrimitives.WriteUInt32BigEndian(fragment[4..], id);
        }
        payload.CopyTo(frame, 14 + header);
        return frame;
    }

    private static MemoryStream Capture(params byte[][] frames)
    {
        var stream = new MemoryStream();
        stream.Write(Convert.FromHexString("D4C3B2A10200040000000000000000000000020001000000"));
        using var writer = new BinaryWriter(stream, System.Text.Encoding.UTF8, leaveOpen: true);
        foreach (var frame in frames)
        {
            writer.Write(1u); writer.Write(0u); writer.Write((uint)frame.Length); writer.Write(65535u); writer.Write(frame);
        }
        stream.Position = 0;
        return stream;
    }
}
