using PacketLab.Desktop.Localization;
using System.Collections.Immutable;
using Microsoft.Win32.SafeHandles;
using PacketLab.Analysis.IpReassembly;
using PacketLab.Analysis.Pcap;
using PacketLab.Desktop.Models.PacketExplorer;
using PacketLab.Pcap;
using PacketLab.Protocols;
using PacketLab.Protocols.IP.Reassembly;
using PacketLab.Protocols.IP.IPv4;
using PacketLab.Protocols.IP.IPv6;

namespace PacketLab.Desktop.Services.PacketExplorer;

internal sealed class CaptureIndex : IDisposable
{
    private const int SegmentSize = 4096;
    private readonly SafeFileHandle file;
    private readonly object gate = new();
    private readonly List<CaptureRecord[]> records = [];
    private readonly Dictionary<int, FragmentGroup> groups = [];
    private readonly Dictionary<int, int> groupByRecord = [];
    private readonly Dictionary<int, string> comments = [];
    private readonly Lazy<FileStream> derivedFile = new(OpenDerivedFile);
    private int count;
    private int diagnostics;
    private int groupCount;
    private int timedRecords;
    private CaptureTime firstTime;
    private CaptureTime lastTime;
    private PcapFileHeader? header;
    private string format = "—";
    private string error = "";

    internal CaptureIndex(string path)
    {
        Path = path;
        file = File.OpenHandle(path, FileMode.Open, FileAccess.Read, FileShare.Read, FileOptions.RandomAccess);
    }

    internal string Path { get; }

    internal CaptureSnapshot Scan(Action<CaptureSnapshot> progress, CancellationToken token)
    {
        using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.Read, 256 * 1024,
            FileOptions.SequentialScan);
        using var scanner = new Scanner(this, progress, token);

        return scanner.Scan(stream);
    }

    private sealed class Scanner(CaptureIndex index, Action<CaptureSnapshot> progress, CancellationToken token) : IDisposable
    {
        private readonly Dictionary<uint, PacketInspection> inspections = [];
        private readonly System.Diagnostics.Stopwatch timer = System.Diagnostics.Stopwatch.StartNew();
        private long section = -1;

        internal CaptureSnapshot Scan(FileStream stream)
        {
            var opened = Capture.Open(stream);
            switch (opened)
            {
                case PcapReader reader:
                    ScanPcap(reader);
                    break;

                case PcapNgReader reader:
                    ScanPcapNg(reader);
                    break;

                case PcapError failure:
                    index.SetError(failure);
                    break;
            }
            var reason = index.error.Length == 0 ? IpReassemblyAnalysisReason.EndOfCapture : IpReassemblyAnalysisReason.Aborted;
            Finish(reason);

            return index.Snapshot(opened.Value as PcapNgReader);
        }

        private void ScanPcap(PcapReader reader)
        {
            var header = reader.Header;
            index.header = header;
            index.format = $"PCAP {header.MajorVersion}.{header.MinorVersion}";
            foreach (var result in reader.ReadPackets())
            {
                token.ThrowIfCancellationRequested();
                if (result.Value is PcapError failure)
                {
                    index.SetError(failure);
                    break;
                }

                var packet = (PcapPacket)result.Value!;
                var time = CaptureTime.From(packet.Timestamp);
                var decoding = PcapAnalysis.Decode(header, packet);
                var record = AddPacket(packet.DataOffset, packet.Data.Length, packet.OriginalLength, time, decoding, iface: null, kind: default, comment: null);
                ReportProgress(record, null);
            }
        }

        private void ScanPcapNg(PcapNgReader reader)
        {
            var sections = reader.Sections;
            var initial = sections[0];
            index.format = $"PCAPNG {initial.MajorVersion}.{initial.MinorVersion}";
            foreach (var result in reader.ReadPackets())
            {
                token.ThrowIfCancellationRequested();
                EnterSection(sections[^1].Number);
                if (result.Value is PcapError failure)
                {
                    index.SetError(failure);
                    break;
                }

                var packet = (PcapNgPacket)result.Value!;
                var time = CaptureTime.From(packet.Timestamp);
                var decoding = PcapAnalysis.Decode(packet);
                var comments = packet.Options.IsEmpty ? null : string.Join(" · ", packet.Comments);
                var record = AddPacket(packet.DataOffset, packet.Data.Length, packet.OriginalLength, time, decoding,
                    packet.Interface, packet.Kind, comments);
                ReportProgress(record, reader);
            }
            EnterSection(sections[^1].Number);
        }

        private void EnterSection(long next)
        {
            if (section == next)
                return;

            Finish(IpReassemblyAnalysisReason.EndOfSection);
            section = next;
        }

        private void Finish(IpReassemblyAnalysisReason reason)
        {
            foreach (var inspection in inspections.Values)
            {
                index.SaveGroups(inspection.Finish(reason));
                inspection.Dispose();
            }
            inspections.Clear();
        }

        private int AddPacket(long offset, int length, uint original, CaptureTime time, ProtocolDecodeResult decoding,
            PcapNgInterface? iface, PcapNgPacketKind? kind, string? comment)
        {
            var summary = PacketSummary.From(decoding);
            var issue = time.Kind switch
            {
                TimeKind.Missing => PacketIssue.NoTime,
                TimeKind.Invalid => PacketIssue.InvalidTime,
                _ => PacketIssue.None
            };
            issue |= ((long)length).CompareTo(original) switch
            {
                > 0 => PacketIssue.InvalidCaptureLength,
                < 0 => PacketIssue.Truncated,
                _ => PacketIssue.None
            };
            var fragment = PacketSummary.Fragment(decoding);
            summary = summary with { Issue = summary.Issue | issue };
            var record = new CaptureRecord(offset, length, original, time, summary, iface, kind, fragment);
            var position = index.Append(record, comment);
            var id = iface?.Id ?? 0;
            if (!inspections.TryGetValue(id, out var inspection))
            {
                inspection = new PacketInspection();
                inspections.Add(id, inspection);
            }

            var number = position + 1L;
            inspection.AdvanceTime(time.Nanoseconds());
            index.SaveGroups(inspection.Expire(number));
            if (fragment is not null)
                index.SaveGroups(inspection.AnalyzePacket(number, decoding));

            return position;
        }

        private void ReportProgress(int record, PcapNgReader? reader)
        {
            if (record % 256 != 0 || timer.ElapsedMilliseconds < 220)
                return;

            progress(index.Snapshot(reader));
            timer.Restart();
        }

        public void Dispose()
        {
            foreach (var inspection in inspections.Values)
                inspection.Dispose();
        }
    }

    private CaptureSnapshot Snapshot(PcapNgReader? reader) => new(count, groupCount, diagnostics, format, header,
        reader is null ? [] : reader.Sections.ToArray(),
            reader is null ? [] : reader.Interfaces.ToArray(),
        firstTime, lastTime, timedRecords, error.Length == 0 ? null : error);

    private void SetError(PcapError failure)
    {
        var scope = failure.RecordNumber is { } number ? $" · #{number:000}" : "";
        var diagnostic = CaptureDiagnostics.ParseFailure(failure);
        error = UIText.Format(Strings.CaptureErrorAtOffset, failure.Offset, failure.Offset, scope, diagnostic);
    }

    private int Append(CaptureRecord record, string? comment)
    {
        if (record.Time.Kind == TimeKind.Present)
        {
            if (timedRecords == 0 || record.Time.CompareTo(firstTime) < 0)
                firstTime = record.Time;
            if (timedRecords == 0 || record.Time.CompareTo(lastTime) > 0)
                lastTime = record.Time;

            timedRecords++;
        }
        if (record.Summary.Issue != PacketIssue.None)
            diagnostics++;

        lock (gate)
        {
            var index = count;
            if (index % SegmentSize == 0)
                records.Add(new CaptureRecord[SegmentSize]);

            records[index / SegmentSize][index % SegmentSize] = record;
            if (!string.IsNullOrEmpty(comment))
                comments.Add(index, comment);
            count++;

            return index;
        }
    }

    private void SaveGroups(ImmutableArray<IpReassemblyEvent> updates)
    {
        if (updates.IsEmpty)
            return;

        lock (gate)
        {
            foreach (var update in updates)
                SaveGroup(update);
        }
    }

    private void SaveGroup(IpReassemblyEvent update)
    {
        if (update.RecordNumbers.IsEmpty)
            return;

        var key = checked((int)(update.DatagramNumber - 1));
        var known = groups.GetValueOrDefault(key);
        var members = update.RecordNumbers.Select(number => checked((int)(number - 1))).ToImmutableArray();
        if (known is null)
            groupCount++;
        else if (known.Status is not (IpReassemblyStatus.Pending or IpReassemblyStatus.Duplicate))
        {
            // The association-limit event reports the triggering record and the earlier accepted fragments separately.
            if (update.Reason == IpReassemblyAnalysisReason.RecordAssociationLimit && members[^1] < known.Records[0])
                groups[key] = known with { Records = members.AddRange(known.Records) };

            // Later fragments of a discarded identity remain associated without becoming evidence for the original failure.
            foreach (var index in members)
                groupByRecord[index] = key;

            if (known.Failed)
                CountGroupDiagnostics(members, known);

            return;
        }

        var offset = 0L;
        var length = 0;
        FragmentSlice? slice = null;
        var summary = default(PacketSummary);
        if (update.Packet is { } packet)
        {
            var spool = derivedFile.Value;
            offset = spool.Position;
            length = packet.Bytes.Length;
            spool.Write(packet.Bytes.Span);
            slice = ResultSlice(packet, members);
            summary = packet.Decoding.Value switch
            {
                IPv4DecodeResult { Value: DecodedIPv4 ipv4 } => PacketSummary.FromIPv4(ipv4),
                IPv6DecodeResult { Value: DecodedIPv6 ipv6 } => PacketSummary.FromIPv6(ipv6),
                _ => default
            };
        }
        var group = new FragmentGroup(update.IpVersion, update.Identification, members, update.Status, update.Reason,
            update.Reassembly.DiagnosticCode, offset, length, slice, summary);
        groups[key] = group;
        if (update.Status is IpReassemblyStatus.Pending or IpReassemblyStatus.Duplicate)
            groupByRecord[members[^1]] = key;
        else
        {
            foreach (var index in members)
                groupByRecord[index] = key;
        }
        if (group.Failed)
            CountGroupDiagnostics(members, group);
    }

    private void CountGroupDiagnostics(ImmutableArray<int> members, FragmentGroup group)
    {
        if (group.Status == IpReassemblyStatus.Conflict)
        {
            if (ReadRecord(members[^1]).Summary.Issue == PacketIssue.None)
                diagnostics++;

            return;
        }

        foreach (var index in members)
        {
            if (ReadRecord(index).Summary.Issue == PacketIssue.None)
                diagnostics++;
        }
    }

    private FragmentSlice? ResultSlice(ReassembledIpPacket packet, ImmutableArray<int> members)
    {
        var first = members.Select(index => ReadRecord(index).Fragment).FirstOrDefault(item => item is { Offset: 0 });
        if (first is not { } fragment)
            return null;

        var start = fragment.Start - 14;
        if (packet.Decoding.Value is IPv6DecodeResult)
            start -= 8;

        return start >= 0 && start <= packet.Bytes.Length ? new(0, start, packet.Bytes.Length - start, false) : null;
    }

    private static FileStream OpenDerivedFile() => new(
        System.IO.Path.Combine(System.IO.Path.GetTempPath(), $"packetlab-{Guid.NewGuid():N}.tmp"),
        FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None, bufferSize: 1,
        FileOptions.DeleteOnClose | FileOptions.RandomAccess);

    internal CaptureRecord ReadRecord(int index)
    {
        lock (gate)
            return records[index / SegmentSize][index % SegmentSize];
    }

    internal FragmentGroup? Group(int index)
    {
        lock (gate)
            return groupByRecord.TryGetValue(index, out var key) ? groups[key] : null;
    }

    internal string Comment(int index)
    {
        lock (gate)
            return comments.GetValueOrDefault(index) ?? Strings.NotProvided;
    }

    internal byte[] ReadBytes(CaptureRecord record) => ReadAt(file, record.DataOffset, record.Length);

    internal byte[] ReadDerived(FragmentGroup group)
    {
        lock (gate)
            return ReadAt(derivedFile.Value.SafeFileHandle, group.DerivedOffset, group.DerivedLength);
    }

    internal byte[] ReadFragment(CaptureRecord record, int maxLength)
    {
        if (record.Fragment is not { } fragment)
            return [];

        var length = Math.Min(fragment.Length, Math.Max(0, maxLength - fragment.Offset));

        return ReadAt(file, record.DataOffset + fragment.Start, length);
    }

    private static byte[] ReadAt(SafeFileHandle handle, long offset, int length)
    {
        var bytes = new byte[length];
        var read = 0;
        while (read < bytes.Length)
        {
            var received = RandomAccess.Read(handle, bytes.AsSpan(read), offset + read);
            if (received == 0)
                throw new EndOfStreamException(Strings.CaptureChanged);

            read += received;
        }

        return bytes;
    }

    internal ProtocolDecodeResult Decode(CaptureRecord record, ReadOnlyMemory<byte> bytes) => ProtocolDecoder.Decode(bytes,
        LinkTypeFor(record) == 1 ? LinkLayerProtocol.Ethernet : LinkLayerProtocol.Unsupported);

    internal ushort LinkTypeFor(CaptureRecord record) => record.LinkType(header);

    public void Dispose()
    {
        file.Dispose();
        lock (gate)
        {
            if (derivedFile.IsValueCreated)
                derivedFile.Value.Dispose();
        }
    }
}
