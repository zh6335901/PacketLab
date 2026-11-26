using Avalonia;
using Avalonia.Controls;
using PacketLab.Desktop.Controls.PacketExplorer;
using PacketLab.Desktop.Localization;
using PacketLab.Desktop.Models.PacketExplorer;
using PacketLab.Desktop.ViewModels.PacketExplorer;
using static PacketLab.Desktop.E2ETests.ExplorerTestHost;
using static PacketLab.Desktop.E2ETests.Fixtures.CaptureFiles;

namespace PacketLab.Desktop.E2ETests.PacketExplorer;

public sealed class InspectFragmentCoverageTests
{
    [Test]
    public async Task Selecting_reassembled_bytes_preserves_the_capture_record_and_reveals_the_field()
    {
        var result = await WithExplorer(async window =>
        {
            await SelectFixtureFragment(window);
            await WaitFor(() => FindRecordBytes(window, 5) is not null);
            SaveFrame(window, "app-main");
            Click(window, GetById<Button>(window, "ToggleFullBytes"));
            await WaitFor(() => FindById<Button>(window, "ReassembledByteSource") is not null);
            SaveFrame(window, "app-expanded");

            Click(window, GetById<Button>(window, "ReassembledByteSource"));
            await WaitFor(() => FindById<HexView>(window, "ReassembledEvidenceBytes") is not null &&
                FindById<TextBlock>(window, "SelectedFieldValue") is not null);
            var selection = (ByteSelection)GetById<ContentControl>(window, "ByteSelectionDetails").Content!;

            return (Record: IsRecordSelected(window, 5), Range: selection.Field?.Range,
                Value: GetById<TextBlock>(window, "SelectedFieldValue").Text);
        });

        await Assert.That(result.Record).IsTrue();
        await Assert.That(result.Range).IsEqualTo(new ByteRange(0x0016, 2));
        await Assert.That(result.Value).IsEqualTo("53");
    }

    [Test]
    public async Task A_middle_fragment_arriving_after_the_tail_is_labeled_as_completing_the_datagram()
    {
        var file = Path.GetTempFileName();
        try
        {
            WriteOutOfOrderIpv6Capture(file);
            var result = await WithExplorer(async window =>
            {
                await WaitFor(() => FindRow(window, 3) is not null);
                Click(window, FindRow(window, 3)!);
                await WaitFor(() => IsRecordSelected(window, 3) && FindRecordBytes(window, 3) is not null);

                var row = FindRow(window, 3)!;
                var details = GetById<ScrollViewer>(window, "RecordDetails");
                var title = UIText.Format(Strings.ReassemblyCompletion, "IPv6", Strings.MiddleFragment);

                return (Row: ReadText(row).ToArray(), Details: ReadText(details).ToArray(), Title: title);
            }, file);

            await Assert.That(result.Row).Contains(result.Title);
            await Assert.That(result.Details).Contains(result.Title);
        }
        finally
        {
            File.Delete(file);
        }
    }

    [Test]
    public async Task Clicking_a_coverage_byte_reports_its_frame_and_reassembled_offsets()
    {
        var result = await WithExplorer(async window =>
        {
            await SelectFixtureFragment(window);
            var map = GetById<CoverageMatrix>(window, "FragmentCoverage");

            Click(window, map, new Point(148, 67));
            await WaitFor(() => FindById<TextBlock>(window, "FragmentByteLocation") is not null);
            var selection = (ByteSelection)GetById<ContentControl>(window, "ByteSelectionDetails").Content!;

            return (selection.Payload, Location: GetById<TextBlock>(window, "FragmentByteLocation").Text);
        });

        await Assert.That(result.Payload).IsEqualTo(0);
        await Assert.That(result.Location).Contains("#005");
        await Assert.That(result.Location).Contains("0x0022");
        await Assert.That(result.Location).Contains("0x0014");
        await Assert.That(result.Location).Contains("04");
    }

    [Test]
    public async Task Overlapping_ipv6_fragments_display_the_conflict_without_a_derived_datagram()
    {
        var result = await WithExplorer(async window =>
        {
            await WaitFor(() => FindRow(window, 12) is not null);
            Click(window, FindRow(window, 12)!);
            await WaitFor(() => IsRecordSelected(window, 12) &&
                FindById<TextBlock>(window, "FragmentCoverageSummary") is not null);
            SaveFrame(window, "app-overlap");
            var message = GetById<TextBlock>(window, "FragmentCoverageSummary").Text;
            Click(window, GetById<Button>(window, "ToggleFullBytes"));
            await WaitFor(() => FindById<Button>(window, "RecordByteSource-12") is not null);

            return (Message: message, Derived: FindById<Button>(window, "ReassembledByteSource") is not null);
        });

        await Assert.That(result.Message).Contains("8–15");
        await Assert.That(result.Derived).IsFalse();
    }

    [Test]
    [Arguments((ushort)8)]
    [Arguments((ushort)16)]
    public async Task Incompatible_ipv6_headers_show_the_header_conflict_in_the_record_and_coverage(ushort tailOffset)
    {
        var file = Path.GetTempFileName();
        try
        {
            WriteIpv6HeaderConflictCapture(file, tailOffset);
            var result = await WithExplorer(async window =>
            {
                await WaitFor(() => FindRow(window, 2) is not null);
                Click(window, FindRow(window, 2)!);
                await WaitFor(() => IsRecordSelected(window, 2) &&
                    FindById<TextBlock>(window, "FragmentCoverageSummary") is not null);

                return (Explanation: GetById<TextBlock>(window, "RecordExplanation").Text,
                    Coverage: GetById<TextBlock>(window, "FragmentCoverageSummary").Text,
                    Diagnostic: Strings.ReassemblyIncompatibleHeaders,
                    VisibleText: ReadText(window).ToArray(),
                    FirstOverlapTitle: UIText.Format(Strings.OverlapFirstFragment, "IPv6"),
                    ConflictOverlapTitle: UIText.Format(Strings.FragmentOverlap, "IPv6"));
            }, file);

            await Assert.That(result.Explanation).Contains(result.Diagnostic);
            await Assert.That(result.Coverage).Contains(result.Diagnostic);
            await Assert.That(result.VisibleText).DoesNotContain(result.FirstOverlapTitle);
            await Assert.That(result.VisibleText).DoesNotContain(result.ConflictOverlapTitle);
        }
        finally
        {
            File.Delete(file);
        }
    }
}
