using PacketLab.Desktop.Localization;
using PacketLab.Pcap;

namespace PacketLab.Desktop.Services.PacketExplorer;

internal static class CaptureDiagnostics
{
    internal static string ReadFailure(Exception error) => error switch
    {
        FileNotFoundException => Strings.FileMissing,
        DirectoryNotFoundException => Strings.DirectoryMissing,
        UnauthorizedAccessException => Strings.FileAccessDenied,
        EndOfStreamException => Strings.CaptureChanged,
        PathTooLongException => Strings.FilePathTooLong,
        ArgumentException or NotSupportedException => Strings.InvalidFilePath,
        _ => UIText.Format(Strings.FileIoError, error.HResult)
    };

    internal static string ParseFailure(PcapError error) => error switch
    {
        PcapError.InvalidPcapNg block => NgBlockFailure(block),
        PcapError.UnsupportedFormat format => UIText.Format(Strings.InvalidCaptureMagic, format.Magic),
        PcapError.PcapNgNotSupported => Strings.UnsupportedPcapNg,
        PcapError.UnsupportedVersion version => UIText.Format(Strings.UnsupportedPcapVersion, version.Major, version.Minor),
        PcapError.IncompleteFileHeader partial => UIText.Format(Strings.IncompleteCaptureHeader, partial.ReadBytes),
        PcapError.IncompleteRecordHeader partial => UIText.Format(Strings.IncompleteRecordHeader, partial.ReadBytes),
        PcapError.IncompletePacketData partial => UIText.Format(Strings.IncompletePacketData, partial.ExpectedBytes, partial.ReadBytes),
        PcapError.InvalidSnapLen => Strings.InvalidSnapLen,
        PcapError.InvalidLinkTypeReservedBits link => UIText.Format(Strings.InvalidLinkTypeBits, link.RawLinkType),
        PcapError.CapturedLengthExceedsSnapLen length => UIText.Format(Strings.LengthExceedsSnapLen, length.CapturedLength, length.SnapLen),
        PcapError.PacketLimitExceeded limit => UIText.Format(Strings.PacketLimitExceeded, limit.CapturedLength, limit.MaxPacketBytes),
        null => Strings.UnrecognizedCapture
    };

    private static string NgBlockFailure(PcapError.InvalidPcapNg block)
    {
        var diagnostic = block.Diagnostic;
        var resourceKey = $"PcapNg{diagnostic.Code}";
        var pattern = Strings.ResourceManager.GetString(resourceKey) ?? Strings.PcapNgInvalidBlock;
        var detail = UIText.Format(pattern, diagnostic.FirstArgument, diagnostic.SecondArgument);

        return UIText.Format(Strings.PcapNgBlockAtOffset, block.BlockOffset, detail);
    }
}
