using PacketLab.Pcap;

namespace PacketLab.Desktop.Localization;

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
        _ => UiText.Format(Strings.FileIoError, error.HResult)
    };

    internal static string ParseFailure(PcapError error) => error switch
    {
        PcapError.InvalidPcapNg block => NgBlockFailure(block),
        PcapError.UnsupportedFormat format => UiText.Format(Strings.InvalidCaptureMagic, format.Magic),
        PcapError.PcapNgNotSupported => Strings.UnsupportedPcapNg,
        PcapError.UnsupportedVersion version => UiText.Format(Strings.UnsupportedPcapVersion, version.Major, version.Minor),
        PcapError.IncompleteFileHeader partial => UiText.Format(Strings.IncompleteCaptureHeader, partial.ReadBytes),
        PcapError.IncompleteRecordHeader partial => UiText.Format(Strings.IncompleteRecordHeader, partial.ReadBytes),
        PcapError.IncompletePacketData partial => UiText.Format(Strings.IncompletePacketData, partial.ExpectedBytes, partial.ReadBytes),
        PcapError.InvalidSnapLen => Strings.InvalidSnapLen,
        PcapError.InvalidLinkTypeReservedBits link => UiText.Format(Strings.InvalidLinkTypeBits, link.RawLinkType),
        PcapError.CapturedLengthExceedsSnapLen length => UiText.Format(Strings.LengthExceedsSnapLen, length.CapturedLength, length.SnapLen),
        PcapError.PacketLimitExceeded limit => UiText.Format(Strings.PacketLimitExceeded, limit.CapturedLength, limit.MaxPacketBytes),
        null => Strings.UnrecognizedCapture
    };

    private static string NgBlockFailure(PcapError.InvalidPcapNg block)
    {
        var diagnostic = block.Diagnostic;
        var resourceKey = $"PcapNg{diagnostic.Code}";
        var pattern = Strings.ResourceManager.GetString(resourceKey) ?? Strings.PcapNgInvalidBlock;
        var detail = UiText.Format(pattern, diagnostic.FirstArgument, diagnostic.SecondArgument);

        return UiText.Format(Strings.PcapNgBlockAtOffset, block.BlockOffset, detail);
    }
}
