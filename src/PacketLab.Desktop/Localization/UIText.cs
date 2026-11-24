using System.Globalization;

namespace PacketLab.Desktop.Localization;

internal static class UIText
{
    internal static string Format(string pattern, params object?[] arguments) =>
        string.Format(CultureInfo.CurrentCulture, pattern, arguments);
}
