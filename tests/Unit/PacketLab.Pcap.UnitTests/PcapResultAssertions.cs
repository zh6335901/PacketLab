using PacketLab.Pcap;
using TUnit.Assertions.Exceptions;

namespace PacketLab.Pcap.UnitTests;

internal static class PcapResultAssertions
{
    internal static Task<PcapReader> ShouldSucceed(this PcapOpenResult result) => result switch
    {
        PcapReader reader => Task.FromResult(reader),
        PcapError error => throw new AssertionException($"Expected opening to succeed, got: {error.Message}"),
        null => throw new AssertionException("Expected opening to succeed, got an uninitialized result.")
    };

    internal static Task<PcapPacket> ShouldSucceed(this PcapReadResult result) => result switch
    {
        PcapPacket packet => Task.FromResult(packet),
        PcapEndOfFile => throw new AssertionException("Expected a packet, got end of file."),
        PcapError error => throw new AssertionException($"Expected a packet, got: {error.Message}"),
        null => throw new AssertionException("Expected a packet, got an uninitialized result.")
    };

    internal static Task<PcapError> ShouldFail(this PcapOpenResult result) => result switch
    {
        PcapError error => Task.FromResult(error),
        PcapReader => throw new AssertionException("Expected opening to fail, got a reader."),
        null => throw new AssertionException("Expected opening to fail, got an uninitialized result.")
    };

    internal static Task<PcapError> ShouldFail(this PcapReadResult result) => result switch
    {
        PcapError error => Task.FromResult(error),
        PcapPacket => throw new AssertionException("Expected reading to fail, got a packet."),
        PcapEndOfFile => throw new AssertionException("Expected reading to fail, got end of file."),
        null => throw new AssertionException("Expected reading to fail, got an uninitialized result.")
    };

    internal static async Task<PcapError> ShouldFail(this PcapOpenResult result, PcapError expectedError)
    {
        var error = await result.ShouldFail();
        await Assert.That(error.Value).IsEqualTo(expectedError.Value);
        return error;
    }

    internal static async Task<PcapError> ShouldFail(this PcapReadResult result, PcapError expectedError)
    {
        var error = await result.ShouldFail();
        await Assert.That(error.Value).IsEqualTo(expectedError.Value);
        return error;
    }
}
