namespace PacketLab.Pcap.Benchmarks.UnitTests;

public class ReadToEndTests
{
    [Test]
    [Arguments(64)]
    [Arguments(1500)]
    public async Task Repeated_invocations_read_the_entire_capture(int payloadSize)
    {
        var benchmark = new PcapReaderBenchmarks { PayloadSize = payloadSize };
        benchmark.PrepareCapture();
        try
        {
            var expected = (4096, 4096L * payloadSize);
            await Assert.That(benchmark.ReadToEnd()).IsEqualTo(expected);
            await Assert.That(benchmark.ReadToEnd()).IsEqualTo(expected);
        }
        finally
        {
            benchmark.CloseCapture();
        }
    }
}
