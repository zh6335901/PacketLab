using System.Buffers.Binary;
using static PacketLab.Cli.E2ETests.CliProcess;

namespace PacketLab.Cli.E2ETests;

public class InspectArpTests
{
    [Test]
    [Arguments("000108000604000102000000000100000000000000000000C0000202", "Request", "02:00:00:00:00:01", "0.0.0.0", "00:00:00:00:00:00", "192.0.2.2")]
    [Arguments("0001080006040002102030405060C0000202020000000001C0000201", "Reply", "10:20:30:40:50:60", "192.0.2.2", "02:00:00:00:00:01", "192.0.2.1")]
    [Arguments("1234080006040001020000000001C0000201000000000000C0000202", "Request", "020000000001", "192.0.2.1", "000000000000", "192.0.2.2")]
    [Arguments("0001123406040001020000000001C0000201000000000000C0000202", "Request", "02:00:00:00:00:01", "C0000201", "00:00:00:00:00:00", "C0000202")]
    [Arguments("000108000204ABCD0102C00002010304C0000202", "43981", "0102", "192.0.2.1", "0304", "192.0.2.2")]
    [Arguments("0001080006030001020000000001010203102030405060040506", "Request", "02:00:00:00:00:01", "010203", "10:20:30:40:50:60", "040506")]
    public async Task Inspect_formats_hardware_and_protocol_addresses_independently(string hex, string operation,
        string senderHardware, string senderProtocol, string targetHardware, string targetProtocol)
    {
        using var input = new InputFile(Capture(Convert.FromHexString(hex)));
        var result = await Run("pcap", "inspect", input.Path);
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Error).IsEqualTo("");
        await Assert.That(result.Output.TrimEnd()).IsEqualTo($"Record 1: src 02:00:00:00:00:01 dst FF:FF:FF:FF:FF:FF EtherType 0x0806 (ARP); ARP {operation} sender hardware {senderHardware} protocol {senderProtocol} target hardware {targetHardware} protocol {targetProtocol}");
    }

    [Test]
    public async Task Incomplete_arp_reports_lengths_and_continues_to_the_next_record()
    {
        var complete = Convert.FromHexString("0001080006040001020000000001C0000201102030405060C0000202");
        using var input = new InputFile(Capture(complete[..27], complete));
        var result = await Run("pcap", "inspect", input.Path);
        await Assert.That(result.ExitCode).IsEqualTo(0);
        await Assert.That(result.Output).Contains("Incomplete ARP header: expected 28 bytes, captured 27.");
        await Assert.That(result.Output).Contains("Record 2: src");
        await Assert.That(result.Output).Contains("target hardware 10:20:30:40:50:60 protocol 192.0.2.2");
    }

    private static byte[] Capture(params byte[][] payloads)
    {
        using var stream = new MemoryStream();
        stream.Write(Convert.FromHexString("D4C3B2A1020004000000000000000000FFFF000001000000"));
        foreach (var payload in payloads)
        {
            var frame = Convert.FromHexString("FFFFFFFFFFFF0200000000010806").Concat(payload).ToArray();
            var header = new byte[16];
            BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(8), (uint)frame.Length);
            BinaryPrimitives.WriteUInt32LittleEndian(header.AsSpan(12), 60);
            stream.Write(header);
            stream.Write(frame);
        }
        return stream.ToArray();
    }
}
