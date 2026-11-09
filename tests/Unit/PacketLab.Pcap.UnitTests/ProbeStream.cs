namespace PacketLab.Pcap.UnitTests;

internal sealed class ProbeStream(byte[] bytes) : Stream
{
    internal int ChunkSize { get; init; } = int.MaxValue;
    internal int? FailAt { get; set; }
    internal Exception Failure { get; init; } = new IOException("injected read failure");
    internal int BytesRead { get; private set; }
    internal int ReadCalls { get; private set; }
    internal bool IsDisposed { get; private set; }
    public override bool CanRead => !IsDisposed;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

    public override int Read(Span<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(IsDisposed, this);
        ReadCalls++;
        if (FailAt is { } failureOffset && BytesRead >= failureOffset)
            throw Failure;
        int count = Math.Min(buffer.Length, Math.Min(ChunkSize, bytes.Length - BytesRead));
        if (FailAt is { } boundary)
            count = Math.Min(count, boundary - BytesRead);
        bytes.AsSpan(BytesRead, count).CopyTo(buffer);
        BytesRead += count;
        return count;
    }

    public override int Read(byte[] buffer, int offset, int count) => Read(buffer.AsSpan(offset, count));
    protected override void Dispose(bool disposing) { IsDisposed = true; base.Dispose(disposing); }
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
