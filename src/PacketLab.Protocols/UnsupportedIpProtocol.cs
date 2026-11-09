namespace PacketLab.Protocols;

public sealed record UnsupportedIpProtocol(byte Protocol, uint DeclaredLength, ReadOnlyMemory<byte> Bytes);
