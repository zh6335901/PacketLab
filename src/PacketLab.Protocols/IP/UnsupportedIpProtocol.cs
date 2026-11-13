namespace PacketLab.Protocols.IP;

public sealed record UnsupportedIpProtocol(byte Protocol, uint DeclaredLength, ReadOnlyMemory<byte> Bytes);
