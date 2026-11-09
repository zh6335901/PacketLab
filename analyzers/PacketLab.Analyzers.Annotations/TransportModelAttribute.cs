namespace PacketLab.Analyzers.Annotations;

// Data carriers do not own domain state invariants. This exemption applies only to the marked type.
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Struct, Inherited = false)]
public sealed class TransportModelAttribute : Attribute;
