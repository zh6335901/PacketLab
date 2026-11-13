# PacketLab

PacketLab is a lightweight, local-first network protocol analysis and experimentation tool.

## Technology

- .NET 11 / C# 15 / F# 11
- Native AOT compatibility
- Avalonia for desktop UI
- C# 15 supports union types and closed hierarchies, enabling exhaustive pattern matching.

## Engineering Principles

- Prefer simplicity over unnecessary abstractions.
- Favor Functional Core, Imperative Shell.
- Prefer pure functions and immutability.
- Use Result types for expected domain failures; let environmental exceptions propagate to application boundaries.
- Favor type-driven design; make invalid states unrepresentable where practical.
- Prioritize correctness and maintainability.
- Be mindful of performance, memory allocations, and resource efficiency.
- Measure before optimizing.
- Sequence work into verifiable units; verify each before proceeding.
- Write documentation only when explicitly requested.
- Add comments only to explain non-obvious special handling.

## Code Organization

- `PacketLab.Protocols` owns protocol rules and byte-level processing. Stateful protocol mechanisms belong here too; state alone is not a reason to place code in Analysis.
- Group IP capabilities under `PacketLab.Protocols/IP`: `IPv4` and `IPv6` contain version-specific parsing, `Reassembly` contains the shared reassembly mechanism, and IP-wide types live directly under `IP`. Keep other protocols in their own existing folders.
- `PacketLab.Analysis/Pcap` adapts PCAP input: link types, records, timestamps, read errors, EOF, and the lifetime of a capture analysis. It may call analysis capabilities.
- `PacketLab.Analysis/IpReassembly` coordinates IP reassembly with capture record associations. It uses protocol outcomes rather than redefining protocol rules or statuses. It must not depend on PCAP types; input adapters supply record identifiers, normalized time, and decoded protocol data.
- Dependency direction: `Analysis.Pcap` → `Analysis.IpReassembly` → `Protocols.IP.Reassembly`. Protocols must not depend on Analysis, PCAP, or CLI. The IP reassembly core consumes and returns IP data without Ethernet headers, capture record numbers, or EOF semantics.
- Protocol cache/fragment/size/timeout limits belong to the protocol mechanism. Capture record association limits and record-age policies belong to Analysis. EOF and aborted analysis are analysis reasons, distinct from protocol outcomes.
- Match namespaces to folders. Group unit tests by the same capability boundaries: protocol reassembly tests use IP bytes directly; Analysis tests verify input adaptation, capture isolation, record association, and lifecycle. Keep end-to-end PCAP/CLI tests for component integration.
- Add new code beside the capability that owns its behavior. Avoid generic `Helpers`, `Managers`, or `Common` directories and speculative framework layers. Maintain these rules in this root file rather than adding project-level AGENTS.md files for this layout.
