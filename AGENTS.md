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
- Keep code easy to follow by giving intermediate values meaningful names and splitting dense expressions or nested conditionals into clear steps.
- Be mindful of performance, memory allocations, and resource efficiency.
- Measure before optimizing.
- Sequence work into verifiable units; verify each before proceeding.
- Write documentation only when explicitly requested.
- Add comments only to explain non-obvious special handling.
