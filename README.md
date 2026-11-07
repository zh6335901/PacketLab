# PacketLab

PacketLab is a lightweight, local-first network protocol analysis and experimentation tool.

## Goals

- Explore and understand network protocols through visualization and hands-on experiments.
- Build practical networking and diagnostic tools.
- Continuously improve performance, memory efficiency, and resource usage.
- Explore reliable Agent-assisted software development.

## Planned Capabilities

PacketLab will evolve incrementally:

1. **Packet Analyzer** — PCAP parsing, protocol inspection, and traffic visualization.
2. **Network Simulator** — TCP behavior simulation and controlled network experiments.
3. **Network Benchmark** — Network performance measurement and analysis.

These are long-term directions, not commitments for the first release.

## Status

Early development.

## Mutation testing (opt-in)

Use the .NET SDK selected by `global.json`. Restore the pinned local Stryker.NET
5.0.0 tool from the repository root:

```sh
dotnet tool restore
```

Run against a selected source file from its unit test project directory. For
example, to check IPv4Parser with the existing protocol unit tests:

```sh
cd tests/Unit/PacketLab.Protocols.UnitTests
dotnet stryker --config-file ../../../stryker-config.json --mutate "IPv4/IPv4Parser.cs"
```

The `--mutate` path or glob is relative to the **production project** directory
(`src/PacketLab.Protocols` in this example). To check another parser, replace it
with e.g. `"Ethernet/EthernetParser.cs"` or `"Arp/ArpParser.cs"`. For another
production project, run from its corresponding unit test project directory and
adjust the config path as needed. If that test project references multiple
production projects, also pass `--project "PacketLab.Pcap.csproj"` (using the
desired project filename). Omitting `--mutate` selects all source files in the
chosen production project.

The shared config selects the `mtp` runner for TUnit and `preview` language mode
for C# 15 union syntax with Stryker.NET 5.0.0. The tool manifest allows runtime
roll-forward so the tool can run on the repository's .NET 11 runtime.

Inspect the console summary and open
`StrykerOutput/<run>/reports/mutation-report.html` under the directory where you
ran Stryker. The same directory contains `mutation-report.json` for inspecting
individual mutants. These local reports are ignored by Git.

Mutation testing runs only when explicitly invoked; it is not part of CI.
No mutation score is enforced (Stryker's default break threshold is 0).
