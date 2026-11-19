using BenchmarkDotNet.Running;
using PacketLab.Analysis.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(PcapAnalysisBenchmarks).Assembly).Run(args);
