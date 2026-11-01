using BenchmarkDotNet.Running;
using PacketLab.Analysis.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(PcapAnalysisReaderBenchmarks).Assembly).Run(args);
