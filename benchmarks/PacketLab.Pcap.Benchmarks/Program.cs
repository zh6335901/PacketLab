using BenchmarkDotNet.Running;
using PacketLab.Pcap.Benchmarks;

BenchmarkSwitcher.FromAssembly(typeof(PcapReaderBenchmarks).Assembly).Run(args);
