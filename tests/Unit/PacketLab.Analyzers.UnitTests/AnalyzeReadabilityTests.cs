using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers.UnitTests;

public class AnalyzeReadabilityTests
{
    [Test]
    [Arguments("a ? 1 : b ? 2 : 3")]
    [Arguments("a ? (b ? 1 : 2) : 3")]
    [Arguments("(a ? b : c) ? 1 : 2")]
    [Arguments("a ? 1 :\n b ? 2 : ((c ? 3 : 4))")]
    public async Task Nested_decisions_report_one_warning_per_chain(string expression)
    {
        var diagnostic = (await Analyze(expression)).Single();

        await Assert.That(diagnostic.Id).IsEqualTo("PL0004");
        await Assert.That(diagnostic.Location.SourceSpan.Length).IsEqualTo(1);
    }

    [Test]
    [Arguments("a ? 1 : 2")]
    [Arguments("a ? Read(b ? 1 : 2) : 3")]
    [Arguments("Header(Read(0), Read(2), 0)")]
    [Arguments("Header(1, 2, 3, 4)")]
    [Arguments("Header(Read(0), 2, 3, 4)")]
    [Arguments("Header(\n Read(0),\n Read(2),\n Read(4),\n Read(6))")]
    [Arguments("Header((byte)1, (byte)2, 3, 4)")]
    public async Task Simple_or_separated_expressions_pass(string expression)
    {
        var diagnostics = await Analyze(expression);

        await Assert.That(diagnostics.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments("Header(Read(0), 1, Read(2), Read(4))", "Read(2)")]
    [Arguments("Header(0,\n (byte)(1 << 2), (int)(3 + 4), 5)", "(int)(3 + 4)")]
    [Arguments("new Sample(Read(0), Read(2), Read(4), Read(6)).Value", "Read(2)")]
    public async Task Packed_computations_point_to_the_second_argument_on_the_line(string expression, string expected)
    {
        var diagnostic = (await Analyze(expression)).Single();

        await Assert.That(diagnostic.Id).IsEqualTo("PL0005");
        var span = diagnostic.Location.SourceSpan;
        await Assert.That(diagnostic.Location.SourceTree!.GetText().ToString(span)).IsEqualTo(expected);
    }

    [Test]
    public async Task Generated_code_skips_readability_warnings()
    {
        var diagnostics = await Analyze("Header(Read(0), Read(2), Read(Read(Read(Read(0)))), a ? 1 : b ? 2 : 3)",
            statements: "x = y = 0; x = Total(values.Where(v => v > 0).Select(v => v + 1));", path: "Case.g.cs");

        await Assert.That(diagnostics.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments("x = y = z = 0;")]
    [Arguments("x = (y = 0);")]
    [Arguments("var n = y = 0;")]
    [Arguments("x = 1; y = 2; z = 3;")]
    [Arguments("var n = 1; y += n;")]
    [Arguments("switch (x) { case 1: y = 1; z = 2; break; }")]
    public async Task Packed_assignments_report_one_warning(string statements)
    {
        var diagnostics = await Analyze("0", statements);

        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0006");
    }

    [Test]
    [Arguments("x = 1;\ny = 2;\nz = 3;")]
    [Arguments("(x, y) = (y, x);")]
    public async Task Separate_assignments_and_deconstruction_pass(string statements)
    {
        var diagnostics = await Analyze("0", statements);

        await Assert.That(diagnostics.IsEmpty).IsTrue();
    }

    [Test]
    [Arguments("Read(Read(Read(0)))")]
    [Arguments("Read(Read(Read(Read(0))))")]
    [Arguments("Read(Read((int)(Read(Read(Read(0))))))")]
    public async Task Three_or_more_directly_nested_calls_report_once(string expression)
    {
        var diagnostics = await Analyze(expression);

        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0007");
    }

    [Test]
    [Arguments("Total(values.Where(v => v > 0).Select(v => v + 1))")]
    [Arguments("Total(values.Distinct().Reverse())")]
    [Arguments("Total(values.Where(v => v > 0 && v < 10))")]
    [Arguments("Total(values.Distinct().Reverse().ToArray())")]
    [Arguments("Total(from v in values where v > 0 select v)")]
    [Arguments("Read(1 + 2 * (3 + 4) - 5)")]
    [Arguments("Read(1 + 2 * (3 + 4))")]
    public async Task Computations_inside_one_argument_report_even_without_sibling_arguments(string expression)
    {
        var diagnostics = await Analyze(expression);

        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0008");
    }

    [Test]
    [Arguments("Read(Read(0))")]
    [Arguments("Total(values.Distinct())")]
    [Arguments("Total(values.Where(v => v > 0))")]
    [Arguments("Total(values.Where(v => v + 1 > 0))")]
    [Arguments("values.Where(v => v > 0).Select(v => v + 1).Sum()")]
    [Arguments("Total(from v in values select v)")]
    [Arguments("Read(1 + 2 * 3)")]
    public async Task Short_arguments_and_standalone_pipelines_pass(string expression)
    {
        var diagnostics = await Analyze(expression);

        await Assert.That(diagnostics.IsEmpty).IsTrue();
    }

    private static readonly ImmutableArray<MetadataReference> References =
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
        .Where(p => Path.GetFileName(p) is "System.Private.CoreLib.dll" or "System.Runtime.dll" or "System.Linq.dll")
        .Select(p => MetadataReference.CreateFromFile(p)).ToImmutableArray<MetadataReference>();

    private static async Task<ImmutableArray<Diagnostic>> Analyze(string expression, string statements = "", string path = "Case.cs")
    {
        var source = $$"""
            using System.Collections.Generic;
            using System.Linq;
            class Sample
            {
                public int Value;
                public Sample(int a, int b, int c, int d) { Value = a; }
                static int Read(int offset) => offset;
                static int Header(int a, int b, int c, int d = 0) => a;
                static int Total(IEnumerable<int> items) => items.Sum();
                static int Parse(bool a, bool b, bool c, int[] values) => {{expression}};
                static void Update(int x, int y, int z, int[] values) { {{statements}} }
            }
            """;
        var tree = CSharpSyntaxTree.ParseText(source, path: path);
        var compilation = CSharpCompilation.Create("ReadabilityCase", [tree], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error);
        await Assert.That(string.Join("\n", errors)).IsEqualTo("");
        return await compilation.WithAnalyzers([new ReadabilityAnalyzer(), new AssignmentLayoutAnalyzer(), new CallComplexityAnalyzer()])
            .GetAnalyzerDiagnosticsAsync();
    }
}
