using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Testing.Analyzers.UnitTests;

public class CheckExpectedValuesTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
        .Select(path => (MetadataReference)MetadataReference.CreateFromFile(path)).ToImmutableArray();

    [Test]
    [Arguments("new Result(n, flag)", 0)]
    [Arguments("(n, flag)", 0)]
    [Arguments("new Box { Items = [(n, flag)] }", 0)]
    [Arguments("new int[] { n, 2 }", 0)]
    [Arguments("new System.Collections.Generic.List<int> { n, 2 }", 0)]
    [Arguments("result.Calculated", 1)]
    [Arguments("new Box { Items = [(n / 2, flag)] }", 1)]
    [Arguments("flag ? n : 3", 1)]
    [Arguments("System.IO.File.ReadAllText(System.IO.Path.Combine(System.AppContext.BaseDirectory, name + \".txt\")).ReplaceLineEndings(\"\\n\")", 0)]
    [Arguments("System.IO.File.ReadAllText(flag ? \"one\" : \"two\")", 1)]
    [Arguments("System.IO.File.ReadAllText(name).Length * 8", 1)]
    [Arguments("alias", 1)]
    [Arguments("incremented", 1)]
    [Arguments("rewritten", 1)]
    [Arguments("copied", 0)]
    [Arguments("Identity(n)", 0)]
    [Arguments("Identity(n * 8)", 1)]
    [Arguments("new Result(n, flag).Compute()", 1)]
    public async Task Only_explicit_answers_and_their_components_pass(string expression, int expectedCount)
    {
        var compilation = Compile(expression);
        var diagnostics = await compilation.WithAnalyzers([new ExplicitExpectationAnalyzer()]).GetAnalyzerDiagnosticsAsync();

        await Assert.That(diagnostics.Length).IsEqualTo(expectedCount);
        await Assert.That(diagnostics.All(d => d.Id == "PL0014" && d.Severity == DiagnosticSeverity.Warning)).IsTrue();
    }

    [Test]
    [Arguments("counter.Value", "baseline", false, 0)]
    [Arguments("other.Value", "baseline", false, 1)]
    [Arguments("counter.Value", "baseline", true, 1)]
    [Arguments("counter.Double", "derived", false, 1)]
    public async Task Before_after_comparisons_require_the_same_stored_property(
        string observed, string expected, bool replaceCounter, int expectedCount)
    {
        var compilation = Compile(expected, actual: observed, replaceCounter: replaceCounter);
        var diagnostics = await compilation.WithAnalyzers([new ExplicitExpectationAnalyzer()]).GetAnalyzerDiagnosticsAsync();

        await Assert.That(diagnostics.Length).IsEqualTo(expectedCount);
        await Assert.That(diagnostics.All(d => d.Id == "PL0014")).IsTrue();
    }

    [Test]
    [Arguments("#pragma warning disable PL0014")]
    [Arguments("#pragma warning disable")]
    [Arguments("[System.Diagnostics.CodeAnalysis.SuppressMessage(\"Testing\", \"PL0014: expectation\")]")]
    [Arguments("[System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage(\"Testing\", \"PL0014\")]")]
    public async Task Local_suppression_cannot_make_a_computed_expectation_compile(string suppression)
    {
        var compilation = Compile("n * 8", suppression);
        GeneratorDriver driver = CSharpGeneratorDriver.Create(new ExpectationSuppressionGuard());

        driver.RunGeneratorsAndUpdateCompilation(compilation, out var output, out var generatorDiagnostics);

        await Assert.That(generatorDiagnostics.IsEmpty).IsTrue();
        await Assert.That(output.GetDiagnostics().Single(d => d.Severity == DiagnosticSeverity.Error).Id).IsEqualTo("CS1029");
    }

    private static CSharpCompilation Compile(string expression, string suppression = "", string? actual = null,
        bool replaceCounter = false)
    {
        var source = $$"""
            using TUnit.Assertions;
            using TUnit.Assertions.Extensions;
            public record Result(int Length, bool Flag)
            {
                public int Calculated => Length * 8;
                public int Compute() => Length / 2;
            }
            public class Counter { public int Value { get; set; } public int Double => Value * 2; }
            public class Box { public (int, bool)[] Items { get; init; } }
            public class Cases
            {
                static int Identity(int value) => value;
                {{suppression}}
                [TUnit.Core.Test, TUnit.Core.Arguments(2, false, "fixture")]
                public async System.Threading.Tasks.Task Example(int n, bool flag, string name)
                {
                    var result = new Result(n, flag);
                    var calculated = n * 8;
                    var alias = calculated;
                    int incremented = n;
                    incremented++;
                    int rewritten = n;
                    if (flag) rewritten = 3;
                    int copied = n * 8;
                    copied = n;
                    object actual = new object();
                    var counter = new Counter();
                    var other = new Counter();
                    var baseline = counter.Value;
                    var derived = counter.Double;
                    {{(replaceCounter ? "counter = other;" : "")}}
                    await Assert.That({{actual ?? "actual"}}).IsEqualTo({{(actual is null ? $"(object)({expression})" : expression)}});
                }
            }
            """;
        var compilation = CSharpCompilation.Create("Examples", [CSharpSyntaxTree.ParseText(source)], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error).ToArray();
        if (errors.Length != 0) throw new InvalidOperationException(string.Join("\n", errors.AsEnumerable()));
        return compilation;
    }
}
