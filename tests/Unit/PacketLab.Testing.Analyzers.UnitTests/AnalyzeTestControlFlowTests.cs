using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Testing.Analyzers.UnitTests;

public class AnalyzeTestControlFlowTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
        .Select(p => MetadataReference.CreateFromFile(p)).ToImmutableArray<MetadataReference>();

    [Test]
    [Arguments("for (var i = 0; i < 2; i++) Assert.That(i);", "for")]
    [Arguments("foreach (var i in new[] { 1, 2 }) Assert.That(i);", "foreach")]
    [Arguments("foreach (var (a, b) in new[] { (1, 2) }) Assert.That(a);", "foreach")]
    [Arguments("while (flag) { Assert.That(flag); break; }", "while")]
    [Arguments("do { Assert.That(flag); } while (flag);", "do/while")]
    [Arguments("if (flag) Assert.That(flag);", "if")]
    [Arguments("if (flag) { } else Assert.That(flag);", "if")]
    [Arguments("switch (flag) { case true: Assert.That(flag); break; }", "switch")]
    [Arguments("var result = flag switch { true => Assert.That(1), false => Assert.That(2) };", "switch expression")]
    public async Task Assertions_inside_control_flow_report_a_warning_at_the_test_name(string body, string construct)
    {
        var source = TestSource(body);
        var diagnostic = (await Analyze(source)).Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0003");
        await Assert.That(diagnostic.Severity).IsEqualTo(DiagnosticSeverity.Warning);
        await Assert.That(source.Substring(diagnostic.Location.SourceSpan.Start, diagnostic.Location.SourceSpan.Length)).IsEqualTo("Case");
        await Assert.That(diagnostic.GetMessage()).Contains($"assertions inside {construct}");
        await Assert.That(diagnostic.GetMessage()).Contains("single behavior named by this test");
        await Assert.That(diagnostic.GetMessage()).Contains("suppress PL0003 locally and document why");
    }

    [Test]
    public async Task Nested_and_repeated_constructs_report_once_per_test()
    {
        var diagnostic = (await Analyze(TestSource("""
            for (var i = 0; i < 2; i++)
            {
                if (flag) Assert.That(i);
                if (!flag) Assert.That(i + 1);
            }
            foreach (var item in new[] { 3 }) Assert.That(item);
            """))).Single();
        await Assert.That(diagnostic.GetMessage()).Contains("inside if, for, foreach");
    }

    [Test]
    [Arguments("var expected = 0; for (var i = 0; i < 2; i++) expected += i; Assert.That(expected);")]
    [Arguments("var expected = 0; if (flag) expected = 1; else expected = 2; Assert.That(expected);")]
    [Arguments("var expected = 0; switch (flag) { case true: expected = 1; break; } Assert.That(expected);")]
    [Arguments("var expected = flag switch { true => 1, false => 2 }; Assert.That(expected);")]
    [Arguments("while (flag) { if (flag) break; } Assert.That(flag);")]
    [Arguments("Assert.That(flag); Assert.That(!flag);")]
    [Arguments("for (var i = 0; i < 2; i++) { using var scope = Assert.Multiple(); }")]
    public async Task Control_flow_without_assertions_does_not_report(string body)
    {
        await Assert.That((await Analyze(TestSource(body))).Length).IsEqualTo(0);
    }

    [Test]
    [Arguments("System.Action action = () => { if (flag) Assert.That(flag); }; action();")]
    [Arguments("System.Action action = delegate { while (flag) { Assert.That(flag); break; } }; action();")]
    [Arguments("void Check() { if (flag) Assert.That(flag); } Check();")]
    public async Task Nested_function_bodies_are_not_treated_as_the_test_body(string body)
    {
        await Assert.That((await Analyze(TestSource(body))).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Loop_calling_a_local_assertion_function_reports()
    {
        var diagnostic = (await Analyze(TestSource("""
            void Check(bool value) => Assert.That(value);
            foreach (var value in new[] { flag }) Check(value);
            """))).Single();
        await Assert.That(diagnostic.GetMessage()).Contains("inside foreach");
    }

    [Test]
    public async Task Branch_calling_a_chain_of_helpers_reports()
    {
        var diagnostic = (await Analyze(TestSource("if (flag) Checks.Check(flag);"), helperSource: """
            using TUnit.Assertions;
            static class Checks
            {
                public static void Check<T>(T value) => Verify(value);
                static void Verify<T>(T value) { Assert.That(value); }
            }
            """)).Single();
        await Assert.That(diagnostic.GetMessage()).Contains("Test 'Case' contains assertions inside if");
    }

    [Test]
    public async Task Recursive_calls_without_a_reachable_assertion_do_not_report()
    {
        var diagnostics = await Analyze(TestSource("""
            void First() => Second();
            void Second()
            {
                void Unused() => Assert.Fail("unused");
                System.Action deferred = () => Assert.Fail("deferred");
                First();
            }
            if (flag) First();
            """));
        await Assert.That(diagnostics.Length).IsEqualTo(0);
    }

    [Test]
    public async Task Helpers_are_not_analyzed_as_test_methods()
    {
        var source = """
            using TUnit.Assertions;
            public class Cases
            {
                [TUnit.Core.Test] public void Case() => Check();
                private void Check() { if (true) Assert.That(true); }
            }
            """;
        await Assert.That((await Analyze(source)).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Unrelated_test_attributes_do_not_mark_methods_as_tests()
    {
        var source = """
            using TUnit.Assertions;
            public class TestAttribute : System.Attribute { }
            public class Cases { [Test] public void Case() { if (true) Assert.That(true); } }
            """;
        await Assert.That((await Analyze(source)).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Unrelated_assertion_names_do_not_trigger_the_rule()
    {
        var source = """
            public static class Assert { public static void That(bool value) { } }
            public class Cases { [TUnit.Core.Test] public void Case() { if (true) Assert.That(true); } }
            """;
        await Assert.That((await Analyze(source)).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Aliases_and_static_imports_still_identify_framework_symbols()
    {
        var source = """
            using Test = TUnit.Core.TestAttribute;
            using static TUnit.Assertions.Assert;
            public class Cases { [Test] public void Case() { if (true) That(true); } }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0003");
    }

    [Test]
    [Arguments("Assert.Fail(\"unexpected\");")]
    [Arguments("Assert.Throws<System.Exception>(() => throw new System.Exception());")]
    public async Task Explicit_failure_and_exception_assertions_are_recognized(string assertion)
    {
        await Assert.That((await Analyze(TestSource($"if (flag) {{ {assertion} }}"))).Single().Id).IsEqualTo("PL0003");
    }

    [Test]
    public async Task A_documented_local_suppression_only_affects_its_test()
    {
        var source = """
            using TUnit.Assertions;
            public class Cases
            {
            #pragma warning disable PL0003 // Each prefix checks the same truncation contract.
                [TUnit.Core.Test] public void Prefixes() { for (var i = 0; i < 20; i++) Assert.That(i); }
            #pragma warning restore PL0003
                [TUnit.Core.Test] public void Other() { if (true) Assert.That(true); }
            }
            """;
        var diagnostic = (await Analyze(source)).Single();
        await Assert.That(diagnostic.GetMessage()).Contains("Test 'Other'");
    }

    [Test]
    public async Task Explicit_warning_configuration_keeps_the_rule_nonblocking_under_warnings_as_errors()
    {
        var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
            generalDiagnosticOption: ReportDiagnostic.Error,
            specificDiagnosticOptions: new Dictionary<string, ReportDiagnostic> { ["PL0003"] = ReportDiagnostic.Warn });
        var diagnostic = (await Analyze(TestSource("if (flag) Assert.That(flag);"), options)).Single();
        await Assert.That(diagnostic.Severity).IsEqualTo(DiagnosticSeverity.Warning);
        await Assert.That(diagnostic.IsWarningAsError).IsFalse();
    }

    [Test]
    public async Task Generated_tests_are_skipped()
    {
        await Assert.That((await Analyze("// <auto-generated/>\n" + TestSource("if (flag) Assert.That(flag);"))).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Incomplete_test_code_does_not_crash_analysis()
    {
        var diagnostics = await Analyze("using TUnit.Assertions; public class Cases { [TUnit.Core.Test] public void Case() { if (", allowErrors: true);
        await Assert.That(diagnostics.Any(d => d.Id == "AD0001")).IsFalse();
    }

    private static string TestSource(string body) => $$"""
        using TUnit.Assertions;
        public class Cases { [TUnit.Core.Test] public void Case(bool flag) { {{body}} } }
        """;

    private static async Task<ImmutableArray<Diagnostic>> Analyze(string source,
        CSharpCompilationOptions? options = null, bool allowErrors = false, string? helperSource = null)
    {
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), path: "Case.cs");
        SyntaxTree[] trees = helperSource is null ? [tree] :
            [tree, CSharpSyntaxTree.ParseText(helperSource, (CSharpParseOptions)tree.Options, path: "Checks.cs")];
        var compilation = CSharpCompilation.Create("TestCase", trees, References,
            options ?? new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        if (!allowErrors)
            await Assert.That(string.Join("\n", compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error))).IsEqualTo("");
        var diagnostics = await compilation.WithAnalyzers([new TestControlFlowAnalyzer()]).GetAnalyzerDiagnosticsAsync();
        await Assert.That(string.Join("\n", diagnostics.Where(d => d.Id == "AD0001"))).IsEqualTo("");
        return diagnostics;
    }
}
