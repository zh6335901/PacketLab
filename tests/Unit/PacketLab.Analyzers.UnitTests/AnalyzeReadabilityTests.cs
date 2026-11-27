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
        // Act
        var diagnostics = await Analyze(expression);

        // Assert
        var diagnostic = diagnostics.Single();
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
        // Act
        var diagnostics = await Analyze(expression);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    [Arguments("Header(Read(0), 1, Read(2), Read(4))", "Read(2)")]
    [Arguments("Header(0,\n (byte)(1 << 2), (int)(3 + 4), 5)", "(int)(3 + 4)")]
    [Arguments("new Sample(Read(0), Read(2), Read(4), Read(6)).Value", "Read(2)")]
    public async Task Packed_computations_point_to_the_second_argument_on_the_line(string expression, string expected)
    {
        // Act
        var diagnostics = await Analyze(expression);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0005");
        var span = diagnostic.Location.SourceSpan;
        await Assert.That(diagnostic.Location.SourceTree!.GetText().ToString(span)).IsEqualTo(expected);
    }

    [Test]
    public async Task Generated_code_skips_readability_warnings()
    {
        // Act
        var diagnostics = await Analyze("Header(Read(0), Read(2), Read(Read(Read(Read(0)))), a ? 1 : b ? 2 : 3)",
            statements: "x = y = 0; x = Total(values.Where(v => v > 0).Select(v => v + 1));", path: "Case.g.cs");

        // Assert
        await Assert.That(diagnostics).IsEmpty();
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
        // Act
        var diagnostics = await Analyze("0", statements);

        // Assert
        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0006");
    }

    [Test]
    [Arguments("x = 1;\ny = 2;\nz = 3;")]
    [Arguments("(x, y) = (y, x);")]
    public async Task Separate_assignments_and_deconstruction_pass(string statements)
    {
        // Act
        var diagnostics = await Analyze("0", statements);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    [Arguments("if (x > 0) return;")]
    [Arguments("if (x > 0) { return; }")]
    [Arguments("if (\n x > 0) /* guard */ return;")]
    [Arguments("if (x > 0)\n return; else return;")]
    [Arguments("if (x > 0)\n return; else if (y > 0) return;")]
    [Arguments("for (int i = 0; i < x; i++) break;")]
    [Arguments("foreach (var n in values) break;")]
    [Arguments("foreach (var (a, b) in new[] { (x, y) }) break;")]
    [Arguments("while (x > 0) break;")]
    [Arguments("do x++; while (x < 0);")]
    public async Task Single_statement_on_the_header_line_reports_a_warning(string statements)
    {
        // Act
        var diagnostics = await Analyze("0", statements);

        // Assert
        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0009");
    }

    [Test]
    [Arguments("if (x > 0)\n return;")]
    [Arguments("if (x > 0) {\n return; }")]
    [Arguments("if (x > 0) { } else if (y > 0)\n return; else\n return;")]
    [Arguments("for (;;)\n break;")]
    [Arguments("foreach (var n in values)\n break;")]
    [Arguments("while (x > 0)\n break;")]
    [Arguments("do\n x++; while (x < 0);")]
    public async Task Body_on_a_separate_line_passes(string statements)
    {
        // Act
        var diagnostics = await Analyze("0", statements);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    [Arguments("x++;\nreturn;")]
    [Arguments("x++; // finished\nreturn;")]
    [Arguments("x++;\n/* a\n\ncomment */\nreturn;")]
    [Arguments("if (x > 0)\n return;\nreturn;")]
    [Arguments("if (x > 0) { x++;\nreturn; }")]
    [Arguments("switch (x) { case 0: if (y > 0) { x++;\nreturn; }\n\nbreak; }")]
    public async Task Return_after_a_statement_requires_one_separator(string statements)
    {
        // Act
        var diagnostics = await Analyze("0", statements);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0010");
    }

    [Test]
    [Arguments("if (x > 0)\n return;\nx++;")]
    [Arguments("if (x > 0)\n throw new System.Exception();\nx++;")]
    [Arguments("if (x > 0) { x++;\n\n return; }\nx++;")]
    [Arguments("for (; x > 0; x--) { if (y > 0)\n continue;\ny--; }")]
    [Arguments("while (x > 0) { if (y > 0)\n continue;\nif (z > 0)\n break;\nx--; }")]
    public async Task Last_guard_requires_a_separator_before_normal_flow(string statements)
    {
        // Act
        var diagnostics = await Analyze("0", statements);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0011");
    }

    [Test]
    [Arguments("return;")]
    [Arguments("if (x > 0)\n return;")]
    [Arguments("while (x > 0) {\n return; }")]
    [Arguments("switch (x) { case 0: return;\n\ndefault: x++; break; }")]
    [Arguments("while (x > 0) { x--;\ncontinue; }")]
    [Arguments("x++;\r\n  \r\n// result\r\nreturn;")]
    [Arguments("if (x > 0)\n return;\nif (y > 0)\n throw new System.Exception();\n\nx++;")]
    [Arguments("while (x > 0) { if (y > 0)\n continue;\nif (z > 0)\n break;\n\nx--; }")]
    [Arguments("if (x > 0)\n return; else\n x++;\nx--;")]
    public async Task Spacing_respects_statement_groups_and_embedded_exits(string statements)
    {
        // Act
        var diagnostics = await Analyze("0", statements);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    [Arguments("switch (x) { case 0: x++;\nreturn; }")]
    [Arguments("switch (x) { case 0: { x++;\nreturn; } }")]
    [Arguments("switch (x) { case 0: case 1: x++;\nreturn; }")]
    [Arguments("switch (x) { case 0: x++; break;\n\n// next section\ndefault: return; }")]
    [Arguments("switch (x) { case 0: x++; break;\r\n \t\r\ndefault: return; }")]
    public async Task Switch_sections_keep_terminal_returns_with_their_work(string statements)
    {
        // Act
        var diagnostics = await Analyze("0", statements);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    [Arguments("switch (x) { case 0: x++; return; default: return; }")]
    [Arguments("switch (x) { case 0: break;\ndefault: return; }")]
    [Arguments("switch (x) { case 0: { x++; return; }\ndefault: return; }")]
    [Arguments("switch (x) { case 0: break;\n/* next\n\nsection */\ndefault: return; }")]
    public async Task Adjacent_switch_sections_require_a_blank_line(string statements)
    {
        // Act
        var diagnostics = await Analyze("0", statements);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0012");
        await Assert.That(diagnostic.Location.SourceTree!.GetText().ToString(diagnostic.Location.SourceSpan))
            .IsEqualTo("default");
    }

    [Test]
    public async Task Guard_spacing_still_applies_before_a_section_return()
    {
        // Act
        var diagnostics = await Analyze("0", "switch (x) { case 0: if (y > 0)\nreturn;\nreturn; }");

        // Assert
        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0011");
    }

    [Test]
    [Arguments("Read(Read(Read(0)))")]
    [Arguments("Read(Read(Read(Read(0))))")]
    [Arguments("Read(Read((int)(Read(Read(Read(0))))))")]
    public async Task Three_or_more_directly_nested_calls_report_once(string expression)
    {
        // Act
        var diagnostics = await Analyze(expression);

        // Assert
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
        // Act
        var diagnostics = await Analyze(expression);

        // Assert
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
        // Act
        var diagnostics = await Analyze(expression);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    [Arguments("Configure(b => b.Append(1).Append(2));")]
    [Arguments("Configure(b => { b.Append(1).Append(2); });")]
    [Arguments("ConfigureCustom(b => b.Append(1).Append(2));")]
    [Arguments("Configure((System.Action<System.Text.StringBuilder>)(b => b.Append(1).Append(2)));")]
    public async Task Fluent_statements_in_void_callbacks_pass(string statement)
    {
        var diagnostics = await Analyze("0", statement);

        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    [Arguments("Transform(b => b.Append(1).Append(2));", "b.Append(1).Append(2)")]
    [Arguments("System.GC.KeepAlive(new System.Text.StringBuilder().Append(1).Append(2));",
        "new System.Text.StringBuilder().Append(1).Append(2)")]
    [Arguments("Configure(b => b.Append(1).AppendJoin(',', values.Distinct().Reverse()));",
        "values.Distinct().Reverse()")]
    [Arguments("Configure(b => b.Append(1).Append(1 + 2 * (3 + 4)));", "1 + 2 * (3 + 4)")]
    public async Task Consumed_values_still_report_at_the_complex_expression(string statement, string expected)
    {
        var diagnostics = await Analyze("0", statement);

        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0008");
        await Assert.That(diagnostic.Location.SourceTree!.GetText().ToString(diagnostic.Location.SourceSpan))
            .IsEqualTo(expected);
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
            using System.Text;
            class Sample
            {
                public int Value;
                public Sample(int a, int b, int c, int d) { Value = a; }
                static int Read(int offset) => offset;
                static int Header(int a, int b, int c, int d = 0) => a;
                static int Total(IEnumerable<int> items) => items.Sum();
                delegate void ConfigureCallback(StringBuilder builder);
                static void Configure(System.Action<StringBuilder> configure) { }
                static void ConfigureCustom(ConfigureCallback configure) { }
                static StringBuilder Transform(System.Func<StringBuilder, StringBuilder> transform) => transform(new());
                static int Parse(bool a, bool b, bool c, int[] values) => {{expression}};
                static void Update(int x, int y, int z, int[] values) { {{statements}} }
            }
            """;
        var tree = CSharpSyntaxTree.ParseText(source, path: path);
        var compilation = CSharpCompilation.Create("ReadabilityCase", [tree], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error);
        await Assert.That(errors).IsEmpty();
        ImmutableArray<DiagnosticAnalyzer> analyzers = [
            new ReadabilityAnalyzer(),
            new AssignmentLayoutAnalyzer(),
            new CallComplexityAnalyzer(),
            new StatementSpacingAnalyzer()
        ];

        return await compilation.WithAnalyzers(analyzers).GetAnalyzerDiagnosticsAsync();
    }
}
