using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers.UnitTests;

public sealed class AnalyzeOptionalParametersTests
{
    [Test]
    [Arguments("class Reader { void Read(bool buffered = false) { } }", "= false")]
    [Arguments("class Reader { public Reader(string? path = null) { } }", "= null")]
    [Arguments("record Options(int Limit = 4);", "= 4")]
    [Arguments("delegate void Read(int limit = default);", "= default")]
    [Arguments("class Reader { int Read() { var limit = (int n = 4) => n; return limit(); } }", "= 4")]
    public async Task Declared_default_values_are_reported_as_warnings(string source, string expectedLocation)
    {
        var diagnostics = await Analyze(source, "Reader.cs");

        var warning = diagnostics.Single();
        await Assert.That(warning.Id).IsEqualTo("PL0015");
        await Assert.That(warning.Severity).IsEqualTo(DiagnosticSeverity.Warning);
        await Assert.That(warning.Location.SourceTree!.GetText().ToString(warning.Location.SourceSpan)).IsEqualTo(expectedLocation);
    }

    [Test]
    public async Task An_interop_optional_parameter_is_reported_at_its_name()
    {
        const string source = """
            using System.Runtime.InteropServices;
            class Reader
            {
                static int Read([Optional, DefaultParameterValue(4)] int limit) => limit;
            }
            """;

        var diagnostics = await Analyze(source, "Reader.cs");

        var warning = diagnostics.Single();
        await Assert.That(warning.Id).IsEqualTo("PL0015");
        await Assert.That(warning.Location.SourceTree!.GetText().ToString(warning.Location.SourceSpan)).IsEqualTo("limit");
    }

    [Test]
    public async Task Required_parameters_and_explicit_default_arguments_pass()
    {
        const string source = """
            using System.Runtime.InteropServices;
            class Reader
            {
                static void Read([In] int limit, params int[] positions) { }
                static void Run() => Read(limit: default);
            }
            """;

        var diagnostics = await Analyze(source, "Reader.cs");

        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    public async Task Generated_optional_parameters_pass()
    {
        var diagnostics = await Analyze("class Reader { void Read(int limit = 4) { } }", "Reader.g.cs");

        await Assert.That(diagnostics).IsEmpty();
    }

    private static readonly ImmutableArray<MetadataReference> References =
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
        .Where(path => Path.GetFileName(path) is "System.Private.CoreLib.dll" or "System.Runtime.dll" or "System.Runtime.InteropServices.dll")
        .Select(path => MetadataReference.CreateFromFile(path)).ToImmutableArray<MetadataReference>();

    private static async Task<ImmutableArray<Diagnostic>> Analyze(string source, string path)
    {
        var tree = CSharpSyntaxTree.ParseText(source, path: path);
        var compilation = CSharpCompilation.Create("OptionalParameterCase", [tree], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable));
        var errors = compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        await Assert.That(errors).IsEmpty();

        return await compilation.WithAnalyzers([new OptionalParameterAnalyzer()]).GetAnalyzerDiagnosticsAsync();
    }
}
