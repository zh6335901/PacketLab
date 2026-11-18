using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers.UnitTests;

public class AnalyzeImplementationCapabilitiesTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
        .Where(path => Path.GetFileName(path) is "System.Private.CoreLib.dll" or "System.Runtime.dll" or "System.Collections.dll" or "netstandard.dll" or "System.Linq.dll")
        .Select(path => MetadataReference.CreateFromFile(path)).ToImmutableArray<MetadataReference>();

    private const string Types = """
        using System;
        using System.Collections;
        using System.Collections.Generic;
        using System.Linq;
        public enum State { Unavailable, Available }
        public class Reader { public virtual string[] Common => []; }
        public interface ISections { string[] Sections { get; } }
        public class Special : Reader, ISections
        {
            public string[] Sections => [];
            public string Label => "label";
            public State Status => State.Available;
            public string this[int index] => "value";
            public override string[] Common => [];
            public void Reset() { }
            public IEnumerator Read() => Sections.GetEnumerator();
        }
        public class Other : Reader { public string[] Entries => []; }
        """;

    [Test]
    [Arguments("public string[] Sections => reader is Special s ? s.Sections : [];")]
    [Arguments("public string[] Sections => reader is Special s ? s.Sections : Array.Empty<string>();")]
    [Arguments("public string[] Sections => reader is Special ? ((Special)reader).Sections : new string[] {};")]
    [Arguments("public string[] Sections { get { if (reader is Special s) return s.Sections; return []; } }")]
    [Arguments("public string[] Sections { get { if (reader is not Special s) return []; return s.Sections; } }")]
    [Arguments("public string[] Sections { get { if (reader is Special s) { return s.Sections; } else { throw new NotSupportedException(); } } }")]
    [Arguments("public string[] Sections => reader switch { Special s => s.Sections, _ => [] };")]
    [Arguments("public string[] Sections { get { switch(reader) { case Special s: return s.Sections; default: return []; } } }")]
    [Arguments("public string[] Sections => (reader as Special)?.Sections ?? [];")]
    [Arguments("public string[] Sections { get { var s = reader as Special; return s?.Sections ?? []; } }")]
    [Arguments("public string[] Sections { get { var s = reader as Special; if (reader != null) return s?.Sections ?? []; s = new Special(); return s.Sections; } }")]
    [Arguments("public string[] Sections => reader is Special {} s ? s.Sections : throw new InvalidOperationException();")]
    public async Task Conditional_implementation_capabilities_report_evidence(string declaration)
    {
        // Arrange
        var source = Wrap(declaration);

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0013");
        await Assert.That(diagnostic.GetMessage()).Contains("'Sections'");
        await Assert.That(diagnostic.GetMessage()).Contains("'reader'");
        await Assert.That(diagnostic.GetMessage()).Contains("'Special'");
        await Assert.That(diagnostic.AdditionalLocations.Count).IsEqualTo(2);
        await Assert.That(diagnostic.Location.SourceTree!.GetText().ToString(diagnostic.Location.SourceSpan)).IsEqualTo("Sections");
    }

    [Test]
    [Arguments("public string[] Sections => reader is ISections s ? s.Sections : [];")]
    [Arguments("public IEnumerable<string> Read() => reader is Special s ? s.Sections : Enumerable.Empty<string>();")]
    [Arguments("public string? Label => reader is Special s ? s.Label : null;")]
    [Arguments("public string this[int index] => reader is Special s ? s[index] : string.Empty;")]
    [Arguments("public int Count() => reader is Special s ? s.Sections.Length : 0;")]
    [Arguments("public void Reset() { if (reader is Special s) s.Reset(); else throw new NotSupportedException(); }")]
    public async Task Implementation_specific_members_with_placeholder_fallbacks_report_an_error(string declaration)
    {
        // Arrange
        var source = Wrap(declaration);

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0013");
        await Assert.That(diagnostic.Severity).IsEqualTo(DiagnosticSeverity.Error);
    }

    [Test]
    [Arguments("public string[] Sections = reader is Special s ? s.Sections : [];")]
    [Arguments("public string[] Sections { get; } = reader is Special s ? s.Sections : [];")]
    public async Task Public_initializers_exposing_implementation_specific_data_report_an_error(string declaration)
    {
        // Arrange
        var source = Wrap(declaration);

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0013");
    }

    [Test]
    [Arguments("public readonly string[] Sections;")]
    [Arguments("public string[] Sections { get; }")]
    public async Task Constructor_assignments_exposing_implementation_specific_data_report_an_error(string declaration)
    {
        // Arrange
        var source = Types + $$"""
            public class Wrapper
            {
                {{declaration}}
                public Wrapper(Reader reader) { Sections = reader is Special s ? s.Sections : []; }
            }
            """;

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0013");
    }

    [Test]
    [Arguments("public string[] Sections => reader is Special s ? s.Sections : new[] { \"available\" };")]
    [Arguments("public string[] Sections => reader is Special s ? s.Sections : ((Other)reader).Entries;")]
    [Arguments("public State Status => reader is Special s ? s.Status : State.Unavailable;")]
    [Arguments("public string[] Sections => reader switch { Special s => s.Sections, Other o => o.Entries, null => throw new InvalidOperationException(), _ => new[] { \"available\" } };")]
    [Arguments("public string[] Sections { get { switch (reader) { case Special s: return s.Sections; case Other o: return o.Entries; case null: throw new InvalidOperationException(); default: return new[] { \"available\" }; } } }")]
    [Arguments("public string[] Common => reader is Special s ? s.Common : [];")]
    [Arguments("public string[] Sections => reader is Special s ? new string[1] : [];")]
    [Arguments("public string[] Sections { get { if (reader is Special s) GC.KeepAlive(s.Sections); return []; } }")]
    [Arguments("public bool TryGetSections(out string[] sections) { if (reader is Special s) { sections = s.Sections; return true; } sections = []; return false; }")]
    [Arguments("private string[] Sections => reader is Special s ? s.Sections : [];")]
    [Arguments("public string[] Convert(Reader input) => input is Special s ? s.Sections : [];")]
    [Arguments("public string[] Sections => reader is Special s ? ((Special)other).Sections : []; private Reader other = new Reader();")]
    public async Task Normal_dispatch_queries_and_unrelated_conditions_are_not_reported(string declaration)
    {
        // Arrange
        var source = Wrap(declaration);

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    [Arguments("reader is Special s ? s.Sections : []")]
    [Arguments("reader switch { Special s => s.Sections, _ => [] }")]
    public async Task Only_a_count_derived_from_implementation_specific_sections_reports_a_diagnostic(string expression)
    {
        // Arrange
        var source = $$"""
            using System;
            public interface IReader { }
            public class Special(string[] sections) : IReader
            {
                public string[] Sections => sections;
            }
            public class Wrapper(IReader reader)
            {
                public int InternalOnly()
                {
                    string[] sections = {{expression}};
                    GC.KeepAlive(sections);
                    return 1;
                }

                public int ExposedCount()
                {
                    string[] sections = {{expression}};
                    GC.KeepAlive(sections);
                    return sections.Length;
                }
            }
            """;

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        var reported = diagnostics.Select(d => (d.Id, d.Location.SourceTree!.GetText().ToString(d.Location.SourceSpan)));
        await Assert.That(reported.ToArray()).IsEquivalentTo([("PL0013", "ExposedCount")]);
    }

    [Test]
    [Arguments("s = new Special(); return s?.Sections ?? [];")]
    [Arguments("if (reader is Other) s = new Special(); return s?.Sections ?? [];")]
    [Arguments("ref Special? alias = ref s; alias = new Special(); return s?.Sections ?? [];")]
    [Arguments("""
        Replace(ref s);
        return s?.Sections ?? [];
        static void Replace(ref Special? value) => value = new Special();
        """)]
    [Arguments("""
        ReplaceCaptured();
        return s?.Sections ?? [];
        void ReplaceCaptured() => s = new Special();
        """)]
    public async Task A_local_that_may_have_been_replaced_does_not_establish_a_capability(string statements)
    {
        // Arrange
        var source = Wrap($$"""
            public string[] Sections
            {
                get
                {
                    var s = reader as Special;
                    {{statements}}
                }
            }
            """);

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    public async Task Only_the_generic_overload_outside_the_interface_contract_is_reported()
    {
        // Arrange
        const string source = """
            public interface IReader<TItem> { TItem[] Read<T>(); }
            public class Special<TItem> : IReader<TItem>
            {
                public TItem[] Read<T>() => [];
                public TItem[] Read<T>(int count) => [];
            }
            public class Wrapper(IReader<string> reader)
            {
                public string[] Common => reader is Special<string> s ? s.Read<int>() : [];
                public string[] Extra => reader is Special<string> s ? s.Read<int>(1) : [];
            }
            """;

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0013");
        await Assert.That(diagnostic.GetMessage()).Contains("'Extra'");
    }

    [Test]
    public async Task A_generic_reader_reports_only_capabilities_requiring_an_additional_interface()
    {
        // Arrange
        const string source = """
            public interface IReader<out T> { T[] Read(); }
            public class Wrapper(IReader<string> reader)
            {
                public int[] Numbers => reader is IReader<int> numbers ? numbers.Read() : [];
                public object[] Objects => reader is IReader<object> objects ? objects.Read() : [];
            }
            """;

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0013");
        await Assert.That(diagnostic.Location.SourceTree!.GetText().ToString(diagnostic.Location.SourceSpan)).IsEqualTo("Numbers");
    }

    [Test]
    public async Task Members_already_available_on_the_internal_interface_are_not_specific_capabilities()
    {
        // Arrange
        const string source = """
            public interface IReader { string[] Sections { get; } }
            public class Special : IReader { public string[] Sections => []; }
            public class Wrapper(IReader reader)
            {
                public string[] Sections => reader is Special s ? s.Sections : [];
            }
            """;

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    public async Task Positional_record_members_still_expose_implementation_capabilities()
    {
        // Arrange
        const string source = Types + "public record Wrapper(Reader Reader) { public string[] Sections => Reader is Special s ? s.Sections : []; }";

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0013");
    }

    [Test]
    public async Task A_fixed_value_type_is_not_an_alternative_internal_implementation()
    {
        // Arrange
        const string source = """
            public interface ISections { string[] Sections { get; } }
            public struct Data : ISections { public string[] Sections => []; }
            public class View(Data data) { public string[] Sections => data is ISections s ? s.Sections : []; }
            """;

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    public async Task Source_defined_interfaces_do_not_hide_the_same_contract_problem()
    {
        // Arrange
        const string source = Types + """
            public interface IWrapper { string[] Sections { get; } }
            public class Wrapper(Reader reader) : IWrapper
            {
                string[] IWrapper.Sections => reader is Special s ? s.Sections : [];
            }
            """;

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0013");
    }

    [Test]
    public async Task An_override_exposing_an_implementation_specific_capability_reports_an_error()
    {
        // Arrange
        const string source = Types + """
            public abstract class View { public abstract string[] Sections { get; } }
            public class Wrapper(Reader reader) : View
            {
                public override string[] Sections => reader is Special s ? s.Sections : [];
            }
            """;

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics.Single().Id).IsEqualTo("PL0013");
    }

    [Test]
    public async Task Metadata_contract_implementations_do_not_require_redesigning_external_interfaces()
    {
        // Arrange
        const string source = Types + """
            public class Wrapper(Reader reader) : IEnumerable
            {
                public IEnumerator GetEnumerator() => reader is Special s ? s.Read() : throw new NotSupportedException();
                public override string ToString() => reader is Special s ? s.Label : "";
            }
            """;

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        await Assert.That(diagnostics).IsEmpty();
    }

    [Test]
    public async Task A_warning_pragma_cannot_suppress_the_capability_error()
    {
        // Arrange
        var source = Wrap("""
            #pragma warning disable PL0013
            public string[] Sections => reader is Special s ? s.Sections : [];
            """);

        // Act
        var diagnostics = await Analyze(source);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0013");
        await Assert.That(diagnostic.Severity).IsEqualTo(DiagnosticSeverity.Error);
    }

    [Test]
    [Arguments("[assembly: System.Diagnostics.CodeAnalysis.SuppressMessage(\"Design\", \"PL0013\")] public class Subject {}")]
    [Arguments("[System.Diagnostics.CodeAnalysis.SuppressMessage(\"Design\", \"PL0013\")] public class Subject {}")]
    [Arguments("[System.Diagnostics.CodeAnalysis.SuppressMessage(category: \"Design\", \"PL0013\")] public class Subject {}")]
    [Arguments("public class Subject { [System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessage(\"Design\", \"PL0013\")] public int Value => 0; }")]
    [Arguments("using Hide = System.Diagnostics.CodeAnalysis.SuppressMessageAttribute; [Hide(checkId: Subject.Id, category: \"Design\")] public class Subject { public const string Id = \"PL0013: title\"; }")]
    public async Task Suppression_attributes_produce_a_compiler_error(string source)
    {
        // Arrange
        var parseOptions = new CSharpParseOptions(LanguageVersion.Preview);
        var tree = CSharpSyntaxTree.ParseText("#pragma warning disable CS1029\n" + source, parseOptions, path: "Case.cs");
        var compilation = CSharpCompilation.Create("SuppressionCase", [tree], References,
            new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary));
        GeneratorDriver driver = CSharpGeneratorDriver.Create([new ImplementationCapabilitySuppressionGuard().AsSourceGenerator()], parseOptions: parseOptions);

        // Act
        driver.RunGeneratorsAndUpdateCompilation(compilation, out var output, out var generatorErrors);

        // Assert
        await Assert.That(generatorErrors).IsEmpty();
        var error = output.GetDiagnostics().Single(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        await Assert.That(error.Id).IsEqualTo("CS1029");
        await Assert.That(error.GetMessage()).Contains("PL0013");
        await Assert.That(error.GetMessage()).Contains("Case.cs:2");
    }

    [Test]
    public async Task Diagnostic_configuration_cannot_disable_the_rule()
    {
        // Arrange
        var source = Wrap("public string[] Sections => reader is Special s ? s.Sections : [];");

        // Act
        var diagnostics = await Analyze(source, suppress: true);

        // Assert
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0013");
        await Assert.That(diagnostic.Severity).IsEqualTo(DiagnosticSeverity.Error);
    }

    private static string Wrap(string member) => Types + "\npublic class Wrapper(Reader reader) {\n" + member + "\n}";

    private static async Task<ImmutableArray<Diagnostic>> Analyze(string source, bool suppress = false)
    {
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), path: "Case.cs");
        var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary, nullableContextOptions: NullableContextOptions.Enable);
        if (suppress)
            options = options.WithSpecificDiagnosticOptions(new Dictionary<string, ReportDiagnostic> { ["PL0013"] = ReportDiagnostic.Suppress });
        var compilation = CSharpCompilation.Create("CapabilityCase", [tree], References, options);
        var errors = compilation.GetDiagnostics().Where(diagnostic => diagnostic.Severity == DiagnosticSeverity.Error);
        await Assert.That(errors).IsEmpty();
        var diagnostics = await compilation.WithAnalyzers([new ImplementationCapabilityAnalyzer()]).GetAnalyzerDiagnosticsAsync();
        await Assert.That(string.Join("\n", diagnostics.Where(diagnostic => diagnostic.Id == "AD0001"))).IsEqualTo("");

        return diagnostics;
    }
}
