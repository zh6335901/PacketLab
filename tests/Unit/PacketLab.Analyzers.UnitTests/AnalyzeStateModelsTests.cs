using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers.UnitTests;

public class AnalyzeStateModelsTests
{
    private static readonly ImmutableArray<MetadataReference> References =
        ((string)AppContext.GetData("TRUSTED_PLATFORM_ASSEMBLIES")!).Split(Path.PathSeparator)
        .Where(p => Path.GetFileName(p) is "System.Private.CoreLib.dll" or "System.Runtime.dll" or "System.Collections.dll" or "netstandard.dll")
        .Append(typeof(Annotations.TransportModelAttribute).Assembly.Location)
        .Select(p => MetadataReference.CreateFromFile(p)).ToImmutableArray<MetadataReference>();

    [Test]
    [Arguments("class")]
    [Arguments("struct")]
    [Arguments("record")]
    public async Task Transport_models_are_exempt_from_both_rules(string kind)
    {
        var source = $$"""
            [PacketLab.Analyzers.Annotations.TransportModel]
            public {{kind}} Snapshot
            {
                public string? Value { get; init; }
                public string? Error { get; init; }
                public static Snapshot Success() => new() { Value = "ok" };
                public static Snapshot Failure() => new() { Error = "error" };
            }
            """;
        await Assert.That((await Analyze(source)).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Transport_model_exemption_does_not_spread_to_nested_or_derived_types()
    {
        const string source = """
            [PacketLab.Analyzers.Annotations.TransportModel]
            public class Carrier
            {
                public class Nested { public string? Value; public string? Error; }
            }
            public class Derived : Carrier { public string? Value; public string? Error; }
            """;
        var diagnostics = await Analyze(source);
        await Assert.That(diagnostics.Length).IsEqualTo(2);
        await Assert.That(diagnostics.All(d => d.Id == "PL0001")).IsTrue();
    }

    [Test]
    public async Task Unrelated_attribute_with_the_same_short_name_does_not_exempt_a_type()
    {
        const string source = """
            public class TransportModelAttribute : System.Attribute { }
            [TransportModel]
            public record Result(string? Value, string? Error);
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0001");
    }

    [Test]
    [Arguments("public record Result(string? Value, string? Error);")]
    [Arguments("public record Result(int? Value, bool? Error);")]
    [Arguments("public record Result<T>(T? Value, string? Error);")]
    [Arguments("public record struct Result(string? Value, string? Error);")]
    [Arguments("public record Result(bool Success, string? Error);")]
    [Arguments("public enum Status { Success, Failure } public record Result(Status Status, string? Error);")]
    [Arguments("public class Result { public string? Value; public string? Error; }")]
    [Arguments("public partial class Result { public string? Value { get; init; } } public partial class Result { public string? Error { get; init; } }")]
    public async Task Optional_storage_reports_one_warning_at_the_type(string source)
    {
        var diagnostics = await Analyze(source);
        await Assert.That(diagnostics.Length).IsEqualTo(1);
        var diagnostic = diagnostics.Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0001");
        await Assert.That(diagnostic.Severity).IsEqualTo(DiagnosticSeverity.Warning);
        await Assert.That(source.Substring(diagnostic.Location.SourceSpan.Start, diagnostic.Location.SourceSpan.Length)).IsEqualTo("Result");
    }

    [Test]
    [Arguments("public record Result(string? Value);")]
    [Arguments("public record Result(string Value, string Error);")]
    [Arguments("public class Result { public string? Value => null; public string? Error => null; }")]
    [Arguments("public class Result { public string? Value { get; } public static string? Error { get; } }")]
    [Arguments("public interface Result { string? Value { get; } string? Error { get; } }")]
    [Arguments("public class Result { public string? Value { get; } public bool Success => Value is not null; }")]
    [Arguments("#nullable disable\npublic record Result(string Value, string Error);")]
    public async Task Non_state_shapes_do_not_report_diagnostics(string source)
    {
        await Assert.That((await Analyze(source)).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Positional_record_factories_report_stronger_rule_without_duplicate()
    {
        const string source = """
            public record Result(string? Value, string? Error)
            {
                public static Result Success(string value) => new(value, null);
                public static Result Failure(string error) => new(Error: error, Value: null);
            }
            """;
        var diagnostic = (await Analyze(source)).Single();
        await Assert.That(diagnostic.Id).IsEqualTo("PL0002");
        await Assert.That(diagnostic.GetMessage()).Contains("Value=present, Error=null");
        await Assert.That(diagnostic.GetMessage()).Contains("Value=null, Error=present");
    }

    [Test]
    public async Task Readonly_fields_with_transparent_public_constructor_are_unprotected()
    {
        const string source = """
            public sealed class Result
            {
                public readonly string? Value;
                public readonly string? Error;
                public Result(string? value, string? error) { Value = value; Error = error; }
                public static Result Create(bool success) => success ? new("ok", null) : new(null, "error");
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    [Arguments("init")]
    [Arguments("set")]
    public async Task Private_constructor_does_not_protect_public_mutation(string accessor)
    {
        var source = $$"""
            public sealed record Result
            {
                public string? Value { get; {{accessor}}; }
                public string? Error { get; }
                private Result(string? value, string? error) { Value = value; Error = error; }
                public static Result Success() => new("ok", null);
                public static Result Failure() => new(null, "error");
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    public async Task Object_initializer_factories_are_analyzed()
    {
        const string source = """
            public class Result
            {
                public string? Value { get; init; }
                public string? Error { get; init; }
                public static Result Success() => new() { Value = "ok" };
                public static Result Failure() => new() { Error = "error" };
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    [Arguments("bool", "true", "false")]
    [Arguments("Status", "Status.Success", "Status.Failure")]
    public async Task Discriminator_and_optional_member_can_supply_state_evidence(string type, string success, string failure)
    {
        var source = $$"""
            public enum Status { Success, Failure }
            public record Result({{type}} Status, string? Error)
            {
                public static Result Success() => new({{success}}, null);
                public static Result Failure() => new({{failure}}, "error");
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    [Arguments("bool?", "true", "false")]
    [Arguments("int?", "42", "17")]
    [Arguments("Status?", "Status.Success", "Status.Failure")]
    public async Task Optional_value_types_are_compared_by_presence(string type, string first, string second)
    {
        var source = $$"""
            public enum Status { Success, Failure }
            public record Result({{type}} Value, {{type}} Error)
            {
                public static Result Success() => new({{first}}, null);
                public static Result Failure() => new(null, {{second}});
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    public async Task Default_nullable_construction_is_not_treated_as_present()
    {
        const string source = """
            public record Result(int? Value, int? Error)
            {
                public static Result First() => new(new int?(), null);
                public static Result Second() => new(null, new int?());
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0001");
    }

    [Test]
    public async Task Fields_that_appear_together_are_also_related_states()
    {
        const string source = """
            public record Result(string? ErrorCode, string? ErrorMessage)
            {
                public static Result Success() => new(null, null);
                public static Result Failure() => new("E1", "failed");
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    public async Task Missing_optional_arguments_are_null_in_factory_evidence()
    {
        const string source = """
            public record Result(string? Value = null, string? Error = null)
            {
                public static Result Success() => new(Value: "ok");
                public static Result Failure() => new(Error: "error");
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    public async Task Property_initializers_are_applied_before_object_initializers()
    {
        const string source = """
            public class Result
            {
                public string? Value { get; init; } = "ok";
                public string? Error { get; init; }
                public static Result Success() => new();
                public static Result Failure() => new() { Value = null, Error = "error" };
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    public async Task Private_setters_do_not_claim_external_mutation()
    {
        const string source = """
            public sealed class Result
            {
                public string? Value { get; private set; }
                public string? Error { get; private set; }
                private Result() { }
                public static Result Success() => new() { Value = "ok" };
                public static Result Failure() => new() { Error = "error" };
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0001");
    }

    [Test]
    public async Task Factories_in_partial_declarations_share_evidence()
    {
        const string source = """
            public partial record Result(string? Value, string? Error)
            {
                public static Result Success() => new("ok", null);
            }
            public partial record Result
            {
                public static Result Failure() => new(null, "error");
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    public async Task Unrelated_unknown_members_do_not_hide_known_relationships()
    {
        const string source = """
            public record Result(string? Value, string? Error, string? Context)
            {
                public static Result Success(string? context) => new("ok", null, context);
                public static Result Failure(string? context) => new(null, "error", context);
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    public async Task Unsupported_constructor_effects_remain_unknown()
    {
        const string source = """
            public class Result
            {
                public string? Value { get; set; }
                public string? Error { get; set; }
                public Result(string? value, string? error) { Validate(); Value = value; Error = error; }
                private static void Validate() { }
                public static Result Success() => new("ok", null);
                public static Result Failure() => new(null, "error");
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0001");
    }

    [Test]
    public async Task Constructor_branches_provide_evidence_when_state_is_mutable()
    {
        const string source = """
            public class Result
            {
                public string? Value { get; set; }
                public string? Error { get; set; }
                public Result(bool success)
                {
                    if (success) { Value = "ok"; Error = null; }
                    else { Value = null; Error = "error"; }
                }
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0002");
    }

    [Test]
    public async Task Controlled_readonly_type_only_gets_the_structural_warning()
    {
        const string source = """
            public sealed class Result
            {
                public string? Value { get; }
                public string? Error { get; }
                private Result(string? value, string? error) { Value = value; Error = error; }
                public static Result Success() => new("ok", null);
                public static Result Failure() => new(null, "error");
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0001");
    }

    [Test]
    public async Task Guarded_constructor_is_not_assumed_to_accept_independent_combinations()
    {
        const string source = """
            public sealed class Result
            {
                public string? Value { get; }
                public string? Error { get; }
                public Result(string? value, string? error)
                {
                    if ((value is null) == (error is null)) throw new System.ArgumentException();
                    Value = value; Error = error;
                }
                public static Result Success() => new("ok", null);
                public static Result Failure() => new(null, "error");
            }
            """;
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0001");
    }

    [Test]
    [Arguments("public static Result Make(string? value, string? error) => new(value, error);")]
    [Arguments("public static Result Make() => new(Get(), null); private static string? Get() => null;")]
    [Arguments("public static Result Make() => new(null, null);")]
    [Arguments("public static Result Make() => new(\"a\", null); public static Result Other() => new(\"b\", null);")]
    [Arguments("public static Result Make(bool success) => new(success ? \"ok\" : null, success ? null : \"error\");")]
    public async Task Unknown_or_unchanged_combinations_do_not_claim_stronger_evidence(string factories)
    {
        var source = "public record Result(string? Value, string? Error) { " + factories + " }";
        await Assert.That((await Analyze(source)).Single().Id).IsEqualTo("PL0001");
    }

    [Test]
    public async Task Independent_contact_fields_can_be_locally_suppressed()
    {
        const string source = """
            #pragma warning disable PL0001 // Contact methods are independently optional.
            public record Contact(string? Email, string? Phone);
            #pragma warning restore PL0001
            """;
        await Assert.That((await Analyze(source)).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Warning_as_error_configuration_is_honored()
    {
        var diagnostic = (await Analyze("public record Result(string? Value, string? Error);", warningsAsErrors: true)).Single();
        await Assert.That(diagnostic.Severity).IsEqualTo(DiagnosticSeverity.Error);
    }

    [Test]
    public async Task Generated_sources_are_skipped()
    {
        await Assert.That((await Analyze("// <auto-generated/>\n#nullable enable\npublic record Result(string? Value, string? Error);")).Length).IsEqualTo(0);
    }

    [Test]
    public async Task Incomplete_code_does_not_crash_the_analyzer()
    {
        var diagnostics = await Analyze("public record Result(string? Value, string? Error) { public static Result Make() => new(", allowErrors: true);
        await Assert.That(diagnostics.Any(d => d.Id == "AD0001")).IsFalse();
    }

    private static async Task<ImmutableArray<Diagnostic>> Analyze(string source, bool allowErrors = false,
        bool warningsAsErrors = false)
    {
        var tree = CSharpSyntaxTree.ParseText(source, new CSharpParseOptions(LanguageVersion.Preview), path: "Case.cs");
        var options = new CSharpCompilationOptions(OutputKind.DynamicallyLinkedLibrary,
            nullableContextOptions: NullableContextOptions.Enable,
            generalDiagnosticOption: warningsAsErrors ? ReportDiagnostic.Error : ReportDiagnostic.Default);
        var compilation = CSharpCompilation.Create("AnalyzerCase", [tree], References, options);
        if (!allowErrors)
        {
            var errors = compilation.GetDiagnostics().Where(d => d.Severity == DiagnosticSeverity.Error);
            await Assert.That(string.Join("\n", errors)).IsEqualTo("");
        }
        var diagnostics = await compilation.WithAnalyzers([new StateModelAnalyzer()]).GetAnalyzerDiagnosticsAsync();
        await Assert.That(string.Join("\n", diagnostics.Where(d => d.Id == "AD0001"))).IsEqualTo("");
        return diagnostics;
    }
}
