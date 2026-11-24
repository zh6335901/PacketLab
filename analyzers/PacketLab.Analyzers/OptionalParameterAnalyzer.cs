using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class OptionalParameterAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor Rule = new(
        "PL0015", "Avoid optional parameters",
        "Make parameter '{0}' required so callers pass an explicit value",
        "Design", DiagnosticSeverity.Warning, isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [Rule];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeParameter, SyntaxKind.Parameter);
    }

    private static void AnalyzeParameter(SyntaxNodeAnalysisContext context)
    {
        var parameter = (ParameterSyntax)context.Node;
        var defaultValue = parameter.Default;
        if (defaultValue is null && parameter.AttributeLists.Count == 0)
            return;

        if (defaultValue is null && context.SemanticModel.GetDeclaredSymbol(parameter, context.CancellationToken) is not { IsOptional: true })
            return;

        var location = defaultValue?.GetLocation() ?? parameter.Identifier.GetLocation();
        context.ReportDiagnostic(Diagnostic.Create(Rule, location, parameter.Identifier.ValueText));
    }
}
