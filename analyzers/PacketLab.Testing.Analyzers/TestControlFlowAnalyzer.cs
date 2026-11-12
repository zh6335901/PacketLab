using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Testing.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class TestControlFlowAnalyzer : DiagnosticAnalyzer
{
    public const string RuleId = "PL0003";

    private static readonly DiagnosticDescriptor Rule = new(
        RuleId, "Review assertions inside test control flow",
        "Test '{0}' contains assertions inside {1}. Consider separate tests for independent behaviors or parameterization for input variations. If this control flow is necessary to verify the single behavior named by this test, suppress PL0003 locally and document why.",
        "Testing", DiagnosticSeverity.Warning, isEnabledByDefault: true,
        description: "Assertions inside loops or if/switch constructs warrant review. They may be appropriate for one behavior; explicitly suppress the warning locally with a reason in that case.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [Rule];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeMethod, SyntaxKind.MethodDeclaration);
    }

    private static void AnalyzeMethod(SyntaxNodeAnalysisContext context)
    {
        var method = (MethodDeclarationSyntax)context.Node;
        var symbol = context.SemanticModel.GetDeclaredSymbol(method, context.CancellationToken);
        var testAttribute = context.Compilation.GetTypeByMetadataName("TUnit.Core.TestAttribute");
        var assertType = context.Compilation.GetTypeByMetadataName("TUnit.Assertions.Assert");
        if (testAttribute is null || assertType is null || symbol is null ||
            !symbol.GetAttributes().Any(a => SymbolEqualityComparer.Default.Equals(a.AttributeClass, testAttribute)))
            return;

        var constructs = method.DescendantNodes(EnterExecutableCode)
            .OfType<InvocationExpressionSyntax>()
            .Where(invocation => context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol
                is IMethodSymbol called && called.Name != "Multiple" &&
                SymbolEqualityComparer.Default.Equals(called.ContainingType, assertType))
            .SelectMany(invocation => invocation.Ancestors().TakeWhile(node => node != method))
            .Select(ControlFlowName).Where(name => name is not null).Distinct().ToArray();
        if (constructs.Length != 0)
            context.ReportDiagnostic(Diagnostic.Create(Rule, method.Identifier.GetLocation(),
                symbol.Name, string.Join(", ", constructs)));
    }

    private static bool EnterExecutableCode(SyntaxNode node) =>
        node is not (AnonymousFunctionExpressionSyntax or LocalFunctionStatementSyntax);

    private static string? ControlFlowName(SyntaxNode node) => node switch
    {
        ForStatementSyntax => "for",
        CommonForEachStatementSyntax => "foreach",
        WhileStatementSyntax => "while",
        DoStatementSyntax => "do/while",
        IfStatementSyntax => "if",
        SwitchStatementSyntax => "switch",
        SwitchExpressionSyntax => "switch expression",
        _ => null
    };
}
