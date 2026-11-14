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

        var constructs = new List<string>();
        var models = new Dictionary<SyntaxTree, SemanticModel> { [method.SyntaxTree] = context.SemanticModel };
        foreach (var invocation in method.DescendantNodes(EnterExecutableCode).OfType<InvocationExpressionSyntax>())
        {
            var enclosing = invocation.Ancestors().TakeWhile(node => node != method)
                .Select(ControlFlowName).OfType<string>().Except(constructs).ToArray();
            if (enclosing.Length == 0) continue;
            if (context.SemanticModel.GetSymbolInfo(invocation, context.CancellationToken).Symbol is IMethodSymbol called &&
                ReachesAssertion(called, assertType, context, models))
                constructs.AddRange(enclosing);
        }
        if (constructs.Count != 0)
            context.ReportDiagnostic(Diagnostic.Create(Rule, method.Identifier.GetLocation(),
                symbol.Name, string.Join(", ", constructs)));
    }

    private static bool ReachesAssertion(IMethodSymbol called, INamedTypeSymbol assertType,
        SyntaxNodeAnalysisContext context, Dictionary<SyntaxTree, SemanticModel> models)
    {
        var pending = new Stack<IMethodSymbol>();
        var visited = new HashSet<IMethodSymbol>(SymbolEqualityComparer.Default);
        pending.Push(called);
        while (pending.Count > 0)
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            var method = pending.Pop();
            method = (method.ReducedFrom ?? method).OriginalDefinition;
            method = method.PartialImplementationPart ?? method;
            if (!visited.Add(method)) continue;
            if (SymbolEqualityComparer.Default.Equals(method.ContainingType, assertType))
            {
                if (method.Name != "Multiple") return true;
                continue;
            }
            foreach (var reference in method.DeclaringSyntaxReferences)
            {
                var declaration = reference.GetSyntax(context.CancellationToken);
                SyntaxNode? body = declaration switch
                {
                    MethodDeclarationSyntax m => (SyntaxNode?)m.Body ?? m.ExpressionBody,
                    LocalFunctionStatementSyntax f => (SyntaxNode?)f.Body ?? f.ExpressionBody,
                    _ => null
                };
                if (body is null || !context.Compilation.ContainsSyntaxTree(body.SyntaxTree)) continue;
                if (!models.TryGetValue(body.SyntaxTree, out var model))
                {
#pragma warning disable RS1030 // A called helper can be in another file. Reuse its model for this test.
                    models[body.SyntaxTree] = model = context.Compilation.GetSemanticModel(body.SyntaxTree);
#pragma warning restore RS1030
                }
                foreach (var invocation in body.DescendantNodes(EnterExecutableCode).OfType<InvocationExpressionSyntax>())
                    if (model.GetSymbolInfo(invocation, context.CancellationToken).Symbol is IMethodSymbol target)
                        pending.Push(target);
            }
        }
        return false;
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
