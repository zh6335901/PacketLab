using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class CallComplexityAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor NestedCalls = new(
        "PL0007", "Deeply nested method calls",
        "Split the nested calls into steps with descriptive names",
        "Readability", DiagnosticSeverity.Warning, isEnabledByDefault: true,
        description: "Three or more calls nested directly inside one another's arguments can hide the order of evaluation.");

    private static readonly DiagnosticDescriptor ComplexArgument = new(
        "PL0008", "Complex argument expression",
        "Give this argument's calculation a descriptive name",
        "Readability", DiagnosticSeverity.Warning, isEnabledByDefault: true,
        description: "Extract multi-stage queries, chains of two or more calls, or expressions with three or more binary operations in an argument or its expression-bodied lambda.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [NestedCalls, ComplexArgument];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeInvocation, SyntaxKind.InvocationExpression);
        context.RegisterSyntaxNodeAction(AnalyzeArgument, SyntaxKind.Argument);
    }

    private static void AnalyzeInvocation(SyntaxNodeAnalysisContext context)
    {
        var call = (InvocationExpressionSyntax)context.Node;
        var parent = call.Parent;
        while (parent is ParenthesizedExpressionSyntax or CastExpressionSyntax)
            parent = parent.Parent;
        if (parent is ArgumentSyntax { Parent.Parent: InvocationExpressionSyntax })
            return;

        if (HasNestedCalls(call, remainingDepth: 3))
            context.ReportDiagnostic(Diagnostic.Create(NestedCalls, call.ArgumentList.OpenParenToken.GetLocation()));
    }

    private static bool HasNestedCalls(InvocationExpressionSyntax call, int remainingDepth)
    {
        if (remainingDepth == 1)
            return true;

        foreach (var argument in call.ArgumentList.Arguments)
        {
            if (Unwrap(argument.Expression) is InvocationExpressionSyntax nested && HasNestedCalls(nested, remainingDepth - 1))
                return true;
        }
        return false;
    }

    private static void AnalyzeArgument(SyntaxNodeAnalysisContext context)
    {
        var argument = (ArgumentSyntax)context.Node;
        var expression = Unwrap(argument.Expression);
        if (expression is LambdaExpressionSyntax { Body: ExpressionSyntax body })
            expression = Unwrap(body);
        if (IsComplexArgument(expression))
            context.ReportDiagnostic(Diagnostic.Create(ComplexArgument, expression.GetLocation()));
    }

    private static bool IsComplexArgument(ExpressionSyntax expression)
    {
        if (expression is BinaryExpressionSyntax)
        {
            var operations = expression.DescendantNodesAndSelf(node =>
                node is BinaryExpressionSyntax or ParenthesizedExpressionSyntax or CastExpressionSyntax);
            return operations.OfType<BinaryExpressionSyntax>().Skip(2).Any();
        }

        if (expression is InvocationExpressionSyntax { Expression: MemberAccessExpressionSyntax member })
        {
            expression = Unwrap(member.Expression);
            if (expression is InvocationExpressionSyntax)
                return true;
        }
        return expression is QueryExpressionSyntax query && (query.Body.Clauses.Count > 0 || query.Body.Continuation is not null);
    }

    private static ExpressionSyntax Unwrap(ExpressionSyntax expression)
    {
        while (true)
        {
            switch (expression)
            {
                case ParenthesizedExpressionSyntax parentheses:
                    expression = parentheses.Expression;
                    break;
                case CastExpressionSyntax cast:
                    expression = cast.Expression;
                    break;
                default:
                    return expression;
            }
        }
    }
}
