using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ReadabilityAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor NestedConditional = new(
        "PL0004", "Nested conditional expression",
        "Split the nested conditional into separate decisions or use a switch expression",
        "Readability", DiagnosticSeverity.Warning, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor PackedArguments = new(
        "PL0005", "Computed arguments share a line",
        "Put the computed arguments on separate lines or give their values descriptive names",
        "Readability", DiagnosticSeverity.Warning, isEnabledByDefault: true,
        description: "In a call with four or more arguments, multiple computed arguments starting on the same line can obscure the role of each value.");

    private static readonly DiagnosticDescriptor InlineBody = new(
        "PL0009", "Single-statement body shares the control header's line",
        "Start the body statement on a new line",
        "Readability", DiagnosticSeverity.Warning, isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [NestedConditional, PackedArguments, InlineBody];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeConditional, SyntaxKind.ConditionalExpression);
        context.RegisterSyntaxNodeAction(AnalyzeArguments, SyntaxKind.ArgumentList);
        context.RegisterSyntaxNodeAction(AnalyzeBody,
            SyntaxKind.IfStatement, SyntaxKind.ElseClause, SyntaxKind.ForStatement, SyntaxKind.ForEachStatement,
            SyntaxKind.ForEachVariableStatement, SyntaxKind.WhileStatement, SyntaxKind.DoStatement);
    }

    private static void AnalyzeBody(SyntaxNodeAnalysisContext context)
    {
        if (context.Node is ElseClauseSyntax { Statement: IfStatementSyntax })
            return;

        var (headerEnd, body) = context.Node switch
        {
            IfStatementSyntax branch => (branch.CloseParenToken, branch.Statement),
            ElseClauseSyntax branch => (branch.ElseKeyword, branch.Statement),
            ForStatementSyntax loop => (loop.CloseParenToken, loop.Statement),
            CommonForEachStatementSyntax loop => (loop.CloseParenToken, loop.Statement),
            WhileStatementSyntax loop => (loop.CloseParenToken, loop.Statement),
            DoStatementSyntax loop => (loop.DoKeyword, loop.Statement),
            _ => throw new InvalidOperationException()
        };

        if (body is BlockSyntax block)
        {
            if (block.Statements.Count != 1)
                return;
            body = block.Statements[0];
        }

        var firstToken = body.GetFirstToken();
        if (headerEnd.IsMissing || firstToken.RawKind == 0)
            return;

        var lines = body.SyntaxTree.GetText(context.CancellationToken).Lines;
        var headerLine = lines.GetLineFromPosition(headerEnd.SpanStart).LineNumber;
        var bodyLine = lines.GetLineFromPosition(firstToken.SpanStart).LineNumber;
        if (headerLine == bodyLine)
            context.ReportDiagnostic(Diagnostic.Create(InlineBody, firstToken.GetLocation()));
    }

    private static void AnalyzeConditional(SyntaxNodeAnalysisContext context)
    {
        var conditional = (ConditionalExpressionSyntax)context.Node;
        if (!IsConditional(conditional.Condition) && !IsConditional(conditional.WhenTrue) && !IsConditional(conditional.WhenFalse))
            return;

        // Report once on the outermost decision in a chain.
        var parent = conditional.Parent;
        while (parent is ParenthesizedExpressionSyntax)
            parent = parent.Parent;
        if (parent is ConditionalExpressionSyntax)
            return;

        context.ReportDiagnostic(Diagnostic.Create(NestedConditional, conditional.QuestionToken.GetLocation()));
    }

    private static bool IsConditional(ExpressionSyntax expression)
    {
        while (expression is ParenthesizedExpressionSyntax parentheses)
            expression = parentheses.Expression;
        return expression is ConditionalExpressionSyntax;
    }

    private static void AnalyzeArguments(SyntaxNodeAnalysisContext context)
    {
        var list = (ArgumentListSyntax)context.Node;
        if (list.Arguments.Count < 4)
            return;

        var lines = list.SyntaxTree.GetText(context.CancellationToken).Lines;
        var previousComputedLine = -1;
        foreach (var argument in list.Arguments)
        {
            if (!IsComputed(argument.Expression))
                continue;

            var line = lines.GetLineFromPosition(argument.SpanStart).LineNumber;
            if (line == previousComputedLine)
            {
                context.ReportDiagnostic(Diagnostic.Create(PackedArguments, argument.GetLocation()));
                return;
            }
            previousComputedLine = line;
        }
    }

    private static bool IsComputed(ExpressionSyntax expression) => expression switch
    {
        ParenthesizedExpressionSyntax parentheses => IsComputed(parentheses.Expression),
        CastExpressionSyntax cast => IsComputed(cast.Expression),
        InvocationExpressionSyntax or BaseObjectCreationExpressionSyntax or BinaryExpressionSyntax
            or ConditionalExpressionSyntax or SwitchExpressionSyntax => true,
        _ => false
    };
}
