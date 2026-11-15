using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class AssignmentLayoutAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor PackedAssignments = new(
        "PL0006", "Multiple assignments in one step",
        "Write each assignment as a separate step on its own line",
        "Readability", DiagnosticSeverity.Warning, isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [PackedAssignments];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeChain, SyntaxKind.SimpleAssignmentExpression);
        context.RegisterSyntaxNodeAction(AnalyzeStatements, SyntaxKind.Block, SyntaxKind.SwitchSection, SyntaxKind.CompilationUnit);
    }

    private static void AnalyzeChain(SyntaxNodeAnalysisContext context)
    {
        var assignment = (AssignmentExpressionSyntax)context.Node;
        var parent = assignment.Parent;
        while (parent is ParenthesizedExpressionSyntax)
            parent = parent.Parent;
        if (parent?.IsKind(SyntaxKind.SimpleAssignmentExpression) == true)
            return;

        ExpressionSyntax value = assignment.Right;
        while (value is ParenthesizedExpressionSyntax parentheses)
            value = parentheses.Expression;
        if (value.IsKind(SyntaxKind.SimpleAssignmentExpression) || parent is EqualsValueClauseSyntax { Parent: VariableDeclaratorSyntax })
            context.ReportDiagnostic(Diagnostic.Create(PackedAssignments, assignment.OperatorToken.GetLocation()));
    }

    private static void AnalyzeStatements(SyntaxNodeAnalysisContext context)
    {
        IEnumerable<StatementSyntax> statements = context.Node switch
        {
            BlockSyntax block => block.Statements,
            SwitchSectionSyntax section => section.Statements,
            CompilationUnitSyntax unit => unit.Members.OfType<GlobalStatementSyntax>().Select(global => global.Statement),
            _ => throw new InvalidOperationException()
        };

        var lines = context.Node.SyntaxTree.GetText(context.CancellationToken).Lines;
        var previousEndLine = -1;
        var lastReportedLine = -1;
        foreach (var statement in statements)
        {
            if (!IsAssignmentStatement(statement))
            {
                previousEndLine = -1;
                continue;
            }

            var startLine = lines.GetLineFromPosition(statement.SpanStart).LineNumber;
            if (startLine == previousEndLine && startLine != lastReportedLine)
            {
                context.ReportDiagnostic(Diagnostic.Create(PackedAssignments, statement.GetFirstToken().GetLocation()));
                lastReportedLine = startLine;
            }
            previousEndLine = lines.GetLineFromPosition(statement.Span.End).LineNumber;
        }
    }

    private static bool IsAssignmentStatement(StatementSyntax statement) => statement switch
    {
        ExpressionStatementSyntax { Expression: AssignmentExpressionSyntax } => true,
        LocalDeclarationStatementSyntax local => local.Declaration.Variables.Any(v => v.Initializer is not null),
        _ => false
    };
}
