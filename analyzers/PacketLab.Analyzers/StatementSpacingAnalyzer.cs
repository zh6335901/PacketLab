using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Text;

namespace PacketLab.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class StatementSpacingAnalyzer : DiagnosticAnalyzer
{
    private static readonly DiagnosticDescriptor BeforeReturn = new(
        "PL0010", "Separate a return from the preceding statement",
        "Leave a blank line before this return",
        "Readability", DiagnosticSeverity.Warning, isEnabledByDefault: true);

    private static readonly DiagnosticDescriptor AfterGuards = new(
        "PL0011", "Separate guard clauses from the following statements",
        "Leave a blank line after the last guard clause",
        "Readability", DiagnosticSeverity.Warning, isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [BeforeReturn, AfterGuards];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeStatements, SyntaxKind.Block, SyntaxKind.SwitchSection, SyntaxKind.CompilationUnit);
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
        StatementSyntax? previous = null;
        var previousWasGuard = false;
        foreach (var statement in statements)
        {
            var isGuard = IsGuard(statement);
            if (previous is not null)
            {
                if (statement is ReturnStatementSyntax)
                    CheckSpacing(context, previous, statement, BeforeReturn);
                else if (previousWasGuard && !isGuard)
                    CheckSpacing(context, previous, statement, AfterGuards);
            }

            previous = statement;
            previousWasGuard = isGuard;
        }
    }

    private static bool IsGuard(StatementSyntax statement)
    {
        if (statement is not IfStatementSyntax { Else: null } guard)
            return false;

        var last = guard.Statement is BlockSyntax block ? block.Statements.LastOrDefault() : guard.Statement;

        return last is ReturnStatementSyntax or ThrowStatementSyntax or ContinueStatementSyntax or BreakStatementSyntax;
    }

    private static void CheckSpacing(SyntaxNodeAnalysisContext context, StatementSyntax previous, StatementSyntax next,
        DiagnosticDescriptor rule)
    {
        var tree = context.Node.SyntaxTree;
        var lines = tree.GetText(context.CancellationToken).Lines;
        var previousLine = lines.GetLineFromPosition(previous.Span.End).LineNumber;
        var nextLine = lines.GetLineFromPosition(next.SpanStart).LineNumber;
        for (var i = previousLine + 1; i < nextLine; i++)
        {
            var line = lines[i];
            if (IsBlankLine(line, tree, context.CancellationToken))
                return;
        }

        context.ReportDiagnostic(Diagnostic.Create(rule, next.GetFirstToken().GetLocation()));
    }

    private static bool IsBlankLine(TextLine line, SyntaxTree tree, CancellationToken cancellationToken)
    {
        if (line.Span.Length > 0 && !string.IsNullOrWhiteSpace(line.ToString()))
            return false;

        // A visually empty line inside a block comment or disabled code belongs to that trivia.
        return tree.GetRoot(cancellationToken).FindTrivia(line.End).IsKind(SyntaxKind.EndOfLineTrivia);
    }
}
