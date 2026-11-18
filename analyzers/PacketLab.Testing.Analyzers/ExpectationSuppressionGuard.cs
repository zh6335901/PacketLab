using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;

namespace PacketLab.Testing.Analyzers;

// A configurable warning participates in TreatWarningsAsErrors. Reject attempts to hide it in source.
[Generator(LanguageNames.CSharp)]
public sealed class ExpectationSuppressionGuard : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var attributes = context.SyntaxProvider.CreateSyntaxProvider(
            static (node, _) => node is AttributeSyntax,
            static (syntax, token) => IsSuppression(syntax, token) ? syntax.Node.GetLocation() : null)
            .Where(static location => location is not null);

        var pragmas = context.SyntaxProvider.CreateSyntaxProvider(
            static (node, _) => node is CompilationUnitSyntax { ContainsDirectives: true },
            static (syntax, token) => FindDirectives(syntax, token))
            .SelectMany(static (locations, _) => locations);

        context.RegisterSourceOutput(attributes.Collect().Combine(pragmas.Collect()), static (output, groups) =>
        {
            var locations = groups.Left.Concat(groups.Right).OfType<Location>();
            var errors = locations.Select(location =>
            {
                var line = location.GetLineSpan();
                var path = line.Path.Replace("\r", " ").Replace("\n", " ");
                return $"#error Remove the PL0014 suppression at {path}:{line.StartLinePosition.Line + 1}";
            });
            var source = string.Join("\n", errors);
            if (source.Length != 0) output.AddSource("ExpectationSuppressions.g.cs", source);
        });
    }

    private static IEnumerable<Location> FindDirectives(GeneratorSyntaxContext syntax, CancellationToken token)
    {
        var root = (CompilationUnitSyntax)syntax.Node;
        foreach (var directive in root.DescendantTrivia().Where(trivia => trivia.IsDirective).Select(trivia => trivia.GetStructure()).OfType<PragmaWarningDirectiveTriviaSyntax>())
        {
            token.ThrowIfCancellationRequested();
            if (!directive.IsActive || !directive.DisableOrRestoreKeyword.IsKind(SyntaxKind.DisableKeyword))
                continue;
            if (NamesRule(directive))
                yield return directive.GetLocation();
            else if (directive.ErrorCodes.Count == 0 && CoversCheckedAssertion(directive, root, syntax.SemanticModel, token))
                yield return directive.GetLocation();
        }
    }

    private static bool CoversCheckedAssertion(PragmaWarningDirectiveTriviaSyntax disable, CompilationUnitSyntax root,
        SemanticModel model, CancellationToken token)
    {
        var end = disable.GetNextDirective(d => d.IsActive && d is PragmaWarningDirectiveTriviaSyntax next &&
            (next.ErrorCodes.Count == 0 || NamesRule(next)))?.SpanStart ?? root.FullSpan.End;
        foreach (var method in root.DescendantNodes().OfType<MethodDeclarationSyntax>())
        {
            if (method.Span.End <= disable.Span.End || method.SpanStart >= end ||
                model.GetDeclaredSymbol(method, token)?.GetAttributes().Any(a =>
                    a.AttributeClass?.ToDisplayString() == "TUnit.Core.ArgumentsAttribute") != true)
                continue;
            foreach (var call in method.DescendantNodes().OfType<InvocationExpressionSyntax>())
            {
                if (model.GetOperation(call, token) is Microsoft.CodeAnalysis.Operations.IInvocationOperation invocation &&
                    ExplicitExpectationAnalyzer.Calculation(invocation, token) is { } evidence &&
                    evidence.Syntax.SpanStart >= disable.Span.End && evidence.Syntax.SpanStart < end)
                    return true;
            }
        }
        return false;
    }

    private static bool NamesRule(PragmaWarningDirectiveTriviaSyntax directive) =>
        directive.ErrorCodes.Any(code => code.ToString() == ExplicitExpectationAnalyzer.RuleId);

    private static bool IsSuppression(GeneratorSyntaxContext context, CancellationToken token)
    {
        if (context.SemanticModel.GetOperation(context.Node, token) is not Microsoft.CodeAnalysis.Operations.IAttributeOperation
            { Operation: Microsoft.CodeAnalysis.Operations.IObjectCreationOperation ctor })
            return false;
        if (ctor.Type?.ToDisplayString() is not ("System.Diagnostics.CodeAnalysis.SuppressMessageAttribute" or
            "System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessageAttribute"))
            return false;
        var argument = ctor.Arguments.FirstOrDefault(a => a.Parameter?.Name == "checkId");
        return argument?.Value.ConstantValue is { HasValue: true, Value: string id } &&
            id.Split(':')[0].Trim() == ExplicitExpectationAnalyzer.RuleId;
    }
}
