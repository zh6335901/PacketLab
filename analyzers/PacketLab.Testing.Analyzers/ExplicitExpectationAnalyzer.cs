using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;
using Microsoft.CodeAnalysis.Operations;

namespace PacketLab.Testing.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ExplicitExpectationAnalyzer : DiagnosticAnalyzer
{
    public const string RuleId = "PL0014";

    private static readonly DiagnosticDescriptor Rule = new(RuleId, "Supply explicit expected values",
        "The expected value is derived by '{0}'. Supply the expected value in the test case data.",
        "Testing", DiagnosticSeverity.Warning, isEnabledByDefault: true);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [Rule];

    public override void Initialize(AnalysisContext context)
    {
        context.EnableConcurrentExecution();
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.RegisterOperationBlockStartAction(block =>
        {
            if (block.OwningSymbol is not IMethodSymbol method ||
                !method.GetAttributes().Any(a => a.AttributeClass?.ToDisplayString() == "TUnit.Core.ArgumentsAttribute"))
                return;

            block.RegisterOperationAction(AnalyzeAssertion, OperationKind.Invocation);
        });
    }

    private static void AnalyzeAssertion(OperationAnalysisContext context)
    {
        var evidence = Calculation((IInvocationOperation)context.Operation, context.CancellationToken);
        if (evidence is not null)
            context.ReportDiagnostic(Diagnostic.Create(Rule, evidence.Syntax.GetLocation(), evidence.Syntax.ToString()));
    }

    internal static IOperation? Calculation(IInvocationOperation call, CancellationToken token)
    {
        if (call.TargetMethod.Name is not ("IsEqualTo" or "IsEquivalentTo") ||
            call.TargetMethod.ContainingAssembly.Name != "TUnit.Assertions")
            return null;

        var argument = call.Arguments.FirstOrDefault(a => a.Parameter?.Name == "expected");
        if (argument is null)
            return null;

        var evidence = new ExpectationTrace(token).FindCalculation(argument.Value);
        if (evidence is IPropertyReferenceOperation prior && IsStoredObservation(call, argument.Value, prior, token))
            return null;
        return evidence;
    }

    private static bool IsStoredObservation(IInvocationOperation call, IOperation expected, IPropertyReferenceOperation prior,
        CancellationToken token)
    {
        if (expected is not ILocalReferenceOperation snapshot || prior.Instance is not ILocalReferenceOperation original ||
            prior.Property.IsVirtual || prior.Property.IsOverride || prior.Property.IsAbstract ||
            prior.Property.GetMethod?.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(token) is not
                AccessorDeclarationSyntax { Body: null, ExpressionBody: null } ||
            snapshot.Local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(token) is not VariableDeclaratorSyntax declaration ||
            declaration.Initializer?.Value.Span != prior.Syntax.Span)
            return false;

        var source = call.Instance ?? call.Arguments.FirstOrDefault()?.Value;
        while (source is IConversionOperation conversion) source = conversion.Operand;
        if (source is not IInvocationOperation { TargetMethod.Name: "That" } assertion ||
            assertion.TargetMethod.ContainingType.ToDisplayString() != "TUnit.Assertions.Assert" ||
            assertion.Arguments.FirstOrDefault()?.Value is not IPropertyReferenceOperation
                { Instance: ILocalReferenceOperation current } property)
            return false;

        if (!SymbolEqualityComparer.Default.Equals(property.Property, prior.Property) ||
            !SymbolEqualityComparer.Default.Equals(current.Local, original.Local) ||
            declaration.FirstAncestorOrSelf<LocalDeclarationStatementSyntax>() is not { } capture ||
            call.Syntax.FirstAncestorOrSelf<ExpressionStatementSyntax>() is not { } check ||
            capture.Parent != check.Parent || call.SemanticModel is not { } model)
            return false;

        var flow = model.AnalyzeDataFlow(capture, check);
        return flow is { Succeeded: true } && !flow.WrittenInside.Contains(original.Local, SymbolEqualityComparer.Default);
    }

    private sealed class ExpectationTrace(CancellationToken token)
    {
        private bool tracingPath;
        private readonly HashSet<ISymbol> visited = new(SymbolEqualityComparer.Default);
        private readonly Dictionary<ISymbol, IOperation> arguments = new(SymbolEqualityComparer.Default);

        internal IOperation? FindCalculation(IOperation operation)
        {
            token.ThrowIfCancellationRequested();
            if (operation.ConstantValue.HasValue)
                return null;

            switch (operation)
            {
                case IBinaryOperation { OperatorKind: BinaryOperatorKind.Add, Type.SpecialType: SpecialType.System_String } join when tracingPath:
                    return FindCalculation(join.LeftOperand) ?? FindCalculation(join.RightOperand);
                case IInvocationOperation join when tracingPath && join.TargetMethod.Name == "Combine" &&
                    join.TargetMethod.ContainingType.ToDisplayString() == "System.IO.Path":
                    return join.Arguments.Select(a => FindCalculation(a.Value)).FirstOrDefault(evidence => evidence is not null);
                case IPropertyReferenceOperation directory when tracingPath && directory.Property.Name == "BaseDirectory" &&
                    directory.Property.ContainingType.ToDisplayString() == "System.AppContext":
                    return null;
                case IParameterReferenceOperation parameter:
                    return TraceParameter(parameter);
                case IDefaultValueOperation or ITypeOfOperation:
                    return null;
                case ILocalReferenceOperation local:
                    return TraceLocal(local);
                case IArgumentOperation arg:
                    return FindCalculation(arg.Value);
                case IParenthesizedOperation parens:
                    return FindCalculation(parens.Operand);
                case IConversionOperation conversion when conversion.OperatorMethod is null:
                    return FindCalculation(conversion.Operand);
                case ISimpleAssignmentOperation assignment:
                    // In an object initializer the property is a destination, not a getter.
                    return FindCalculation(assignment.Value);
                case IObjectCreationOperation or IObjectOrCollectionInitializerOperation or ITupleOperation
                    or IArrayInitializerOperation or ICollectionExpressionOperation:
                case IInvocationOperation { IsImplicit: true, TargetMethod.Name: "Add" }:
                    foreach (var value in operation.ChildOperations)
                    {
                        if (value is IInstanceReferenceOperation) continue;
                        if (FindCalculation(value) is { } computed) return computed;
                    }
                    return null;
                case IArrayCreationOperation { Initializer: { } items }:
                    return FindCalculation(items);
                case IInvocationOperation call:
                    if (call.TargetMethod is { Name: "ReadAllText", IsStatic: true } read &&
                        read.ContainingType.ToDisplayString() == "System.IO.File" && call.Arguments.Length == 1)
                        return TraceFixturePath(call.Arguments[0].Value);
                    if (call.TargetMethod.Name == "ReplaceLineEndings" &&
                        call.TargetMethod.ContainingType.SpecialType == SpecialType.System_String &&
                        call.Instance is { } text && call.Arguments.All(a => a.Value.ConstantValue.HasValue))
                        return FindCalculation(text);
                    return TraceReturn(call);
                default:
                    return operation;
            }
        }

        private IOperation? TraceFixturePath(IOperation path)
        {
            bool wasTracingPath = tracingPath;
            tracingPath = true;
            try { return FindCalculation(path); }
            finally { tracingPath = wasTracingPath; }
        }

        private IOperation? TraceReturn(IInvocationOperation call)
        {
            var method = call.TargetMethod.OriginalDefinition;
            var declaration = method.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(token);
            var expression = declaration switch
            {
                MethodDeclarationSyntax m => ReturnedExpression(m.ExpressionBody, m.Body),
                LocalFunctionStatementSyntax f => ReturnedExpression(f.ExpressionBody, f.Body),
                _ => null
            };
            if (expression is null || call.IsVirtual || call.SemanticModel is not { } caller ||
                !caller.Compilation.ContainsSyntaxTree(expression.SyntaxTree) || !visited.Add(method))
                return call;

            try
            {
                foreach (var arg in call.Arguments)
                    if (arg.Parameter is { } parameter)
                        arguments[method.Parameters[parameter.Ordinal]] = arg.Value;
#pragma warning disable RS1030 // A source helper can be declared in another test file.
                var model = expression.SyntaxTree == caller.SyntaxTree ? caller : caller.Compilation.GetSemanticModel(expression.SyntaxTree);
#pragma warning restore RS1030
                if (model.GetOperation(expression, token) is not { } result) return call;
                var calculated = FindCalculation(result);
                // Keep the diagnostic at the test call site, including when a helper is shared.
                return calculated is null ? null : call;
            }
            finally
            {
                foreach (var parameter in method.Parameters) arguments.Remove(parameter);
                visited.Remove(method);
            }
        }

        private static ExpressionSyntax? ReturnedExpression(ArrowExpressionClauseSyntax? arrow, BlockSyntax? block) =>
            arrow?.Expression ?? (block?.Statements.Count == 1 && block.Statements[0] is ReturnStatementSyntax statement ? statement.Expression : null);

        private static bool IsMutation(IdentifierNameSyntax name) => name.Parent is ArgumentSyntax argument &&
            (argument.RefKindKeyword.IsKind(SyntaxKind.RefKeyword) || argument.RefKindKeyword.IsKind(SyntaxKind.OutKeyword)) ||
            name.Parent?.Kind() is SyntaxKind.PreIncrementExpression or SyntaxKind.PreDecrementExpression or
                SyntaxKind.PostIncrementExpression or SyntaxKind.PostDecrementExpression;

        private IOperation? TraceParameter(IParameterReferenceOperation reference)
        {
            if (arguments.TryGetValue(reference.Parameter, out var supplied))
                return FindCalculation(supplied);
            var body = reference.Syntax.FirstAncestorOrSelf<MethodDeclarationSyntax>()?.Body;
            if (body is null || reference.SemanticModel is not { } model) return null;
            return TraceWrites(reference.Parameter, body, body.SpanStart, reference, null, model);
        }

        private IOperation? TraceLocal(ILocalReferenceOperation reference)
        {
            if (!visited.Add(reference.Local))
                return reference;
            try
            {
                var model = reference.SemanticModel;
                var declaration = reference.Local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(token);
                if (model is null || declaration is not VariableDeclaratorSyntax variable)
                    return reference;
                var scope = variable.FirstAncestorOrSelf<BlockSyntax>();
                if (scope is null) return reference;

                IOperation? value = variable.Initializer is null ? null : model.GetOperation(variable.Initializer.Value, token);
                return TraceWrites(reference.Local, scope, variable.Span.End, reference, value, model);
            }
            finally { visited.Remove(reference.Local); }
        }

        private IOperation? TraceWrites(ISymbol symbol, BlockSyntax scope, int start, IOperation reference,
            IOperation? value, SemanticModel model)
        {
            foreach (var name in scope.DescendantNodes().OfType<IdentifierNameSyntax>())
            {
                if (name.SpanStart <= start || name.SpanStart >= reference.Syntax.SpanStart ||
                    name.Identifier.ValueText != symbol.Name ||
                    !SymbolEqualityComparer.Default.Equals(model.GetSymbolInfo(name, token).Symbol, symbol))
                    continue;

                if (name.Parent is AssignmentExpressionSyntax write && write.Left == name)
                {
                    if (write.Span.End > reference.Syntax.SpanStart) continue;
                    if (model.GetOperation(write, token) is not ISimpleAssignmentOperation assignment ||
                        write.Parent?.Parent != scope)
                        return model.GetOperation(write, token);
                    value = assignment.Value;
                }
                else if (IsMutation(name))
                    return model.GetOperation(name.Parent!, token) ?? reference;
            }
            return value is null ? (symbol is ILocalSymbol ? reference : null) : FindCalculation(value);
        }
    }
}
