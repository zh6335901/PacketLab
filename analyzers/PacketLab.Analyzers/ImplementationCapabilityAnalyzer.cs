using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class ImplementationCapabilityAnalyzer : DiagnosticAnalyzer
{
    public const string RuleId = "PL0013";

    private static readonly DiagnosticDescriptor Rule = new(
        RuleId, "Public capability depends on an internal implementation",
        "Public member '{0}' exposes '{1}' only when '{2}' is '{3}'; another implementation receives a placeholder or unsupported result. Review which type owns this capability.",
        "Design", DiagnosticSeverity.Error, isEnabledByDefault: true,
        description: "Expose implementation-specific capabilities on the types that support them, or explicitly model capability availability. Moving the condition into a helper or changing fallback syntax does not resolve the public contract. This rule cannot be suppressed or downgraded.",
        customTags: [WellKnownDiagnosticTags.NotConfigurable]);

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [Rule];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSyntaxNodeAction(AnalyzeMember, SyntaxKind.PropertyDeclaration, SyntaxKind.IndexerDeclaration,
            SyntaxKind.MethodDeclaration, SyntaxKind.VariableDeclarator);
        context.RegisterSyntaxNodeAction(AnalyzeInitialization, SyntaxKind.SimpleAssignmentExpression);
    }

    private static void AnalyzeMember(SyntaxNodeAnalysisContext context)
    {
        var symbol = context.SemanticModel.GetDeclaredSymbol(context.Node, context.CancellationToken);
        if (!OwnsPublicContract(symbol))
            return;

        SyntaxNode? body = context.Node switch
        {
            PropertyDeclarationSyntax property => (SyntaxNode?)property.ExpressionBody?.Expression ?? GetterBody(property.AccessorList) ?? property.Initializer?.Value,
            IndexerDeclarationSyntax indexer => (SyntaxNode?)indexer.ExpressionBody?.Expression ?? GetterBody(indexer.AccessorList),
            MethodDeclarationSyntax method => (SyntaxNode?)method.ExpressionBody?.Expression ?? method.Body,
            VariableDeclaratorSyntax variable when symbol is IFieldSymbol => variable.Initializer?.Value,
            _ => null
        };
        if (body is not null)
            AnalyzeBody(context, symbol!, body);
    }

    private static SyntaxNode? GetterBody(AccessorListSyntax? accessors)
    {
        var getter = accessors?.Accessors.FirstOrDefault(accessor => accessor.IsKind(SyntaxKind.GetAccessorDeclaration));

        return (SyntaxNode?)getter?.ExpressionBody?.Expression ?? getter?.Body;
    }

    private static void AnalyzeInitialization(SyntaxNodeAnalysisContext context)
    {
        var assignment = (AssignmentExpressionSyntax)context.Node;
        var constructor = assignment.Ancestors().OfType<ConstructorDeclarationSyntax>().FirstOrDefault();
        if (constructor is null || assignment.Ancestors().TakeWhile(node => node != constructor)
            .Any(node => node is AnonymousFunctionExpressionSyntax or LocalFunctionStatementSyntax))
            return;

        var symbol = context.SemanticModel.GetSymbolInfo(assignment.Left, context.CancellationToken).Symbol;
        var owner = context.SemanticModel.GetDeclaredSymbol(constructor, context.CancellationToken)?.ContainingType;
        if (symbol is not (IFieldSymbol or IPropertySymbol) || !OwnsPublicContract(symbol) ||
            !SymbolEqualityComparer.Default.Equals(symbol.ContainingType, owner))
            return;

        AnalyzeBody(context, symbol, assignment.Right);
    }

    private static bool OwnsPublicContract(ISymbol? symbol)
    {
        if (symbol is null || symbol.DeclaredAccessibility != Accessibility.Public && !ImplementsSourceContract(symbol))
            return false;
        if (symbol is IMethodSymbol method && method.Parameters.Any(parameter => parameter.RefKind == RefKind.Out) &&
            method.ReturnType.SpecialType == SpecialType.System_Boolean)
            return false;

        var original = symbol;
        while (OverriddenMember(original) is { } overridden)
            original = overridden;
        if (!original.Locations.Any(location => location.IsInSource))
            return false;

        // Metadata contracts are outside this compilation's ownership. Source contracts remain checked.
        foreach (var contract in symbol.ContainingType.AllInterfaces.Where(type => !type.Locations.Any(location => location.IsInSource)))
            foreach (var member in contract.GetMembers())
                if (SymbolEqualityComparer.Default.Equals(symbol.ContainingType.FindImplementationForInterfaceMember(member), symbol))
                    return false;

        return true;
    }

    private static bool ImplementsSourceContract(ISymbol symbol)
    {
        IEnumerable<ISymbol> contracts = symbol switch
        {
            IMethodSymbol method => method.ExplicitInterfaceImplementations,
            IPropertySymbol property => property.ExplicitInterfaceImplementations,
            _ => []
        };

        return contracts.Any(contract => contract.Locations.Any(location => location.IsInSource));
    }

    private static ISymbol? OverriddenMember(ISymbol symbol) => symbol switch
    {
        IMethodSymbol method => method.OverriddenMethod,
        IPropertySymbol property => property.OverriddenProperty,
        _ => null
    };

    private static void AnalyzeBody(SyntaxNodeAnalysisContext context, ISymbol member, SyntaxNode body)
    {
        foreach (var node in body.DescendantNodesAndSelf(EnterExecutableCode))
        {
            context.CancellationToken.ThrowIfCancellationRequested();
            Evidence? evidence = node switch
            {
                ConditionalExpressionSyntax conditional => CheckConditional(context, member, conditional),
                IfStatementSyntax conditional => CheckIf(context, member, conditional),
                SwitchExpressionSyntax expression => CheckSwitchExpression(context, member, expression),
                SwitchStatementSyntax statement => CheckSwitch(context, member, statement),
                BinaryExpressionSyntax coalesce when coalesce.IsKind(SyntaxKind.CoalesceExpression) => CheckCoalesce(context, member, coalesce),
                _ => null
            };
            if (evidence is null)
                continue;

            var location = member.Locations.First(location => location.IsInSource);
            context.ReportDiagnostic(Diagnostic.Create(Rule, location,
                additionalLocations: [evidence.Gate.Receiver.GetLocation(), evidence.Fallback.GetLocation()], properties: null,
                messageArgs: [member.Name, evidence.Capability.Name, evidence.Gate.Receiver.ToString(), evidence.Gate.Type.ToDisplayString()]));
            return;
        }
    }

    private static bool EnterExecutableCode(SyntaxNode node) => node is not (AnonymousFunctionExpressionSyntax or LocalFunctionStatementSyntax);

    private static Evidence? CheckConditional(SyntaxNodeAnalysisContext context, ISymbol member, ConditionalExpressionSyntax conditional)
    {
        var gate = GetGate(context, member, conditional.Condition);
        if (gate is null)
            return null;

        return CheckBranches(context, gate, gate.Negated ? conditional.WhenFalse : conditional.WhenTrue,
            gate.Negated ? conditional.WhenTrue : conditional.WhenFalse);
    }

    private static Evidence? CheckIf(SyntaxNodeAnalysisContext context, ISymbol member, IfStatementSyntax conditional)
    {
        var gate = GetGate(context, member, conditional.Condition);
        if (gate is null)
            return null;

        SyntaxNode? alternative = conditional.Else?.Statement;
        if (alternative is null && conditional.Parent is BlockSyntax block && AlwaysReturns(conditional.Statement))
            alternative = block.Statements.SkipWhile(statement => statement != conditional).Skip(1).FirstOrDefault();
        if (alternative is null)
            return null;

        return CheckBranches(context, gate, gate.Negated ? alternative : conditional.Statement,
            gate.Negated ? conditional.Statement : alternative);
    }

    private static bool AlwaysReturns(StatementSyntax statement) => statement switch
    {
        ReturnStatementSyntax or ThrowStatementSyntax => true,
        BlockSyntax block => block.Statements.LastOrDefault() is ReturnStatementSyntax or ThrowStatementSyntax,
        _ => false
    };

    private static Evidence? CheckSwitchExpression(SyntaxNodeAnalysisContext context, ISymbol member, SwitchExpressionSyntax expression)
    {
        foreach (var arm in expression.Arms)
        {
            var gate = GetPatternGate(context, member, expression.GoverningExpression, arm.Pattern);
            if (gate is null || gate.Negated)
                continue;

            foreach (var other in expression.Arms.Where(other => other != arm && !IsNullPattern(other.Pattern)))
                if (CheckBranches(context, gate, arm.Expression, other.Expression) is { } evidence)
                    return evidence;
        }

        return null;
    }

    private static Evidence? CheckSwitch(SyntaxNodeAnalysisContext context, ISymbol member, SwitchStatementSyntax statement)
    {
        foreach (var section in statement.Sections)
            foreach (var label in section.Labels.OfType<CasePatternSwitchLabelSyntax>())
            {
                var gate = GetPatternGate(context, member, statement.Expression, label.Pattern);
                if (gate is null || gate.Negated)
                    continue;

                foreach (var other in statement.Sections.Where(other => other != section && !other.Labels.All(IsNullLabel)))
                    if (CheckBranches(context, gate, section, other) is { } evidence)
                        return evidence;
            }

        return null;
    }

    private static bool IsNullPattern(PatternSyntax pattern) =>
        pattern is ConstantPatternSyntax { Expression: LiteralExpressionSyntax literal } && literal.IsKind(SyntaxKind.NullLiteralExpression);

    private static bool IsNullLabel(SwitchLabelSyntax label) => label switch
    {
        CaseSwitchLabelSyntax { Value: LiteralExpressionSyntax literal } => literal.IsKind(SyntaxKind.NullLiteralExpression),
        CasePatternSwitchLabelSyntax pattern => IsNullPattern(pattern.Pattern),
        _ => false
    };

    private static Evidence? CheckCoalesce(SyntaxNodeAnalysisContext context, ISymbol member, BinaryExpressionSyntax coalesce)
    {
        if (Unwrap(coalesce.Left) is not ConditionalAccessExpressionSyntax access)
            return null;

        var receiver = Unwrap(access.Expression);
        if (receiver is IdentifierNameSyntax && context.SemanticModel.GetSymbolInfo(receiver, context.CancellationToken).Symbol is ILocalSymbol local)
        {
            var declaration = local.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(context.CancellationToken) as VariableDeclaratorSyntax;
            if (declaration?.Initializer is { } initializer)
                receiver = Unwrap(initializer.Value);
        }
        if (receiver is not BinaryExpressionSyntax cast || !cast.IsKind(SyntaxKind.AsExpression))
            return null;

        var gate = CreateGate(context, member, cast.Left, cast.Right, alias: null, negated: false);
        if (gate is null || Placeholder(context, coalesce.Right) is not { } fallback)
            return null;

        foreach (var binding in access.WhenNotNull.DescendantNodesAndSelf(EnterExecutableCode).OfType<MemberBindingExpressionSyntax>())
        {
            var capability = context.SemanticModel.GetSymbolInfo(binding, context.CancellationToken).Symbol;
            if (binding.Ancestors().OfType<ConditionalAccessExpressionSyntax>().FirstOrDefault() == access && IsSpecificCapability(gate, capability))
                return new(gate, capability!, fallback);
        }

        return null;
    }

    private static TypeGate? GetGate(SyntaxNodeAnalysisContext context, ISymbol member, ExpressionSyntax condition)
    {
        condition = Unwrap(condition);
        if (condition is IsPatternExpressionSyntax pattern)
            return GetPatternGate(context, member, pattern.Expression, pattern.Pattern);
        if (condition is BinaryExpressionSyntax binary && binary.IsKind(SyntaxKind.IsExpression))
            return CreateGate(context, member, binary.Left, binary.Right, alias: null, negated: false);

        return null;
    }

    private static TypeGate? GetPatternGate(SyntaxNodeAnalysisContext context, ISymbol member, ExpressionSyntax receiver, PatternSyntax pattern)
    {
        bool negated = false;
        while (pattern is ParenthesizedPatternSyntax or UnaryPatternSyntax)
        {
            if (pattern is ParenthesizedPatternSyntax parentheses)
                pattern = parentheses.Pattern;
            else if (pattern is UnaryPatternSyntax unary && unary.IsKind(SyntaxKind.NotPattern))
            {
                negated = !negated;
                pattern = unary.Pattern;
            }
            else
                return null;
        }
        TypeSyntax? type = pattern switch
        {
            DeclarationPatternSyntax declaration => declaration.Type,
            TypePatternSyntax typePattern => typePattern.Type,
            RecursivePatternSyntax recursive => recursive.Type,
            _ => null
        };
        if (type is null)
            return null;

        var designation = pattern switch
        {
            DeclarationPatternSyntax declaration => declaration.Designation as SingleVariableDesignationSyntax,
            RecursivePatternSyntax recursive => recursive.Designation as SingleVariableDesignationSyntax,
            _ => null
        };
        var alias = designation is null ? null : context.SemanticModel.GetDeclaredSymbol(designation, context.CancellationToken);

        return CreateGate(context, member, receiver, type, alias, negated);
    }

    private static TypeGate? CreateGate(SyntaxNodeAnalysisContext context, ISymbol member, ExpressionSyntax receiver,
        SyntaxNode typeSyntax, ISymbol? alias, bool negated)
    {
        var type = context.SemanticModel.GetTypeInfo(typeSyntax, context.CancellationToken).Type;
        var contract = context.SemanticModel.GetTypeInfo(receiver, context.CancellationToken).Type;
        if (type is not INamedTypeSymbol { TypeKind: TypeKind.Class or TypeKind.Struct or TypeKind.Interface } || contract is null || contract.IsValueType ||
            SymbolEqualityComparer.Default.Equals(type, contract) || !IsInternalReceiver(context, member, receiver))
            return null;

        return new(receiver, type, contract, alias, negated, member is IMethodSymbol { ReturnsVoid: true });
    }

    private static bool IsInternalReceiver(SyntaxNodeAnalysisContext context, ISymbol member, ExpressionSyntax expression)
    {
        expression = Unwrap(expression);
        var symbol = context.SemanticModel.GetSymbolInfo(expression, context.CancellationToken).Symbol;
        if (symbol is IFieldSymbol or IPropertySymbol)
            return !symbol.IsImplicitlyDeclared && !symbol.DeclaringSyntaxReferences.IsEmpty &&
                SymbolEqualityComparer.Default.Equals(symbol.ContainingType, member.ContainingType);
        if (symbol is not IParameterSymbol parameter)
            return false;

        return parameter.ContainingSymbol is IMethodSymbol { MethodKind: MethodKind.Constructor } constructor &&
            SymbolEqualityComparer.Default.Equals(constructor.ContainingType, member.ContainingType);
    }

    private static Evidence? CheckBranches(SyntaxNodeAnalysisContext context, TypeGate gate, SyntaxNode supported, SyntaxNode unsupported)
    {
        var fallback = ReturnedValues(unsupported).Select(value => Placeholder(context, value)).FirstOrDefault(value => value is not null);
        if (fallback is null)
            return null;

        foreach (var value in ReturnedValues(supported, gate.IsVoid))
            foreach (var access in value.DescendantNodesAndSelf(EnterExecutableCode))
            {
                var receiver = access switch
                {
                    MemberAccessExpressionSyntax named => named.Expression,
                    ElementAccessExpressionSyntax indexed => indexed.Expression,
                    _ => null
                };
                if (receiver is null || !UsesImplementation(context, gate, receiver))
                    continue;

                var capability = context.SemanticModel.GetSymbolInfo(access, context.CancellationToken).Symbol;
                if (IsSpecificCapability(gate, capability))
                    return new(gate, capability!, fallback);
            }

        return null;
    }

    private static IEnumerable<SyntaxNode> ReturnedValues(SyntaxNode node, bool includeCalls = false)
    {
        if (node is ExpressionSyntax)
        {
            yield return node;
            yield break;
        }
        IEnumerable<SyntaxNode> statements = node switch
        {
            BlockSyntax block => block.Statements,
            SwitchSectionSyntax section => section.Statements,
            _ => [node]
        };
        foreach (var statement in statements)
        {
            if (statement is BlockSyntax nested)
            {
                foreach (var value in ReturnedValues(nested, includeCalls))
                    yield return value;
            }
            else if (statement is ReturnStatementSyntax { Expression: { } expression })
                yield return expression;
            else if (statement is ThrowStatementSyntax thrown)
                yield return thrown;
            else if (includeCalls && statement is ExpressionStatementSyntax call)
                yield return call.Expression;
        }
    }

    private static bool UsesImplementation(SyntaxNodeAnalysisContext context, TypeGate gate, ExpressionSyntax expression)
    {
        expression = Unwrap(expression);
        if (gate.Alias is not null && SymbolEqualityComparer.Default.Equals(
            context.SemanticModel.GetSymbolInfo(expression, context.CancellationToken).Symbol, gate.Alias))
            return true;
        if (expression is not CastExpressionSyntax cast || !SymbolEqualityComparer.Default.Equals(
            context.SemanticModel.GetTypeInfo(cast.Type, context.CancellationToken).Type, gate.Type))
            return false;

        return SymbolEqualityComparer.Default.Equals(context.SemanticModel.GetSymbolInfo(Unwrap(cast.Expression), context.CancellationToken).Symbol,
            context.SemanticModel.GetSymbolInfo(Unwrap(gate.Receiver), context.CancellationToken).Symbol);
    }

    private static bool IsSpecificCapability(TypeGate gate, ISymbol? capability)
    {
        if (capability is not (IPropertySymbol or IFieldSymbol or IMethodSymbol) || capability.IsStatic)
            return false;
        if (gate.Contract is not INamedTypeSymbol contract)
            return false;

        for (var current = contract; current is not null; current = current.BaseType)
            if (HasContractMember(current, gate.Type, capability))
                return false;
        foreach (var inherited in contract.AllInterfaces)
            if (HasContractMember(inherited, gate.Type, capability))
                return false;

        return true;
    }

    private static bool HasContractMember(INamedTypeSymbol contract, ITypeSymbol implementation, ISymbol capability)
    {
        foreach (var member in contract.GetMembers(capability.Name))
        {
            if (contract.TypeKind == TypeKind.Interface && implementation is INamedTypeSymbol named &&
                SymbolEqualityComparer.Default.Equals(named.FindImplementationForInterfaceMember(member), capability))
                return true;
            for (ISymbol? current = capability; current is not null; current = current switch
            {
                IPropertySymbol property => property.OverriddenProperty,
                IMethodSymbol method => method.OverriddenMethod,
                _ => null
            })
                if (SymbolEqualityComparer.Default.Equals(current.OriginalDefinition, member.OriginalDefinition))
                    return true;
        }

        return false;
    }

    private static SyntaxNode? Placeholder(SyntaxNodeAnalysisContext context, SyntaxNode node)
    {
        if (node is ExpressionSyntax expression)
        {
            expression = Unwrap(expression);
            // A named domain state (including a zero-valued enum case) is not an empty placeholder.
            if (context.SemanticModel.GetSymbolInfo(expression, context.CancellationToken).Symbol is
                IFieldSymbol { ContainingType.TypeKind: TypeKind.Enum })
                return null;

            var constant = context.SemanticModel.GetConstantValue(expression, context.CancellationToken);
            if (constant.HasValue && constant.Value is null or false or "" or 0 or 0L or 0U or 0UL or 0F or 0D or 0M)
                return node;
            if (expression is DefaultExpressionSyntax || expression.IsKind(SyntaxKind.DefaultLiteralExpression) ||
                expression is CollectionExpressionSyntax { Elements.Count: 0 } ||
                expression is ArrayCreationExpressionSyntax { Initializer.Expressions.Count: 0 })
                return node;
            var symbol = context.SemanticModel.GetSymbolInfo(expression, context.CancellationToken).Symbol;
            var owner = symbol?.ContainingType?.ToDisplayString();
            if (symbol?.Name == "Empty" && owner is "System.Array" or "System.Linq.Enumerable" or "string")
                return node;
        }
        ExpressionSyntax? thrown = node switch
        {
            ThrowExpressionSyntax thrownExpression => thrownExpression.Expression,
            ThrowStatementSyntax statement => statement.Expression,
            _ => null
        };
        var exception = thrown is null ? null : context.SemanticModel.GetTypeInfo(thrown, context.CancellationToken).Type?.ToDisplayString();

        return exception is "System.NotSupportedException" or "System.InvalidOperationException" or "System.NotImplementedException" ? node : null;
    }

    private static ExpressionSyntax Unwrap(ExpressionSyntax expression)
    {
        while (expression is ParenthesizedExpressionSyntax parentheses)
            expression = parentheses.Expression;

        return expression;
    }

    private sealed class TypeGate(ExpressionSyntax receiver, ITypeSymbol type, ITypeSymbol contract, ISymbol? alias, bool negated, bool isVoid)
    {
        internal bool IsVoid { get; } = isVoid;
        internal ExpressionSyntax Receiver { get; } = receiver;
        internal ITypeSymbol Type { get; } = type;
        internal ITypeSymbol Contract { get; } = contract;
        internal ISymbol? Alias { get; } = alias;
        internal bool Negated { get; } = negated;
    }

    private sealed class Evidence(TypeGate gate, ISymbol capability, SyntaxNode fallback)
    {
        internal TypeGate Gate { get; } = gate;
        internal ISymbol Capability { get; } = capability;
        internal SyntaxNode Fallback { get; } = fallback;
    }
}
