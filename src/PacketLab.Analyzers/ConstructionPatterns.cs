using System.Collections.Immutable;
using System.Globalization;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Operations;

namespace PacketLab.Analyzers;

internal static class ConstructionPatterns
{
    // Empty means unknown. Keep path exploration bounded for interactive editing.
    private const string Unknown = "";
    private const string Null = "null";
    private const string Present = "present";
    private const int MaxPaths = 32;

    internal static string? FindUnprotectedStates(INamedTypeSymbol type, ImmutableArray<ISymbol> members,
        Compilation compilation, CancellationToken cancellationToken)
    {
        var observations = new List<string[]>();
        foreach (var constructor in type.InstanceConstructors)
        {
            cancellationToken.ThrowIfCancellationRequested();
            observations.AddRange(Construct(constructor, members, compilation, null, cancellationToken));
        }

        foreach (var method in type.GetMembers().OfType<IMethodSymbol>().Where(m => m.IsStatic &&
                     SymbolEqualityComparer.Default.Equals(m.ReturnType, type)))
        foreach (var reference in method.DeclaringSyntaxReferences)
        {
            var syntax = reference.GetSyntax(cancellationToken);
            var model = compilation.GetSemanticModel(syntax.SyntaxTree);
            foreach (var creation in syntax.DescendantNodes(n => n is not AnonymousFunctionExpressionSyntax
                         and not LocalFunctionStatementSyntax).OfType<BaseObjectCreationExpressionSyntax>())
            {
                cancellationToken.ThrowIfCancellationRequested();
                if (model.GetOperation(creation, cancellationToken) is not IObjectCreationOperation
                    { Constructor: { } constructor } operation ||
                    !SymbolEqualityComparer.Default.Equals(constructor.ContainingType, type))
                    continue;

                var arguments = new Dictionary<ISymbol, string>(SymbolEqualityComparer.Default);
                foreach (var argument in operation.Arguments)
                    if (argument.Parameter is { } parameter)
                        arguments[parameter] = Value(argument.Value, null);
                var paths = Construct(constructor, members, compilation, arguments, cancellationToken);
                if (operation.Initializer is { } initializer)
                {
                    if (!Apply(initializer.Initializers, paths, members, arguments))
                        continue;
                }
                observations.AddRange(paths);
            }
        }

        // Compare members rather than whole objects: unrelated unknown fields must not hide evidence.
        for (var i = 0; i < members.Length; i++)
        for (var j = i + 1; j < members.Length; j++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!StateModelAnalyzer.IsOptional(members[i]) ||
                !(IsWritable(members[i]) || IsWritable(members[j]) ||
                  CanConstructIndependently(type, members[i], members[j], compilation, cancellationToken)))
                continue;

            var pairs = observations.Select(p => (Left: p[i], Right: p[j]))
                .Where(p => p.Left is Null or Present && p.Right != Unknown).Distinct().ToArray();
            foreach (var first in pairs)
            foreach (var second in pairs)
                if (first.Left != second.Left && first.Right != second.Right)
                    return $"{members[i].Name}={first.Left}, {members[j].Name}={first.Right}; " +
                           $"{members[i].Name}={second.Left}, {members[j].Name}={second.Right}";
        }
        return null;
    }

    private static List<string[]> Construct(IMethodSymbol constructor, ImmutableArray<ISymbol> members,
        Compilation compilation, Dictionary<ISymbol, string>? arguments, CancellationToken cancellationToken)
    {
        var state = members.Select(m => StateModelAnalyzer.IsOptional(m) ? Null : Unknown).ToArray();
        var syntax = constructor.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(cancellationToken);
        for (var i = 0; i < members.Length; i++)
        foreach (var reference in members[i].DeclaringSyntaxReferences)
        {
            var declaration = reference.GetSyntax(cancellationToken);
            if (declaration is ParameterSyntax && constructor.ContainingType.IsRecord &&
                constructor.Parameters.FirstOrDefault(p => p.Name == members[i].Name) is { } parameter)
                state[i] = Normalize(members[i], ParameterValue(parameter, arguments));
            var initializer = declaration switch
            {
                PropertyDeclarationSyntax property => property.Initializer,
                VariableDeclaratorSyntax field => field.Initializer,
                _ => null
            };
            if (initializer is not null)
                state[i] = Normalize(members[i], Value(compilation.GetSemanticModel(declaration.SyntaxTree)
                    .GetOperation(initializer.Value, cancellationToken), arguments));
        }

        var paths = new List<string[]> { state };
        if (syntax is TypeDeclarationSyntax)
            return paths;
        if (syntax is not ConstructorDeclarationSyntax declarationSyntax)
            return constructor.IsImplicitlyDeclared && constructor.Parameters.IsEmpty ? paths : [];
        // Delegation, validation calls and other unsupported effects are not assumed to preserve state.
        if (declarationSyntax.Initializer is not null)
            return [];
        var model = compilation.GetSemanticModel(syntax.SyntaxTree);
        var body = (SyntaxNode?)declarationSyntax.Body ?? declarationSyntax.ExpressionBody?.Expression;
        return body is not null && Execute(model.GetOperation(body, cancellationToken), paths, members, arguments)
            ? paths : [];
    }

    private static bool Execute(IOperation? operation, List<string[]> paths, ImmutableArray<ISymbol> members,
        Dictionary<ISymbol, string>? arguments)
    {
        switch (operation)
        {
            case IBlockOperation block:
                return Apply(block.Operations, paths, members, arguments);
            case IExpressionStatementOperation expression:
                return Execute(expression.Operation, paths, members, arguments);
            case ISimpleAssignmentOperation assignment:
                var index = MemberIndex(assignment.Target, members);
                if (index < 0)
                    return false;
                foreach (var path in paths)
                    path[index] = Normalize(members[index], Value(assignment.Value, arguments));
                return true;
            case IConditionalOperation branch:
                var condition = Value(branch.Condition, arguments);
                if (condition == "True")
                    return Execute(branch.WhenTrue, paths, members, arguments);
                if (condition == "False")
                    return branch.WhenFalse is null || Execute(branch.WhenFalse, paths, members, arguments);
                if (paths.Count * 2 > MaxPaths)
                    return false;
                var alternative = paths.Select(p => (string[])p.Clone()).ToList();
                if (!Execute(branch.WhenTrue, paths, members, arguments) ||
                    branch.WhenFalse is not null && !Execute(branch.WhenFalse, alternative, members, arguments))
                    return false;
                paths.AddRange(alternative);
                return paths.Count <= MaxPaths;
            case IThrowOperation:
                paths.Clear();
                return true;
            case IEmptyOperation:
                return true;
            default:
                return false;
        }
    }

    private static bool Apply(ImmutableArray<IOperation> operations, List<string[]> paths,
        ImmutableArray<ISymbol> members, Dictionary<ISymbol, string>? arguments)
    {
        foreach (var operation in operations)
            if (!Execute(operation, paths, members, arguments))
                return false;
        return true;
    }

    private static int MemberIndex(IOperation target, ImmutableArray<ISymbol> members)
    {
        var symbol = target switch
        {
            IPropertyReferenceOperation { Instance: IInstanceReferenceOperation } property => (ISymbol)property.Property,
            IFieldReferenceOperation { Instance: IInstanceReferenceOperation } field => field.Field,
            _ => null
        };
        for (var i = 0; i < members.Length; i++)
            if (SymbolEqualityComparer.Default.Equals(members[i], symbol))
                return i;
        return -1;
    }

    private static string Value(IOperation? operation, Dictionary<ISymbol, string>? arguments)
    {
        if (operation is null)
            return Unknown;
        if (operation.ConstantValue.HasValue)
        {
            if (operation.ConstantValue.Value is null)
                return Null;
            return operation.Type?.TypeKind == TypeKind.Enum || operation.Type?.SpecialType == SpecialType.System_Boolean
                ? Convert.ToString(operation.ConstantValue.Value, CultureInfo.InvariantCulture) ?? Unknown : Present;
        }
        return operation switch
        {
            IConversionOperation { OperatorMethod: null, IsTryCast: false } conversion => Value(conversion.Operand, arguments),
            IParenthesizedOperation parenthesized => Value(parenthesized.Operand, arguments),
            IParameterReferenceOperation parameter => ParameterValue(parameter.Parameter, arguments),
            IObjectCreationOperation { Arguments.IsEmpty: true } when
                operation.Type?.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T => Null,
            IObjectCreationOperation or IArrayCreationOperation => Present,
            IDefaultValueOperation when operation.Type?.IsReferenceType == true ||
                operation.Type?.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T => Null,
            IConditionalOperation conditional => ConditionalValue(conditional, arguments),
            _ => Unknown
        };
    }

    private static string Normalize(ISymbol member, string value) =>
        StateModelAnalyzer.IsOptional(member) && value is not (Unknown or Null) ? Present : value;

    private static string ConditionalValue(IConditionalOperation conditional, Dictionary<ISymbol, string>? arguments)
    {
        var condition = Value(conditional.Condition, arguments);
        var first = Value(conditional.WhenTrue, arguments);
        var second = Value(conditional.WhenFalse, arguments);
        return condition == "True" ? first : condition == "False" ? second : first == second ? first : Unknown;
    }

    private static string ParameterValue(IParameterSymbol parameter, Dictionary<ISymbol, string>? arguments)
    {
        if (arguments is not null && arguments.TryGetValue(parameter, out var value))
            return value;
        return parameter.Type.TypeKind != TypeKind.Enum && parameter.Type.SpecialType != SpecialType.System_Boolean &&
               parameter.Type.OriginalDefinition.SpecialType != SpecialType.System_Nullable_T &&
               parameter.NullableAnnotation == NullableAnnotation.NotAnnotated ? Present : Unknown;
    }

    private static bool IsWritable(ISymbol member) => member switch
    {
        IPropertySymbol { SetMethod: { } setter } => setter.DeclaredAccessibility != Accessibility.Private,
        IFieldSymbol field => !field.IsReadOnly && field.DeclaredAccessibility != Accessibility.Private,
        _ => false
    };

    private static bool CanConstructIndependently(INamedTypeSymbol type, ISymbol left, ISymbol right,
        Compilation compilation, CancellationToken cancellationToken)
    {
        foreach (var constructor in type.InstanceConstructors.Where(c => c.DeclaredAccessibility != Accessibility.Private))
        {
            var mapping = new Dictionary<ISymbol, IParameterSymbol>(SymbolEqualityComparer.Default);
            var syntax = constructor.DeclaringSyntaxReferences.FirstOrDefault()?.GetSyntax(cancellationToken);
            if (syntax is RecordDeclarationSyntax)
            {
                foreach (var member in new[] { left, right })
                    if (member.DeclaringSyntaxReferences.Any(r => r.GetSyntax(cancellationToken) is ParameterSyntax) &&
                        constructor.Parameters.FirstOrDefault(p => p.Name == member.Name) is { } parameter)
                        mapping[member] = parameter;
            }
            else if (syntax is ConstructorDeclarationSyntax { Initializer: null } declaration)
            {
                var model = compilation.GetSemanticModel(syntax.SyntaxTree);
                var body = (SyntaxNode?)declaration.Body ?? declaration.ExpressionBody?.Expression;
                var operation = body is null ? null : model.GetOperation(body, cancellationToken);
                if (!MapAssignments(operation, mapping))
                    continue;
            }
            if (mapping.TryGetValue(left, out var first) && mapping.TryGetValue(right, out var second) &&
                !SymbolEqualityComparer.Default.Equals(first, second) && AcceptsOptional(left, first) && AcceptsOptional(right, second))
                return true;
        }
        return false;
    }

    private static bool AcceptsOptional(ISymbol member, IParameterSymbol parameter) =>
        !StateModelAnalyzer.IsOptional(member) || parameter.NullableAnnotation == NullableAnnotation.Annotated ||
        parameter.Type.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T;

    private static bool MapAssignments(IOperation? operation, Dictionary<ISymbol, IParameterSymbol> mapping)
    {
        if (operation is IBlockOperation block)
            return block.Operations.All(o => MapAssignments(o, mapping));
        if (operation is IExpressionStatementOperation expression)
            return MapAssignments(expression.Operation, mapping);
        if (operation is not ISimpleAssignmentOperation assignment)
            return false;
        var value = assignment.Value;
        while (value is IConversionOperation { OperatorMethod: null, IsTryCast: false } conversion)
            value = conversion.Operand;
        var target = assignment.Target switch
        {
            IPropertyReferenceOperation { Instance: IInstanceReferenceOperation } property => (ISymbol)property.Property,
            IFieldReferenceOperation { Instance: IInstanceReferenceOperation } field => field.Field,
            _ => null
        };
        if (target is null || value is not IParameterReferenceOperation parameter)
            return false;
        mapping[target] = parameter.Parameter;
        return true;
    }
}
