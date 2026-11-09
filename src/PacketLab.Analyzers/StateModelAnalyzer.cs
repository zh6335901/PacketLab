using System.Collections.Immutable;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Diagnostics;

namespace PacketLab.Analyzers;

[DiagnosticAnalyzer(LanguageNames.CSharp)]
public sealed class StateModelAnalyzer : DiagnosticAnalyzer
{
    public const string ImplicitStatesId = "PL0001";
    public const string UnprotectedStatesId = "PL0002";

    private static readonly DiagnosticDescriptor ImplicitStates = new(
        ImplicitStatesId, "Possible implicit states",
        "Type '{0}' stores optional members ({1}) that may encode dependent or mutually exclusive states; consider separate union cases",
        "Design", DiagnosticSeverity.Warning, isEnabledByDefault: true,
        description: "Multiple optional members, or an optional member with a boolean or enum discriminator, may permit unintended state combinations. Independent optional data can be locally suppressed with a justification.");

    private static readonly DiagnosticDescriptor UnprotectedStates = new(
        UnprotectedStatesId, "Observed state combinations are not protected",
        "Type '{0}' constructs different state combinations ({1}), but exposes independent construction or mutation of their members",
        "Design", DiagnosticSeverity.Warning, isEnabledByDefault: true,
        description: "Constructor or factory paths suggest related states while accessible constructors or writable members permit other combinations. Observed paths are evidence, not a complete domain specification.");

    public override ImmutableArray<DiagnosticDescriptor> SupportedDiagnostics => [ImplicitStates, UnprotectedStates];

    public override void Initialize(AnalysisContext context)
    {
        context.ConfigureGeneratedCodeAnalysis(GeneratedCodeAnalysisFlags.None);
        context.EnableConcurrentExecution();
        context.RegisterSymbolAction(AnalyzeType, SymbolKind.NamedType);
    }

    private static void AnalyzeType(SymbolAnalysisContext context)
    {
        var type = (INamedTypeSymbol)context.Symbol;
        if (type.TypeKind is not (TypeKind.Class or TypeKind.Struct) || type.IsImplicitlyDeclared)
            return;

        var transportModel = context.Compilation.GetTypeByMetadataName(
            "PacketLab.Analyzers.Annotations.TransportModelAttribute");
        if (transportModel is not null && type.GetAttributes().Any(attribute =>
                SymbolEqualityComparer.Default.Equals(attribute.AttributeClass, transportModel)))
            return;

        var members = type.GetMembers().Where(IsStoredMember).ToImmutableArray();
        var optional = members.Where(IsOptional).ToImmutableArray();
        var discriminators = members.Where(IsDiscriminator).ToImmutableArray();
        if (optional.Length < 2 && (optional.IsEmpty || discriminators.IsEmpty))
            return;

        var relevant = optional.AddRange(discriminators);
        var location = type.Locations.FirstOrDefault(l => l.IsInSource);
        if (location is null)
            return;

        var evidence = ConstructionPatterns.FindUnprotectedStates(type, relevant, context.Compilation,
            context.CancellationToken);
        context.ReportDiagnostic(evidence is null
            ? Diagnostic.Create(ImplicitStates, location, type.Name, string.Join(", ", optional.Select(m => m.Name)))
            : Diagnostic.Create(UnprotectedStates, location, type.Name, evidence));
    }

    private static bool IsStoredMember(ISymbol member)
    {
        if (member.IsStatic)
            return false;
        if (member is IFieldSymbol field)
            return !field.IsImplicitlyDeclared && !field.IsConst;
        if (member is not IPropertySymbol { IsIndexer: false } property)
            return false;

        return property.DeclaringSyntaxReferences.Any(reference => reference.GetSyntax() switch
        {
            ParameterSyntax => true, // Positional records expose synthesized storage properties.
            PropertyDeclarationSyntax { ExpressionBody: null, AccessorList: { } accessors } =>
                accessors.Accessors.All(a => a.Body is null && a.ExpressionBody is null) && !property.IsAbstract,
            _ => false
        });
    }

    internal static ITypeSymbol MemberType(ISymbol member) => member switch
    {
        IPropertySymbol property => property.Type,
        IFieldSymbol field => field.Type,
        _ => throw new ArgumentException("Expected a field or property.", nameof(member))
    };

    internal static bool IsOptional(ISymbol member) => MemberType(member) is { } type &&
        (type.OriginalDefinition.SpecialType == SpecialType.System_Nullable_T ||
         (type.IsReferenceType || type.TypeKind == TypeKind.TypeParameter) &&
         type.NullableAnnotation == NullableAnnotation.Annotated);

    private static bool IsDiscriminator(ISymbol member) => !IsOptional(member) &&
        (MemberType(member).TypeKind == TypeKind.Enum || MemberType(member).SpecialType == SpecialType.System_Boolean);
}
