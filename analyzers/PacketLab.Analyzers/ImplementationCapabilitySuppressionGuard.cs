using System.Text;
using Microsoft.CodeAnalysis;
using Microsoft.CodeAnalysis.CSharp.Syntax;
using Microsoft.CodeAnalysis.Text;

namespace PacketLab.Analyzers;

// SuppressMessage bypasses NotConfigurable analyzer diagnostics. Emit compiler errors for these attributes.
[Generator]
public sealed class ImplementationCapabilitySuppressionGuard : IIncrementalGenerator
{
    public void Initialize(IncrementalGeneratorInitializationContext context)
    {
        var suppressions = context.SyntaxProvider.CreateSyntaxProvider(
            static (node, _) => node is AttributeSyntax,
            static (syntax, cancellation) => SuppressedLocation(syntax, cancellation))
            .Where(static location => location is not null);
        context.RegisterSourceOutput(suppressions.Collect(), static (output, locations) =>
        {
            if (locations.IsEmpty)
                return;

            var source = new StringBuilder();
            foreach (var location in locations)
                source.Append("#error PL0013 cannot be suppressed; remove the suppression attribute at ")
                    .AppendLine(location);
            output.AddSource("ImplementationCapabilitySuppression.g.cs", SourceText.From(source.ToString(), Encoding.UTF8));
        });
    }

    private static string? SuppressedLocation(GeneratorSyntaxContext context, CancellationToken cancellation)
    {
        var attribute = (AttributeSyntax)context.Node;
        var constructor = context.SemanticModel.GetSymbolInfo(attribute, cancellation).Symbol as IMethodSymbol;
        if (constructor?.ContainingType.ToDisplayString() is not ("System.Diagnostics.CodeAnalysis.SuppressMessageAttribute" or
            "System.Diagnostics.CodeAnalysis.UnconditionalSuppressMessageAttribute"))
            return null;

        var checkId = attribute.ArgumentList?.Arguments.FirstOrDefault(argument => argument.NameColon?.Name.Identifier.ValueText == "checkId")
            ?? attribute.ArgumentList?.Arguments.ElementAtOrDefault(1);
        if (checkId is null || context.SemanticModel.GetConstantValue(checkId.Expression, cancellation).Value is not string value ||
            value.Split(':')[0].Trim() != ImplementationCapabilityAnalyzer.RuleId)
            return null;

        var line = attribute.GetLocation().GetLineSpan();
        var path = line.Path.Replace("\r", " ").Replace("\n", " ");

        return $"{path}:{line.StartLinePosition.Line + 1}";
    }
}
