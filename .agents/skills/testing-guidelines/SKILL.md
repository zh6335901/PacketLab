---
name: testing-guidelines
description: Use when writing, changing, organizing, or reviewing tests.
---

# Testing

## Test Design

- Keep tests focused on the behavior being verified; avoid unrelated assertions and dependencies.
- Add tests only when they provide additional verification value. Avoid redundant coverage, unnecessary test projects, and helper abstractions.
- Cover meaningful success, failure, and boundary cases.
- Avoid speculative or low-value tests.
- Keep tests readable; avoid unnecessary fixtures and abstractions.
- Name test methods as behavior statements using snake_case, e.g., `Login_fails_when_password_is_invalid`.

## Test Organization

- Choose test scope based on where correctness risks lie: prefer unit tests for decision-heavy behavior and integration tests for component interactions.
- Use TUnit with Microsoft.Testing.Platform.
- Separate Unit and Integration tests into independent projects.
- Group tests by use case or capability, keeping success, failure, and boundary cases together.
- Prefer verb-object class names, e.g., `LoginTests`, with matching filenames.
- Keep Unit tests fast, deterministic, and independent of external infrastructure.
- Use Integration tests to verify real integration boundaries.
- Focus integration and E2E tests on representative workflows. Avoid expanding them into a checklist of interface features and input variations.
- Choose the smallest test scope that reliably verifies behavior, without omitting necessary higher-level tests.

## Mutation Testing

- Consider mutation testing after tests pass when changing decision-heavy logic or checking test effectiveness.
- Use Stryker.NET to target the relevant source files.
- Restore the tool with `dotnet tool restore`. From the relevant unit test project directory, run:

  ```sh
  dotnet stryker --config-file ../../../stryker-config.json --mutate "<source-file>"
  ```

- Resolve the source path relative to the production project. Inspect reports under `StrykerOutput/`.
- Inspect surviving mutants; add meaningful tests for real gaps and recognize equivalent mutations.
