---
name: testing-guidelines
description: Use when writing, changing, organizing, or reviewing tests.
---

# Testing

## Test Design

- Name each test after one clear behavior and assert only what is needed to verify it.
- Use examples for specific cases and regressions. Use property-based tests for rules that hold across many input combinations.
- Write separate tests for distinct behaviors; use parameterization or loops for input variations of the same behavior, without branching between unrelated expectations.
- Add tests only when they provide additional verification value; avoid redundant or speculative coverage.
- For correctness checks, assert observable behavior rather than implementation details.
- Keep tests and fixtures simple, allowing small duplication rather than unnecessary abstractions. Prefer explicit expected data; do not duplicate production logic to compute expected results.

## Test Scope

- Unit tests: verify independent logic, especially decision-heavy behavior, including meaningful success, failure, and boundary cases. Keep them fast, deterministic, and independent of external infrastructure.
- Integration and E2E tests: exercise real component boundaries or user workflows and verify outputs for representative success, failure, and boundary cases. Avoid exhaustive input variations.
- Native AOT smoke tests: use known samples to exercise intended paths and verify successful execution under Native AOT. Leave functional correctness to unit, integration, and E2E tests.
- Choose the smallest scope that covers the relevant risks, without omitting necessary higher-level tests.
- Prefer property-based tests at the unit level. Use them in integration tests when the property spans components.

## Test Organization

- Use TUnit with Microsoft.Testing.Platform and FsCheck for property-based tests.
- Separate Unit and Integration tests into independent projects; avoid unnecessary additional projects.
- Group tests by use case or capability, keeping success, failure, and boundary cases together.
- Prefer verb-object class names, e.g., `LoginTests`, with matching filenames.
- Name test methods as behavior statements using snake_case, e.g., `Login_fails_when_password_is_invalid`.

## Mutation Testing

- Consider mutation testing after tests pass when changing decision-heavy logic or checking test effectiveness.
- Use Stryker.NET to target the relevant source files.
- Restore the tool with `dotnet tool restore`. From the relevant unit test project directory, run:

  ```sh
  dotnet stryker --config-file ../../../stryker-config.json --mutate "<source-file>"
  ```

- Resolve the source path relative to the production project. Inspect reports under `StrykerOutput/`.
- Inspect surviving mutants; add meaningful tests for real gaps and recognize equivalent mutations.
