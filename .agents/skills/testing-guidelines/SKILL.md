---
name: testing-guidelines
description: Use when writing, changing, organizing, or reviewing tests.
---

# Testing

## Test Design

- Keep each test focused on its purpose.
- Add tests only when they provide additional verification value; avoid redundant or speculative coverage.
- For correctness checks, assert observable behavior rather than implementation details.
- Keep tests and fixtures simple. Prefer explicit expected data over logic that reconstructs the expected result; allow small duplication rather than unnecessary abstractions.

## Test Scope

- Unit tests: verify independent logic, especially decision-heavy behavior, including meaningful success, failure, and boundary cases. Keep them fast, deterministic, and independent of external infrastructure.
- Integration and E2E tests: exercise real component boundaries or user workflows and verify outputs for representative success, failure, and boundary cases. Avoid exhaustive input variations.
- Native AOT smoke tests: use known samples to exercise intended paths and verify successful execution under Native AOT. Leave functional correctness to unit and integration tests.
- Choose the smallest scope that covers the relevant risks, without omitting necessary higher-level tests.

## Test Organization

- Use TUnit with Microsoft.Testing.Platform.
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
