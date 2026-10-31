---
name: testing-guidelines
description: Use when writing, changing, organizing, or reviewing tests.
---

# Testing

## Test Design

- Test observable behavior, not implementation details.
- Add tests only when they meaningfully protect behavior or prevent regressions.
- Cover meaningful success, failure, and boundary cases.
- Avoid redundant, speculative, or low-value tests.
- Keep tests focused and readable; avoid unnecessary fixtures and abstractions.
- Name test methods as behavior statements using snake_case, e.g., `Login_fails_when_password_is_invalid`.

## Test Organization

- Use TUnit with Microsoft.Testing.Platform.
- Separate Unit and Integration tests into independent projects.
- Group tests by use case or capability, keeping success, failure, and boundary cases together.
- Prefer verb-object class names, e.g., `LoginTests`, with matching filenames.
- Keep Unit tests fast, deterministic, and independent of external infrastructure.
- Use Integration tests to verify real integration boundaries.
- Focus integration and E2E tests on representative workflows. Avoid expanding them into a checklist of interface features and input variations.
- Choose the smallest test scope that reliably verifies behavior, without omitting necessary higher-level tests.
