# Contributing to Crebro

Thank you for your interest in contributing to Crebro. This guide explains how to report issues, propose changes, submit code, and contribute credential pattern rules safely.

## Code of Conduct

Please be respectful and constructive in all interactions. We are committed to providing a welcoming and inclusive experience for everyone.

## How to Contribute

### Reporting Bugs

1. Search [existing issues](../../issues) to check whether the bug has already been reported.
2. Open a new issue with:
   - Steps to reproduce the bug.
   - Expected behavior and actual behavior.
   - Your operating system, Rust version, and child agent command.
   - Relevant Crebro command-line flags or environment variables.
   - Logs or screenshots, with all secrets removed.

Never include real API keys, tokens, passwords, private keys, or credential-bearing URLs in an issue.

### Suggesting Enhancements

1. Search [existing issues](../../issues) for similar suggestions.
2. Open a new issue describing:
   - The problem or use case.
   - The proposed behavior.
   - Alternatives you considered.
   - Any security, privacy, or compatibility tradeoffs.

### Pull Requests

1. Fork the repository.
2. Create a branch from `main`.
3. Keep the change focused on one problem.
4. Add or update tests for behavior changes.
5. Run the relevant local checks before opening a pull request.
6. Open the pull request with a clear summary of what changed and why.
7. Link related issues when applicable.

Security-sensitive changes should explain the threat model, what is protected, and what is intentionally out of scope.

## Development Setup

Crebro is a Rust 2024 project with npm release tooling.

```bash
git clone https://github.com/syi0808/crebro.git
cd crebro
cargo build
cargo test
```

Use the local binary through Cargo while developing:

```bash
cargo run -- --help
cargo run -- --version
cargo run -- -- codex
```

The npm scripts are release-packaging helpers. They are not required for normal Rust development, but they can be checked when changing files under `npm/` or `scripts/`:

```bash
npm run npm:stage
npm run npm:pack
```

## Style Guide

### Code Style

- Follow the existing module boundaries under `src/`.
- Keep secret-handling code explicit about when raw secret material is read, registered, redacted, restored, or dropped.
- Do not log, print, snapshot, or persist raw secrets in tests or examples.
- Use `cargo fmt` formatting.

Run formatting before submitting code changes:

```bash
cargo fmt --check
```

Run Clippy when the change touches Rust logic:

```bash
cargo clippy --all-targets --all-features
```

### Commit Messages

- Use the imperative mood, such as `Add credential pattern test`.
- Keep the first line short and specific.
- Reference issue numbers when applicable, such as `Fix #123`.

## Testing

Run the full Rust test suite before submitting a pull request:

```bash
cargo test
```

Tests live in `tests/` and in Rust module test blocks under `src/`. For focused work, run the relevant test target first:

```bash
cargo test --test redaction_cache
cargo test --test proxy_mode
cargo test --lib
```

If you change npm packaging logic, also validate the JavaScript files:

```bash
node --check scripts/build-npm-package.mjs
node --check npm/bin/crebro.js
```

## Credential Pattern Contributions

Credential patterns are security-sensitive because matching text is registered as a transient in-memory secret and replaced before it is forwarded. Built-in rules live in `patterns/credentials.toml` and are compiled into the binary.

### Issue Required Before Adding a Pattern

Before opening a pull request that adds or changes a built-in credential pattern, you must first open a credential pattern addition issue using the `Credential pattern addition` issue template.

The pull request must link that issue and explain how the implementation follows the agreed behavior. Pull requests that add or change credential patterns without a linked issue may be closed until the design discussion happens.

### What the Issue Should Establish

The issue should document:

- The provider, product, protocol, or credential family.
- Public documentation or references for the credential format.
- Safe synthetic positive examples.
- Likely false positives and examples that must not match.
- The expected redaction impact, including whether any matched values are intentionally public but still worth hiding from upstream LLM requests.

Do not include real credentials in the issue, pull request, tests, screenshots, packet captures, or logs.

### Pattern Behavior

Use the narrowest regex that protects users without overmatching. Every accepted credential pattern redacts automatically, including identifier-like or client-visible values, because Crebro's default stance is that suspicious credential-shaped text should not be sent to an upstream LLM as raw text.

### Implementation Checklist

When a pattern change is accepted:

1. Update `patterns/credentials.toml`.
2. Use a stable, lowercase, descriptive `id`.
3. Add or update tests in `tests/redaction_cache.rs`.
4. Add integration coverage in `tests/proxy_mode.rs`, `tests/gateway_roundtrip.rs`, or `tests/stats.rs` when the runtime behavior changes.
5. Include positive and negative examples using only synthetic values.
6. Run the focused tests and then `cargo test`.

Prefer bounded regular expressions with clear prefixes, delimiters, and length limits. Avoid broad patterns that match ordinary prose, public identifiers, example placeholders, or short values.
