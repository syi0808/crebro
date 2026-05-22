# Crebro

Crebro v0.1 is a zero-config local LLM API redaction gateway for coding agents.

Core principles:

- zero-config
- one-shot process
- in-memory only
- no persistent secret storage
- no daemon
- no MITM
- native LLM gateway only
- plaintext-minimized secret handling
- large-context optimized redaction

## Usage

```sh
crebro -- codex
```

Crebro starts a loopback gateway, launches the child command, points common provider base URL variables at the gateway, removes raw provider keys from the child environment, and exits with the child status. It infers default upstream URLs for `codex`, `claude`, `gemini`, and `opencode`; pass `--upstream-url` or set `CREBRO_UPSTREAM_URL` to override that default.

Verified local routing surfaces:

- Codex CLI 0.132.0: OpenAI-compatible routing through `OPENAI_BASE_URL`.
- Claude Code 2.1.112: Anthropic-compatible routing through `ANTHROPIC_BASE_URL` and `CLAUDE_CODE_API_BASE_URL`.
- Gemini CLI 0.42.0: Gemini API-key routing through `GOOGLE_GEMINI_BASE_URL`.
- OpenCode 1.15.4: OpenAI/Anthropic provider routing through `OPENAI_BASE_URL` and `ANTHROPIC_BASE_URL`.

## Secret Handling

Crebro does not store secrets on disk.

During a session, Crebro avoids keeping plaintext secrets in its registry or long-lived heap state. Secrets are ingested into secure buffers, converted into encrypted in-memory capsules and matching fingerprints, then zeroized.

Request redaction uses fingerprints instead of plaintext secret tables. Response restoration decrypts a secret capsule only at the moment a placeholder needs to be restored, writes the bytes to the local response stream, and immediately zeroizes the scratch buffer.

Crebro disables common core dump paths where supported, but it cannot protect against privileged live memory inspection, kernel-level attackers, or plaintext secrets that already exist in your shell, OS environment, project files, or local agent process.

### User-declared secrets

If automatic discovery cannot know that a prompt fragment is sensitive, wrap it
with `<cb>...</cb>` inside the agent prompt:

```text
Use <cb>my-manual-secret</cb> for this local step.
```

Crebro consumes the tags locally, registers the inner value as a normal
encrypted in-memory secret capsule, and forwards only a Crebro placeholder
upstream. v0.1 intentionally has no naming or reference syntax.

## Credential Pattern Rules

Built-in discovery and detector rules live in `patterns/credentials.toml`.
Crebro compiles this TOML into the binary for zero-config use.

The TOML contains env/.env discovery markers and request-time
`credential_patterns`. Pattern entries use the explicit policy name
`on_unregistered_match = "require_explicit_secret"` when a credential-looking
value must not be forwarded unless it is already registered as a managed secret.

Use a custom rule file with:

```sh
crebro --patterns-file ./patterns/credentials.toml -- codex
```

or:

```sh
CREBRO_PATTERNS_FILE=./patterns/credentials.toml crebro -- codex
```

## Local Stats

When launched through the CLI, Crebro writes best-effort local stats to
`~/.crebro/stats.json`. Override the directory with `--stats-dir` or
`CREBRO_STATS_DIR`.

The stats file stores counts by Crebro placeholder id and credential pattern id.
It does not store raw secrets, raw prompts, or raw responses.

## Large Context Redaction

Crebro scans JSON string values and ordinary text-bearing fields. Repeated no-secret strings, redaction spans, recognized message objects, and tool schemas are cached with keyed hashes so repeated coding-agent context can skip full rescans.

Known binary/base64 payload fields may be skipped for performance. v0.1 targets exact-match redaction of discovered known secrets, not semantic detection of every possible secret-like value.

## Current QA Coverage

The core scenario test suite covers:

- plaintext-free registry state after ingest
- encrypted capsules and just-in-time restore
- source and scratch buffer zeroization paths
- `.env` discovery source buffer zeroization after candidate extraction
- registry debug output hides secret-derived fingerprints and lookup indexes
- redaction cache and streaming sanitizer debug output hides cached prompt/string bytes
- fingerprint-based redaction without a plaintext secret table
- user-declared `<cb>...</cb>` secret directives, including malformed directive rejection
- TOML-backed env/.env discovery and credential detector rules
- `require_explicit_secret` rejection for unregistered credential-like request values
- local stats recording for redacted placeholder ids and unregistered pattern ids without raw secrets
- longest-match-first overlap handling, including later-starting longer spans
- registry-empty streaming fast path that forwards bytes unchanged
- no-secret and redaction-span cache reuse
- bounded LRU cache eviction behavior
- cache invalidation when the registry changes
- provider message object and tool schema cache reuse
- case-insensitive JSON content-type detection before request redaction
- stale request `content-encoding` removal after JSON body redaction
- large JSON request body streaming redaction
- streaming sanitized request forwarding before the child request body finishes
- provider auth restoration applies upstream headers without creating a plaintext `String`
- Gemini v1 stable routes use Gemini API-key auth headers, not OpenAI bearer auth
- provider route inference covers OpenAI, Anthropic, Gemini beta, and Gemini stable routes
- upstream URL joining preserves path and query parameters
- large-string chunk cache with boundary-spanning and overlapping secret spans
- known binary/base64 field skipping in parsed and streaming JSON paths
- message/object cache avoids storing subtrees with skipped binary/base64 fields
- streaming placeholder restore across two- and three-chunk boundaries plus adjacent placeholders
- gateway response restoration for placeholders split across upstream chunks
- stale `content-encoding` removal after response body restoration
- gateway streams restored response chunks before the upstream response finishes
- runtime registration of observed provider auth headers, including case-insensitive Bearer schemes and surrounding whitespace normalization
- gateway roundtrip redaction before upstream and restoration back to the local child
- one-shot CLI wrapper routing a child request through Crebro with mock upstream echo
- child environment mediation so raw provider keys are not passed through unchanged
- zero-config upstream URL inference for supported agent commands

## Current Limits

This implementation is a tested v0.1 core, not a completed provider certification pass.

Remaining work before claiming full v0.1 first-class support:

- run live end-to-end agent sessions against real upstream providers
- verify process-level egress with a macOS outbound monitor such as Little Snitch or LuLu

The local mock-based QA suite is passing. Live provider E2E was not run in this
environment because no provider API key environment variables were set.

The streaming request path avoids buffering the full raw request before JSON tokenization or upstream forwarding. It still buffers the current JSON string token while it is being rewritten; small JSON bodies are parsed in memory.

## Manual Egress QA

For live agent testing on macOS, use an outbound monitor/firewall to verify that
the wrapped agent does not contact provider endpoints directly.

Expected network shape:

- `codex`, `claude`, `gemini`, or `opencode` may connect to `127.0.0.1` or `localhost`.
- The wrapped agent should not connect directly to `api.openai.com`, `api.anthropic.com`, or `generativelanguage.googleapis.com`.
- `crebro` is the process that may connect to the upstream provider endpoint.

This proves process-level mediation, not HTTPS payload contents. To inspect
request bodies and headers, point `--upstream-url` at a local recording upstream
or use a dedicated HTTPS debugging proxy in a separate test profile.

For the full local E2E test setup, including the `crebro-qa-upstream` recorder
and fail-close canary checks, see
`docs/qa/e2e-test-environment.md`.
