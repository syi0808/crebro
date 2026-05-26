# Crebro - Credential Broker

Crebro is a local credential broker for coding agents that keeps secrets out of external LLM requests.

## What It Does

Credentials should stay local. Crebro's position is that API keys, tokens, passwords, and manually marked secrets should not be sent to an external LLM just because they appeared in a prompt, config file, environment variable, or tool context.

Crebro runs as a one-shot wrapper around a child agent process:

```sh
crebro -- codex
```

It starts a loopback gateway or local proxy, launches the child command, routes supported provider traffic through Crebro, redacts discovered secrets before the request reaches the upstream LLM provider, and restores Crebro placeholders in the local response stream before the child agent sees the answer.

The current implementation focuses on:

- zero-config first
- in-memory secret handling
- no persistent secret storage
- environment and `.env` credential discovery
- exact-match redaction for managed secrets
- user-declared secrets with `<cb>...</cb>`
- placeholder restoration in responses

## What It Does Not Do

Crebro is not a full security boundary.

- It does not protect against privileged memory inspection, kernel-level attackers, malicious local processes, or secrets that already exist in your shell, files, terminal, or child agent process.
- It does not provide semantic detection for every possible secret-like value. current targets exact-match redaction of known, discovered, or explicitly declared secrets.
- It does not install system-wide trust. Proxy mode uses a session-local CA for the wrapped child process.
- It does not claim full provider certification yet.
- It does not replace normal secret hygiene, provider-side access controls, or outbound network monitoring.

## Test

Crebro is intended to protect coding-agent traffic broadly. The first tested scope is Codex.

Verified local routing surfaces:

- Codex CLI 0.133.0 using OpenAI-compatible routing through `OPENAI_BASE_URL`
- Codex ChatGPT auth traffic through child-scoped proxy environment variables and `chatgpt.com/backend-api`

Manual Wireshark QA was also run with Crebro TLS key logging enabled. The capture was decrypted in Wireshark to inspect the outbound provider payload during a real Codex session.

Evidence from that run is included below.

| Evidence | Screenshot |
| --- | --- |
| Codex session routed through Crebro | ![Codex session routed through Crebro](docs/codex-chat.png) |
| Wireshark payload inspection | ![Wireshark payload inspection](docs/wireshark-payload-log.png) |

## Install

### Requirements

- Rust toolchain with Rust 2024 edition support
- A supported child agent command, such as `codex`

### Install From crates.io

```sh
cargo install crebro
```

### Install From npm

```sh
npm install -g crebro
```

### Install From Source

```sh
git clone https://github.com/syi0808/crebro.git
cd crebro
cargo install --path .
```

### Verify

```sh
crebro --version
crebro --help
```

## Usage

### Basic Codex Wrapper

```sh
crebro -- codex
```

Crebro launches `codex`, removes raw provider keys from the child environment, sets provider base URL variables to the local Crebro gateway, and exits with the child process status.

### Automatic Routing Choice

```sh
crebro -- codex
```

Crebro does not ask the user to choose a routing mode. It uses the native provider gateway path when the child command can be routed through provider base URL variables. When Codex is running through ChatGPT auth and there is no provider API key, Crebro uses a child-scoped local proxy because that traffic does not honor `OPENAI_BASE_URL`.

The proxy path starts a local explicit proxy, injects proxy environment variables into the child process, and uses a session-local CA for allowlisted MITM traffic. This is an implementation detail driven by the agent's auth path, not a feature toggle the user is expected to manage.

### Upstream URL

Crebro infers the default upstream URL for supported commands. Override it when needed:

```sh
crebro --upstream-url https://api.openai.com -- codex
```

or:

```sh
CREBRO_UPSTREAM_URL=https://api.openai.com crebro -- codex
```

### Provider API Key

Crebro can read provider keys from the environment or from `--provider-api-key`.

```sh
CREBRO_PROVIDER_API_KEY=sk-example crebro -- codex
```

Known provider key variables include `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `GEMINI_API_KEY`, `GOOGLE_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY`, and `OPENCODE_API_KEY`.

### Environment File

By default, Crebro checks `.env` for credential candidates.

```sh
crebro --env-file .env.local -- codex
```

or:

```sh
CREBRO_ENV_FILE=.env.local crebro -- codex
```

### User-Declared Secrets

If automatic discovery cannot know that a prompt fragment is sensitive, wrap it with `<cb>...</cb>` inside the agent prompt:

```text
Use <cb>my-manual-secret</cb> for this local step.
```

Crebro consumes the tags locally, registers the inner value as an encrypted in-memory secret capsule, and forwards only a Crebro placeholder upstream.

### Placeholder Guidance

When Crebro redacts a request, it can add a short instruction asking the LLM to reuse `{{CREBRO_SECRET:...}}` placeholders verbatim in commands, code, config, and shell snippets. The default instruction text is compiled from `prompts/placeholder-guidance.md`.

Disable this behavior with:

```sh
crebro --no-placeholder-guidance -- codex
```

or:

```sh
CREBRO_NO_PLACEHOLDER_GUIDANCE=true crebro -- codex
```

Redaction still runs when placeholder guidance is disabled.

### Credential Pattern Rules

Built-in discovery and detector rules live in `patterns/credentials.toml` and are compiled into the binary.

Use a custom rule file with:

```sh
crebro --patterns-file ./patterns/credentials.toml -- codex
```

or:

```sh
CREBRO_PATTERNS_FILE=./patterns/credentials.toml crebro -- codex
```

Rules can reject unregistered credential-looking values, allow intentionally public identifiers, or auto-redact specific patterns.

### Local Stats

When launched through the CLI, Crebro writes best-effort local stats to `~/.crebro/stats.json`.

```sh
crebro --stats-dir /tmp/crebro-stats -- codex
```

or:

```sh
CREBRO_STATS_DIR=/tmp/crebro-stats crebro -- codex
```

The stats file stores counts by Crebro placeholder id and credential pattern id. It does not store raw secrets, raw prompts, or raw responses.

### TLS Key Logging For QA

For isolated QA sessions, Crebro can write TLS key logs for its upstream HTTPS connections:

```sh
CREBRO_TLS_KEYLOG_FILE=/tmp/crebro-tls.keys crebro -- codex
```

or:

```sh
crebro --tls-keylog-file /tmp/crebro-tls.keys -- codex
```

Use this only in controlled testing. Delete the key log file after analysis.

## Frequently Asked Questions

### Can Crebro guarantee that no secret ever leaves my machine?

No. Crebro redacts known, discovered, or explicitly declared secrets before the upstream LLM request. It cannot protect against secrets already exposed to the child process, secrets not registered with Crebro, privileged local inspection, OS-level compromise, or an agent that sends data outside the routed path.

### Does proxy mode decrypt my traffic?

For allowlisted proxy targets, yes. Proxy mode uses local MITM so Crebro can redact request bodies and restore placeholders in responses. The CA is session-local and injected into the wrapped child process; Crebro does not install system-wide trust.

### How was Crebro built?

The product direction, architecture decisions, and real testing were done by a human. The implementation was vibe-coded with AI assistance and then checked against local tests and manual review.

## License

Crebro is licensed under the [Apache License 2.0](LICENSE).
