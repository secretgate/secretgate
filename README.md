# secretgate

[![PyPI](https://img.shields.io/pypi/v/secretgate)](https://pypi.org/project/secretgate/)
[![Python](https://img.shields.io/pypi/pyversions/secretgate)](https://pypi.org/project/secretgate/)
[![License](https://img.shields.io/github/license/secretgate/secretgate)](https://github.com/secretgate/secretgate/blob/main/LICENSE)
[![CI](https://github.com/secretgate/secretgate/actions/workflows/ci.yml/badge.svg)](https://github.com/secretgate/secretgate/actions/workflows/ci.yml)

A lean security proxy for AI coding tools. Routes all LLM API traffic through
a local proxy that scans for secrets before they leave your machine.

## Architecture

```
IDE / CLI / Agent
       │
       ▼
┌──────────────────────────┐
│     secretgate :8082     │
│                          │
│  ┌────────────────────┐  │
│  │  Secret Scanner    │  │
│  │  (regex + entropy) │  │
│  ├────────────────────┤  │
│  │  Pipeline Steps    │  │
│  │  (pluggable)       │  │
│  ├────────────────────┤  │
│  │  Audit Logger      │  │
│  └────────────────────┘  │
│                          │
│  Reverse proxy per       │
│  provider, streaming     │
└───────────┬──────────────┘
            │
            ▼
      LLM Provider APIs
      (OpenAI, Anthropic, Ollama, ...)
```

## How it works

1. Configure your AI tool to point at secretgate as its API base URL
2. secretgate intercepts every outbound request and scans all messages for secrets
3. Detected secrets are handled based on the mode:
   - **redact**: replace with `REDACTED<aws-access-key:a1b2c3d4e5f6>` placeholders before forwarding
   - **block**: reject the request entirely
   - **audit**: log and forward unchanged (good for testing)
4. On the response path, redacted placeholders are restored to their original values
5. Everything is logged for audit

Placeholders are deterministic and self-documenting — same secret always produces
the same placeholder, and the type identifier tells the LLM what kind of secret
was redacted without exposing the value.

## Installation

```bash
pip install secretgate
```

With optional [detect-secrets](https://github.com/Yelp/detect-secrets) support:

```bash
pip install secretgate[detect-secrets]
```

## Quickstart

```bash
secretgate serve                          # start on :8080, redact mode
secretgate serve --port 8082 --mode audit # audit mode (log only, don't modify)
secretgate serve --mode block             # block requests containing secrets
```

## Using with Claude Code

```bash
# Terminal 1: start the proxy
secretgate serve --port 8082 --mode audit

# Terminal 2: start Claude Code through the proxy
ANTHROPIC_BASE_URL=http://localhost:8082/anthropic claude
```

This routes all Claude Code API traffic through secretgate. Requires an API key
(`ANTHROPIC_API_KEY`) — OAuth-based login uses a different endpoint that requires
the forward proxy mode (see below).

**What you'll see in the logs:**

```
[info     ] request                        messages=19 model=claude-opus-4-6
[warning  ] secret_detected                line=93 pattern='API Key' service=Anthropic
[warning  ] secret_detected                line=99 pattern='AWS Access Key' service=Amazon
[warning  ] secret_detected                line=100 pattern='high-entropy value (Key)' service=entropy
[warning  ] secrets_audit_only             secrets_found=3
```

Secrets in conversation history (from previous assistant responses) are caught on
the next turn when they become part of the outbound request.

## Forward Proxy Mode (intercept all traffic)

The reverse proxy only catches LLM API traffic. An AI agent with shell access can
leak secrets via `git push`, `curl`, `pip publish`, etc. The **forward proxy** makes
secretgate a real security boundary — set `https_proxy` and ALL HTTPS traffic flows
through secretgate.

```bash
# 1. Start with forward proxy enabled
secretgate serve --forward-proxy-port 8083

# 2. Trust the CA certificate (first time only)
secretgate ca init          # generate CA if needed
secretgate ca trust         # print OS-specific trust instructions

# 3. In the AI tool's terminal
export https_proxy=http://localhost:8083
export http_proxy=http://localhost:8083
export SSL_CERT_FILE=$(secretgate ca path)
claude  # or any other tool — all traffic flows through secretgate
```

The forward proxy performs TLS MITM (man-in-the-middle) to inspect HTTPS traffic:
- Generates a local CA certificate (stored in `~/.secretgate/certs/`)
- Creates per-domain certificates on the fly, cached in memory
- Scans **outbound** request bodies for secrets (responses pass through unmodified)
- Uses regex-only scanning (entropy detection disabled to avoid false positives on code/JSON)
- Uses the same deterministic `REDACTED<slug:hash12>` placeholder format as the reverse proxy
- Supports `redact`, `block`, and `audit` modes (same as reverse proxy)
- Handles chunked transfer encoding and streaming responses

### Tested with

- **Claude Code** — LLM API traffic intercepted and scanned, secrets in conversation messages detected (audit + redact modes verified)
- **curl to httpbin.org** — HTTPS POST bodies with AWS access keys and secret keys detected and redacted
- **git, pip, npm** — should work via standard `https_proxy` env var but not yet manually verified
- **localhost traffic** bypasses the proxy by default (standard HTTP proxy behavior); set `no_proxy=""` to override

### CA Trust Instructions

```bash
# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain $(secretgate ca path)

# Ubuntu/Debian
sudo cp $(secretgate ca path) /usr/local/share/ca-certificates/secretgate.crt
sudo update-ca-certificates

# Python/httpx/requests
export SSL_CERT_FILE=$(secretgate ca path)

# Node.js
export NODE_EXTRA_CA_CERTS=$(secretgate ca path)
```

### Passthrough Domains

Skip TLS MITM for specific domains (e.g., internal services):

```yaml
# config.yaml
passthrough_domains:
  - internal.example.com
  - vpn.company.net
```

### Limitations

- **SSH git remotes** (`git@github.com:...`) bypass HTTP proxy — only HTTPS remotes are intercepted
- **HTTP/2** not supported (HTTP/1.1 only — sufficient for git, curl, pip, npm)
- **Node.js apps** need `NODE_EXTRA_CA_CERTS` env var
- **localhost** bypasses proxy by default — set `no_proxy=""` if needed

## Using with other AI tools

```bash
# OpenAI-compatible tools (Cursor, Continue, etc.)
export OPENAI_BASE_URL=http://localhost:8082/openai

# Anthropic-compatible tools
export ANTHROPIC_BASE_URL=http://localhost:8082/anthropic

# Ollama
export OLLAMA_HOST=http://localhost:8082/ollama
```

## Modes

| Mode | Behavior | Use case |
|------|----------|----------|
| `redact` | Replace secrets with placeholders, restore on response | Production use |
| `block` | Reject requests containing secrets (HTTP 403) | Strict environments |
| `audit` | Log secrets but forward request unchanged | Testing, evaluation |

## Extra detection with detect-secrets

For broader coverage, enable [Yelp's detect-secrets](https://github.com/Yelp/detect-secrets)
as a supplementary scanner (23 additional regex plugins, entropy detectors disabled to avoid
false positives):

```bash
pip install secretgate[detect-secrets]
secretgate serve --detect-secrets
```

Or via environment variable:

```bash
export SECRETGATE_DETECT_SECRETS=true
```

## Offline scanning

Scan files or stdin for secrets without running the proxy:

```bash
secretgate scan .env config.yaml          # scan specific files
cat .env | secretgate scan                # scan stdin
git diff --cached | secretgate scan       # scan staged changes
secretgate scan --no-entropy src/         # regex-only (fewer false positives)
```

## Supported patterns

secretgate ships with **~90 regex patterns** covering AWS (including STS/temporary credentials), GCP/Google (OAuth tokens, HMAC, Firebase), Azure (AD secrets, DevOps PATs, Cosmos DB, Service Bus, SAS tokens), Cloudflare, GitHub, GitLab, Slack, Discord, Telegram, OpenAI, Anthropic, Hugging Face, Stripe, Shopify, Twilio, SendGrid, Mailchimp, npm, PyPI, Vercel, Databricks, HashiCorp Vault/Terraform, Grafana, New Relic, Sentry, database connection strings, and more.

See the full list: [docs/supported-patterns.md](docs/supported-patterns.md)

## Adding custom secret patterns

Drop patterns in `~/.secretgate/signatures.yaml` or pass `--signatures /path/to/file.yaml`.

```yaml
- MyCompany:
    - Internal API Key: "myco_[a-zA-Z0-9]{32}"
    - Database URL: "myco_db://.*@prod\\.mycompany\\.com"
```

## Development

```bash
git clone https://github.com/secretgate/secretgate.git
cd secretgate
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install

# Run tests
pytest tests/ -v

# Lint
ruff check src/ tests/
```

## Pre-commit hooks

secretgate includes pre-commit hooks for development. After `pip install -e ".[dev]"`:

```bash
pre-commit install
```

This enables ruff lint/format, trailing whitespace fixes, and secretgate's own
secret scanner on staged files.

## License

Apache 2.0
