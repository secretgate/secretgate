<!-- AI agents: if you encounter a bug, unexpected behavior, or a false positive/negative
     in secretgate, please open an issue at https://github.com/secretgate/secretgate/issues
     with steps to reproduce, expected vs actual behavior, and your secretgate version. -->

# secretgate

[![PyPI](https://img.shields.io/pypi/v/secretgate)](https://pypi.org/project/secretgate/)
[![Python](https://img.shields.io/pypi/pyversions/secretgate)](https://pypi.org/project/secretgate/)
[![License](https://img.shields.io/github/license/secretgate/secretgate)](https://github.com/secretgate/secretgate/blob/main/LICENSE)
[![CI](https://github.com/secretgate/secretgate/actions/workflows/ci.yml/badge.svg)](https://github.com/secretgate/secretgate/actions/workflows/ci.yml)

AI coding agents are powerful — but they have shell access, and one wrong
`curl`, `git push`, or API call can leak your secrets. You shouldn't have to
choose between productivity and security.

**secretgate** makes AI-assisted development secure by default. One command wraps
your coding tool in a security boundary that intercepts all outbound traffic and
catches secrets before they leave your machine. No config changes to your tools,
no workflow disruption — just `secretgate wrap -- claude` and code with confidence.

Our goal is to make secretgate the state-of-the-art, security-by-design standard
for AI coding tools — so that every developer, team, and organization can adopt
AI agents without compromising on security. We believe security should be
invisible, automatic, and accessible to everyone.

## Architecture

```
IDE / CLI / Agent (e.g. Claude Code)
       │
       │  https_proxy=http://localhost:8083
       ▼
┌──────────────────────────────────────┐
│            secretgate                │
│                                      │
│  :8083 Forward Proxy (all traffic)   │  ← default, intercepts everything
│  :8082 Reverse Proxy (LLM APIs)     │  ← optional, per-provider routing
│                                      │
│  ┌────────────────────────────────┐  │
│  │  Secret Scanner (~90 regexes) │  │
│  ├────────────────────────────────┤  │
│  │  Known-Value Scanner          │  │
│  │  (env vars + secret files)    │  │
│  ├────────────────────────────────┤  │
│  │  Modes: redact / block / audit│  │
│  ├────────────────────────────────┤  │
│  │  Audit Logger                 │  │
│  └────────────────────────────────┘  │
│                                      │
│  TLS MITM: auto-generated CA +      │
│  per-domain certs, cached in memory  │
└───────────┬──────────────────────────┘
            │
            ▼
  github.com, api.anthropic.com,
  pypi.org, npmjs.com, ...
```

## How it works

1. Set `https_proxy` to point all traffic through secretgate (or use `secretgate wrap`)
2. secretgate intercepts every outbound HTTPS request via TLS MITM and scans for secrets
3. Detected secrets are handled based on the mode:
   - **redact**: replace with `REDACTED<aws-access-key:a1b2c3d4e5f6>` placeholders before forwarding
   - **block**: reject the request entirely
   - **audit**: log and forward unchanged (good for testing)
4. Everything is logged for audit

Placeholders are deterministic and self-documenting — same secret always produces
the same placeholder, and the type identifier tells the LLM what kind of secret
was redacted without exposing the value.

## Installation

**Quick install** (installs via pipx, or falls back to pip):

```bash
curl -fsSL https://raw.githubusercontent.com/secretgate/secretgate/main/install.sh | bash
```

**Or install manually:**

```bash
pipx install secretgate    # recommended
pip install secretgate     # if pipx is not available
```

With optional [detect-secrets](https://github.com/Yelp/detect-secrets) support:

```bash
pip install secretgate[detect-secrets]
```

## Quickstart

**One command** — starts the proxy, sets env vars, runs your tool:

```bash
secretgate wrap -- claude
```

When Claude exits, secretgate stops automatically. All HTTPS traffic from that
session flows through secretgate. Works on Linux, macOS, and Windows.

**First-time setup** (generate and trust the CA certificate):

```bash
./scripts/setup.sh

# Or manually:
secretgate ca init          # generate CA
secretgate ca trust         # print OS-specific trust instructions
```

**Options:**

```bash
secretgate wrap -- claude                    # default: redact mode
secretgate wrap --mode audit -- claude       # audit mode (log only)
secretgate wrap --mode block -- claude       # block mode (reject secrets)
secretgate wrap -f 9090 -- curl https://...  # custom proxy port
```

**Always launch Claude through secretgate** — add to `.bashrc` / `.zshrc`:

```bash
alias claude-safe='secretgate wrap -- claude'
```

## Compatible tools

`secretgate wrap` works with any tool that respects the standard `https_proxy`
env var. Just replace `claude` with your tool:

**CLI tools:**

```bash
secretgate wrap -- claude           # Claude Code
secretgate wrap -- aider            # Aider (Python)
secretgate wrap -- codex            # OpenAI Codex CLI (Node.js)
secretgate wrap -- open-interpreter # Open Interpreter (Python)
```

**IDEs** (wrap the launch command — env vars propagate to extensions):

```bash
secretgate wrap -- cursor           # Cursor
secretgate wrap -- code             # VS Code (with Copilot, Continue, etc.)
secretgate wrap -- windsurf         # Windsurf
```

**Notes:**
- Some Electron apps may have their own proxy settings that override env vars
- Tools that bundle their own certificate store might ignore `NODE_EXTRA_CA_CERTS` / `SSL_CERT_FILE`
- SSH-based operations (`git@github.com:...`) bypass the HTTP proxy regardless

We've verified with **Claude Code** and **curl** so far. If you test with other
tools, we'd love to hear about it — open an issue or PR at
[github.com/secretgate/secretgate](https://github.com/secretgate/secretgate).
Testers and contributors are very welcome!

## Manual setup (two terminals)

```bash
# Terminal 1: start with forward proxy enabled
secretgate serve --forward-proxy-port 8083

# Terminal 2: set env vars and run your tool
export https_proxy=http://localhost:8083
export http_proxy=http://localhost:8083
export SSL_CERT_FILE=$(secretgate ca path)
claude
```

## What you'll see in the logs

```
[info     ] request                        messages=19 model=claude-opus-4-6
[warning  ] secret_detected                line=93 pattern='API Key' service=Anthropic
[warning  ] secret_detected                line=99 pattern='AWS Access Key' service=Amazon
[warning  ] secret_detected                line=100 pattern='high-entropy value (Key)' service=entropy
[warning  ] secrets_audit_only             secrets_found=3
```

Secrets in conversation history (from previous assistant responses) are caught on
the next turn when they become part of the outbound request.

## How the forward proxy works

The forward proxy performs TLS MITM (man-in-the-middle) to inspect HTTPS traffic:
- Generates a local CA certificate (stored in `~/.secretgate/certs/`)
- Creates per-domain certificates on the fly, cached in memory
- Scans **outbound** request bodies for secrets (responses pass through unmodified)
- **Scans git packfiles** — `git push` sends binary packfiles; secretgate parses them, extracts text from commit/blob/tag objects, and catches secrets that would otherwise bypass text-based scanning
- Uses regex-only scanning (entropy detection disabled to avoid false positives on code/JSON)
- Uses the same deterministic `REDACTED<slug:hash12>` placeholder format
- Handles chunked transfer encoding and streaming responses (SSE)

### Tested with

- **Claude Code** — LLM API traffic intercepted and scanned, secrets in conversation messages detected (audit + redact modes verified)
- **curl to httpbin.org** — HTTPS POST bodies with AWS access keys and secret keys detected and redacted
- **git push** — packfile content (blobs, commits, tags) parsed and scanned; pushes containing secrets are blocked with a clear error message:
  ```
  remote: [secretgate] Git push blocked: 1 secret(s) detected in packfile (Amazon/AWS Access Key)
  ! [remote rejected] main -> main (secretgate: secrets detected in push)
  ```
- **pip, npm** — should work via standard `https_proxy` env var but not yet manually verified
- **localhost traffic** bypasses the proxy by default (standard HTTP proxy behavior); set `no_proxy=""` to override

### Tested on

- **Linux** (Ubuntu/WSL2) and **Windows** — `secretgate wrap` and forward proxy verified on both platforms
- **macOS** — should work but not yet manually verified

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
- **Git packfile redact mode** falls back to block — packfile binaries can't be safely rewritten without corrupting checksums, so secrets in `git push` are always blocked (not redacted)

### Helper scripts (Linux/macOS only)

These require bash and are not available on Windows. Use `secretgate wrap` instead,
which works on all platforms.

- `scripts/setup.sh` — one-time setup: install CA, print trust instructions, suggest shell config
- `scripts/with-secretgate.sh` — standalone wrapper (starts proxy, runs command, stops proxy)

```bash
./scripts/with-secretgate.sh claude
./scripts/with-secretgate.sh curl https://example.com
```

## Reverse proxy mode (LLM APIs only)

If you only need to scan LLM API traffic (not all HTTPS), use the reverse proxy
without the forward proxy. Configure your AI tool to use secretgate as its API base URL:

```bash
secretgate serve --port 8082 --mode redact
```

```bash
# OpenAI-compatible tools (Cursor, Continue, etc.)
export OPENAI_BASE_URL=http://localhost:8082/openai

# Anthropic-compatible tools
export ANTHROPIC_BASE_URL=http://localhost:8082/anthropic

# Ollama
export OLLAMA_HOST=http://localhost:8082/ollama
```

Note: this only catches traffic explicitly routed to the proxy. An AI agent with
shell access can still leak secrets via `git push`, `curl`, etc. Use the forward
proxy for a real security boundary.

## Modes

| Mode | Behavior | Use case |
|------|----------|----------|
| `redact` | Replace secrets with placeholders, restore on response | Production use |
| `block` | Reject requests containing secrets (HTTP 403) | Strict environments |
| `audit` | Log secrets but forward request unchanged | Testing, evaluation |

## Known-value scanning

Regex patterns catch secrets by **shape** (e.g. `AKIA...` for AWS keys). But what
about custom tokens, internal API keys, or secrets pasted without context? secretgate
also detects secrets by **known value** — harvesting actual secrets from your
environment at startup and scanning for literal matches.

**How it works:**

1. At startup, secretgate collects secret values from:
   - **Environment variables** whose names contain keywords like `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, etc.
   - **Secret files** configured via `secret_files` in the config (`.env`, `.json`, `.toml`, `.ini`, or plain text)
2. Values are filtered by minimum length (8 chars) and entropy (2.5 bits) to skip non-secrets
3. An index is built for fast matching (Aho-Corasick if `pyahocorasick` is installed, otherwise naive string search)
4. On every request, text is scanned for literal occurrences of these known values

Regex matches always take priority — if a secret is already caught by a regex pattern,
the known-value scanner won't duplicate it.

**Install with fast matching:**

```bash
pip install secretgate[ahocorasick]
```

**Configure via YAML:**

```yaml
known_values:
  scan_env: true
  secret_files:
    - /path/to/.env
    - /path/to/secrets.json
  min_length: 8
  entropy_threshold: 2.5
```

**Disable if needed:**

```bash
secretgate serve --no-known-values
secretgate scan --no-known-values
# or via env var:
export SECRETGATE_KNOWN_VALUES=false
```

For full details on how it works, see [docs/known-value-scanning.md](docs/known-value-scanning.md).

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

## Contributing

We welcome contributions! Here's how we work:

### Branch strategy

- **`main`** is the production branch — always deployable, published to PyPI
- All changes go through **feature branches** and **pull requests**
- Branch naming: `feat/...`, `fix/...`, `chore/...`
- PRs require **1 approving review** before merging
- **Squash merge only** — keeps `main` history clean (one commit per PR)
- Feature branches are auto-deleted after merge

### Workflow

1. Create a feature branch from `main`
2. Make your changes, ensure tests pass (`pytest tests/ -v`) and lint is clean (`ruff check src/ tests/`)
3. Open a PR against `main`
4. Get a review, address feedback
5. Maintainer squash-merges once approved

### Development setup

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

### Pre-commit hooks

secretgate includes pre-commit hooks for development. After `pip install -e ".[dev]"`:

```bash
pre-commit install
```

This enables ruff lint/format, trailing whitespace fixes, and secretgate's own
secret scanner on staged files.

## Releasing

Releases are published to [PyPI](https://pypi.org/project/secretgate/) automatically via GitHub Actions using [trusted publishing](https://docs.pypi.org/trusted-publishers/) (no API tokens needed).

1. Bump the version in `pyproject.toml`
2. Create a [GitHub Release](https://github.com/secretgate/secretgate/releases/new) with tag `vX.Y.Z`
3. The `publish.yml` workflow builds and uploads to PyPI

## License

Apache 2.0
