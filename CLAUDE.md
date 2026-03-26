# secretgate

Lean security proxy for AI coding tools — scans and redacts secrets before they reach LLM APIs.

## Project structure

- `src/secretgate/` — main package
  - `server.py` — FastAPI app assembly, `AppState` dataclass, lifespan management
  - `proxy.py` — reverse proxy core (JSON parsing, pipeline execution, streaming/buffered forwarding)
  - `forward.py` — forward proxy with TLS MITM (`asyncio.Server`, CONNECT tunnels, HTTP scanning)
  - `certs.py` — CA cert generation, per-domain cert caching for TLS MITM
  - `scan.py` — raw text/bytes scanning adapter (wraps `SecretScanner` for forward proxy, routes git packfiles)
  - `packfile.py` — git packfile parser: extracts text from commit/blob/tag objects for secret scanning
  - `pipeline.py` — pluggable `PipelineStep` / `Pipeline` / `PipelineContext` abstraction
  - `steps.py` — `SecretRedactionStep` (scan + redact) and `AuditLogStep`
  - `cli.py` — Click CLI (`serve`, `scan`, and `ca` commands)
  - `config.py` — Config with env var overrides (prefix `SECRETGATE_`)
  - `secrets/scanner.py` — regex patterns from YAML + Shannon entropy analysis + known-value integration
  - `secrets/redactor.py` — deterministic `REDACTED<slug:hash12>` placeholders via SHA-256
  - `secrets/known_values.py` — known-value scanning: harvest env vars/files at startup, Aho-Corasick or naive matching
  - `secrets/detect_secrets_adapter.py` — optional Yelp detect-secrets integration (regex plugins only)
  - `signatures.yaml` — ~170 regex patterns (AWS, GCP, GitHub, GitLab, Slack, OpenAI, Anthropic, Stripe, etc.)
  - `firewall.py` — OS-specific firewall rule generation (iptables/nftables/pf) for preventing proxy bypass (issue #33)
  - `stats.py` — Thread-safe runtime statistics (requests scanned/blocked/redacted, per-service breakdowns)
- `scripts/` — helper scripts
  - `setup.sh` — one-time setup (install CA, trust instructions, shell config)
  - `with-secretgate.sh` — standalone wrapper (starts proxy, runs command, stops proxy)
- `docs/` — documentation
  - `supported-patterns.md` — full list of regex patterns
  - `known-value-scanning.md` — detailed explanation of known-value detection
- `tests/` — pytest test suite
- `.github/workflows/ci.yml` — matrix CI across Python 3.11–3.13

## Key patterns

- **AppState**: shared state dataclass populated during FastAPI lifespan, referenced by routes registered at creation time
- **Pipeline**: steps run sequentially on request, reversed on response; `SecretRedactionStep` scans first without mutating, then redacts only in `redact` mode
- **Placeholders**: `REDACTED<aws-access-key:a1b2c3d4e5f6>` — deterministic (same secret = same placeholder), self-documenting type identifier + truncated SHA-256 hash
- **Deduplication**: scanner deduplicates matches by value; redactor does a second pass `result.replace()` to catch repeated occurrences
- **Known-value scanning**: harvests actual secret values from env vars (filtered by name keywords + entropy) and config files at startup; scans via Aho-Corasick (optional `pyahocorasick`) or naive string matching; regex matches always take priority via shared `seen` set

## Branch strategy

- `main` is protected — all changes go through PRs with at least 1 approving review
- Squash merge only — each PR becomes a single commit on `main`
- Feature branches: `feat/...`, `fix/...`, `chore/...`
- Feature branches are auto-deleted after merge
- Never push directly to `main`

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
pytest tests/ -v
ruff check src/ tests/
```

## Publishing

Package is on PyPI as `secretgate`. Releases are automated via GitHub Actions trusted publishing (OIDC, no tokens):

1. Bump version in `pyproject.toml`
2. Create a GitHub Release with tag `vX.Y.Z`
3. The `publish.yml` workflow builds and uploads to PyPI automatically

## Forward proxy

The forward proxy (`--forward-proxy-port 8083`) intercepts all HTTPS traffic via `https_proxy` env var:
- Runs as a separate `asyncio.Server` alongside FastAPI (port 8083 by default)
- Handles CONNECT tunnels with TLS MITM using auto-generated per-domain certs
- Scans outbound request bodies for secrets (responses pass through unmodified)
- Uses regex-only scanning (entropy detection disabled to avoid false positives on code/JSON in raw HTTP bodies)
- Uses the same `REDACTED<slug:hash12>` placeholder format as the reverse proxy
- CA certs stored in `~/.secretgate/certs/` — trust via `secretgate ca trust`
- `passthrough_domains` config skips MITM for specified domains
- Supports chunked transfer encoding and streaming responses (SSE)
- `secretgate wrap -- <command>` starts proxy, sets env vars, runs command, stops proxy on exit
- **Git packfile scanning**: `git push` sends data as binary packfiles (zlib-compressed objects); secretgate parses these, extracts text from commit/blob/tag objects, and scans for secrets. Redact mode falls back to block (can't safely rewrite packfile binaries). Delta objects are skipped. Safety limits: 1MB per object, 10MB total decompressed.

### Tested with

- **Claude Code** — all LLM API traffic (api.anthropic.com) intercepted and scanned via CONNECT tunnel, secrets detected in conversation messages (audit + redact modes)
- **curl to httpbin.org** — HTTPS POST with AWS keys (access key ID + secret access key) detected and redacted through the MITM tunnel
- **git push** — packfile content (blobs, commits, tags) is parsed and scanned for secrets; pushes containing secrets are blocked with a clear `remote: [secretgate]` error message via git protocol report-status
- Other HTTPS tools (pip, npm) should work since they all use standard HTTP proxy env vars, but have not been manually verified yet
- **localhost traffic** bypasses proxy by default (standard HTTP proxy behavior) — use `no_proxy=""` to override
- **Platforms**: tested on Linux (Ubuntu/WSL2) and Windows; macOS should work but not yet verified

## Notes

- Pre-commit hooks require venv active (`language: system`)
- `--no-entropy` flag avoids false positives in pre-commit scanning
- Claude Code integration: `ANTHROPIC_BASE_URL=http://localhost:8082/anthropic` (API key only, not OAuth)
- detect-secrets entropy detectors are disabled due to high false-positive rate
- Forward proxy requires `cryptography>=42.0` (added to core deps)
- SSH git remotes (`git@github.com:...`) bypass HTTP proxy — only HTTPS remotes intercepted
- Node.js apps need `NODE_EXTRA_CA_CERTS` env var to trust the CA
- Scanner uses capture group(1) when available in regex patterns — allows patterns like AWS Secret Key to extract just the secret value, not the surrounding key name
- Known-value scanning is enabled by default; disable with `--no-known-values` or `SECRETGATE_KNOWN_VALUES=false`
- `pyahocorasick` is an optional dependency for faster known-value matching; falls back to naive string search
- Git packfile scanning: `application/x-git-receive-pack-request` content type is routed to the packfile parser instead of the text scanner; redact mode falls back to block since packfile binaries can't be safely rewritten without corrupting checksums/delta chains
