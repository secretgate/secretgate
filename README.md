# secretgate

A lean security proxy for AI coding tools. Routes all LLM API traffic through
a local proxy that scans for secrets before they leave your machine.

## Architecture

```
IDE / CLI / Agent
       │
       ▼
┌─────────────────────────┐
│     secretgate :8080        │
│                         │
│  ┌───────────────────┐  │
│  │  Secret Scanner   │  │
│  │  (regex+entropy)  │  │
│  ├───────────────────┤  │
│  │  Pipeline Steps   │  │
│  │  (pluggable)      │  │
│  ├───────────────────┤  │
│  │  Audit Logger     │  │
│  └───────────────────┘  │
│                         │
│  Reverse proxy per      │
│  provider, streaming    │
└────────┬────────────────┘
         │
         ▼
   LLM Provider APIs
   (OpenAI, Anthropic, Ollama, ...)
```

## How it works

1. Configure your AI tool to use `http://localhost:8080` as its API base URL
2. secretgate intercepts every request, scans outbound prompts for secrets
3. Secrets are redacted with `REDACTED<uuid>` placeholders before forwarding
4. Responses are scanned; placeholders are restored on the way back
5. Everything is logged for audit

## Quickstart

```bash
pip install secretgate
secretgate serve                     # start on :8080
secretgate serve --port 9090         # custom port
secretgate serve --block              # block requests instead of redacting
```

## Configuration

```bash
# Point your AI tool at secretgate
export OPENAI_BASE_URL=http://localhost:8080/openai
export ANTHROPIC_BASE_URL=http://localhost:8080/anthropic

# Or use as a generic HTTP proxy
export HTTPS_PROXY=http://localhost:8080
```

## Adding custom secret patterns

Drop patterns in `~/.secretgate/signatures.yaml` or pass `--signatures /path/to/file.yaml`.

```yaml
- MyCompany:
    - Internal API Key: "myco_[a-zA-Z0-9]{32}"
    - Database URL: "postgres://.*@prod\\.mycompany\\.com"
```
