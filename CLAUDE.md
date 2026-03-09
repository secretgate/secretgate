# secretgate

Lean security proxy for AI coding tools — scans and redacts secrets before they reach LLM APIs.

## Project structure

- `src/secretgate/` — main package
  - `server.py` — FastAPI app assembly, `AppState` dataclass, lifespan management
  - `proxy.py` — reverse proxy core (JSON parsing, pipeline execution, streaming/buffered forwarding)
  - `pipeline.py` — pluggable `PipelineStep` / `Pipeline` / `PipelineContext` abstraction
  - `steps.py` — `SecretRedactionStep` (scan + redact) and `AuditLogStep`
  - `cli.py` — Click CLI (`serve` and `scan` commands)
  - `config.py` — Config with env var overrides (prefix `SECRETGATE_`)
  - `secrets/scanner.py` — regex patterns from YAML + Shannon entropy analysis
  - `secrets/redactor.py` — deterministic `REDACTED<slug:hash12>` placeholders via SHA-256
  - `secrets/detect_secrets_adapter.py` — optional Yelp detect-secrets integration (regex plugins only)
  - `signatures.yaml` — ~30 regex patterns (AWS, GCP, GitHub, Slack, OpenAI, Anthropic, Stripe, etc.)
- `tests/` — pytest test suite (28 tests)
- `.github/workflows/ci.yml` — matrix CI across Python 3.11–3.13

## Key patterns

- **AppState**: shared state dataclass populated during FastAPI lifespan, referenced by routes registered at creation time
- **Pipeline**: steps run sequentially on request, reversed on response; `SecretRedactionStep` scans first without mutating, then redacts only in `redact` mode
- **Placeholders**: `REDACTED<aws-access-key:a1b2c3d4e5f6>` — deterministic (same secret = same placeholder), self-documenting type identifier + truncated SHA-256 hash
- **Deduplication**: scanner deduplicates matches by value; redactor does a second pass `result.replace()` to catch repeated occurrences

## Development

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
pytest tests/ -v
ruff check src/ tests/
```

## Publishing

Package is on PyPI as `secretgate`. To release a new version:
1. Bump version in `pyproject.toml`
2. `python -m build`
3. `twine upload dist/*` (or use GitHub Actions trusted publishing)

## Notes

- Pre-commit hooks require venv active (`language: system`)
- `--no-entropy` flag avoids false positives in pre-commit scanning
- Claude Code integration: `ANTHROPIC_BASE_URL=http://localhost:8082/anthropic` (API key only, not OAuth)
- detect-secrets entropy detectors are disabled due to high false-positive rate
