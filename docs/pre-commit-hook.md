# Pre-commit Hook Integration

secretgate can be used as a pre-commit hook to catch secrets before they
reach git history. There are two approaches:

## 1. Using `secretgate scan --staged`

The simplest approach — scans only the staged diff:

```bash
# .git/hooks/pre-commit
#!/bin/sh
secretgate scan --staged --no-entropy
```

Or with a shell script in your repo:

```bash
# scripts/pre-commit.sh
#!/bin/sh
set -e
echo "Scanning staged changes for secrets..."
secretgate scan --staged --no-entropy
```

## 2. Using `.pre-commit-config.yaml`

If you use the [pre-commit](https://pre-commit.com/) framework:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: secretgate
        name: secretgate secret scan
        entry: secretgate scan --no-entropy
        language: system
        types: [text]
```

## 3. CI/CD Integration

For CI pipelines, use `--json-output` for machine-readable results:

```yaml
# .github/workflows/ci.yml
- name: Scan for secrets
  run: |
    pip install secretgate
    secretgate scan --json-output src/ tests/ > scan-results.json || {
      echo "::error::Secrets detected in codebase"
      cat scan-results.json
      exit 1
    }
```

## Directory Scanning

`secretgate scan` supports directory arguments and will walk them
recursively, automatically skipping:

- Binary files (`.png`, `.jpg`, `.zip`, `.pdf`, etc.)
- Hidden directories (`.git`, `.venv`, etc.)
- Build artifacts (`node_modules`, `__pycache__`, `dist`, etc.)

```bash
# Scan entire project
secretgate scan src/ tests/ docs/

# Scan everything
secretgate scan .
```

## Tips

- Use `--no-entropy` to reduce false positives in pre-commit hooks
  (entropy detection can flag random-looking code)
- Use `--no-known-values` if env-var harvesting is too noisy locally
- The `--json-output` flag is useful for CI/CD integration and log parsing
