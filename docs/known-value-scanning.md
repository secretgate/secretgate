# Known-Value Secret Scanning

## The problem

secretgate's regex scanner detects secrets by **shape** — patterns like `AKIA[0-9A-Z]{16}` catch AWS access keys, `ghp_[A-Za-z0-9]{36}` catches GitHub tokens, and so on. This works well for secrets that follow a recognizable format, but misses:

- **Custom or internal tokens** with no standard prefix (e.g. `mycompany_live_xK9mP2nQ7rT4wZ8a`)
- **Secrets pasted without context** — a bare API key on a line by itself, without `API_KEY=` around it
- **Secrets from unrecognized services** that don't match any of the ~170 built-in patterns
- **Database passwords, encryption keys, and other values** that are just random strings

The known-value scanner solves this by detecting secrets based on their **actual value**, not their shape.

## How it works

Known-value scanning operates in three phases: **harvest**, **index**, and **scan**.

### Phase 1: Harvest (startup only)

At startup, secretgate collects actual secret values from two sources:

#### Environment variables

The scanner inspects `os.environ` and keeps values that pass all four filters:

1. **Name keyword match** — the variable name must contain at least one of:
   `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `CREDENTIAL`, `AUTH`, `PRIVATE`, `API_KEY`, `APIKEY`, `ACCESS_KEY`, `PASSPHRASE`

2. **Denylist exclusion** — common non-secret variables are skipped:
   `PATH`, `HOME`, `SHELL`, `LANG`, `TERM`, `USER`, `PWD`, `EDITOR`, `DISPLAY`, `HOSTNAME`, and others.
   All `SECRETGATE_*` variables are also excluded to avoid self-detection.

3. **Minimum length** — values shorter than 8 characters (configurable) are skipped.

4. **Minimum entropy** — values with Shannon entropy below 2.5 bits (configurable) are skipped.
   This filters out values like `true`, `localhost`, or `aaaaaaaaaa` that pass the length check but aren't secrets.
   The threshold (2.5) is lower than the regex scanner's entropy detection (4.0) because the name-based keyword filter already provides strong signal that the value is likely a secret.

#### Secret files

Files listed in the `secret_files` config are parsed based on their extension:

| Extension | Parser | What's extracted |
|-----------|--------|-----------------|
| `.env` | Line-by-line `KEY=VALUE` | Values (handles quotes, comments, `export` prefix) |
| `.json` | `json.load()` | Top-level string values |
| `.toml` | `tomllib.loads()` (stdlib) | Top-level string values |
| `.ini`, `.cfg` | `configparser` | All values from all sections |
| Other | Plain text | One value per non-blank, non-comment line |

Each extracted value goes through the same min-length and entropy filters as env vars.

### Phase 2: Index (startup only)

After harvesting, the scanner builds an index for fast matching:

**With `pyahocorasick` installed** (recommended for many known values):
- Builds an [Aho-Corasick automaton](https://en.wikipedia.org/wiki/Aho%E2%80%93Corasick_algorithm) — a finite-state machine that can find all known values in a text in O(n) time, regardless of how many values are indexed
- Install with: `pip install secretgate[ahocorasick]`

**Without `pyahocorasick`** (fallback):
- Sorts values longest-first (so longer matches take priority)
- Checks each value with Python's `str.find()` — O(n*m) where m is the number of known values
- Perfectly fine for typical use (dozens of env vars), only matters at scale

### Phase 3: Scan (every request)

On every outbound request, after regex and entropy scanning, the known-value scanner runs:

1. Search the text for any harvested values
2. For each match found, record a `Match` with:
   - `service = "known-value"` — distinguishes from regex matches
   - `pattern_name` = the env var name or file key (e.g. `MY_SECRET_TOKEN`)
   - Correct line number and character position
3. Deduplicate: if the same value was already found by regex scanning, the known-value match is skipped (regex takes priority)

The result feeds into the same redaction pipeline, producing placeholders like:
```
REDACTED<my-secret-token:a1b2c3d4e5f6>
```

## Scan order and deduplication

The `SecretScanner.scan()` method runs detectors in this order:

```
1. Regex patterns (~170 signatures)     ← highest priority
2. Entropy detection (key=value pairs)
3. detect-secrets plugins (optional)
4. Known-value scanner                 ← lowest priority
```

All four share a `seen` set of matched values. If a regex pattern already found a value (e.g. an AWS key that's also in your env), the known-value scanner won't create a duplicate match. This means:
- Regex matches always get the more specific `service` and `pattern_name` (e.g. `service=Amazon`, `pattern_name=AWS Access Key`)
- Known-value scanning only adds matches for values that no other detector caught

## Configuration

### CLI flags

```bash
secretgate serve --no-known-values    # disable for the proxy server
secretgate scan --no-known-values     # disable for offline scanning
```

### Environment variable

```bash
export SECRETGATE_KNOWN_VALUES=false  # disable globally
```

### Config file (YAML)

```yaml
enable_known_values: true

known_values:
  scan_env: true
  secret_files:
    - /home/user/.env
    - /home/user/project/secrets.json
    - /home/user/.config/tokens.toml
  min_length: 8
  entropy_threshold: 2.5
```

### Defaults

| Setting | Default | Description |
|---------|---------|-------------|
| `enable_known_values` | `true` | Master switch |
| `scan_env` | `true` | Harvest from environment variables |
| `secret_files` | `[]` | List of file paths to harvest from |
| `min_length` | `8` | Skip values shorter than this |
| `entropy_threshold` | `2.5` | Skip values with entropy below this |

## Memory safety

Known values are stored in memory for the lifetime of the proxy. On shutdown, secretgate calls `clear()` which:
1. Overwrites each stored value with null bytes (`\x00`)
2. Clears the internal list and destroys the Aho-Corasick automaton

This follows the same pattern as `SecretRedactor.clear()`.

## Example: catching a custom token

```bash
# Set a custom token that no regex would match
export MY_SECRET_TOKEN=xK9mP2nQ7rT4wZ8aB5cD

# Start Claude Code through secretgate
secretgate wrap -- claude

# In the Claude conversation, if the token value appears in any outbound
# request, secretgate redacts it:
#   "the token is xK9mP2nQ7rT4wZ8aB5cD"
#   → "the token is REDACTED<my-secret-token:34d69d4032da>"
```

This was verified live: with `MY_SECRET_TOKEN` set in the environment and Claude Code running through secretgate's forward proxy, pasting the token value into conversation resulted in the LLM receiving only the redacted placeholder. The actual value never left the machine.

## Offline scanning

Known-value scanning also works with `secretgate scan`:

```bash
export MY_SECRET_TOKEN=xK9mP2nQ7rT4wZ8aB5cD
echo "the token is xK9mP2nQ7rT4wZ8aB5cD" | secretgate scan

# Output:
#   Line 1: [known-value] MY_SECRET_TOKEN - xK9mP2nQ...
#   1 secret(s) found.
```
