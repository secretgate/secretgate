# Research: proxy & firewall alternatives for secretgate

**Status:** research notes, not a proposal. Date: 2026-04-11.

## Why this exists

secretgate keeps hitting edge cases where legitimate traffic breaks: HTTP/2
flow-control data loss (fixed in #63), git packfile redaction falling back to
block, WebSocket frames bypassing scanning entirely, JSON content-type
heuristics that miss vendor MIME types, `content-length` header mangling in the
forward proxy, and platform gaps in the hardening path (`harden.py`). Most of
these failures are not scanner bugs — they are reinventing HTTP. Mature proxies
have already solved flow control, chunked encoding, TLS MITM, WebSocket
upgrade, and HTTP/2 stream multiplexing, and we should seriously consider
leaning on one of them instead of maintaining our own.

This doc surveys the landscape, groups projects by what they would actually
replace in secretgate, and flags which ideas are worth copying.

## Current pain points (what we're trying to fix)

Taken from a quick codebase sweep:

1. **Redaction breaks payload integrity.** `secrets/redactor.py` does raw
   `text.replace()` on the serialized JSON, so nested objects can be corrupted
   and repeated occurrences are re-scanned. For git packfiles the redactor
   gives up entirely and blocks (`scan.py:104-110`).
2. **Hand-rolled HTTP/2.** `h2_handler.py` recently lost data on flow-control
   window exhaustion (#63). Every stream-management bug we write is one a
   battle-tested proxy already has covered.
3. **WebSockets are invisible.** `forward.py:411-456` switches to raw
   bidirectional pipe on Upgrade; frame payloads are never scanned. Known
   limitation.
4. **JSON sniffing is fragile.** `proxy.py:49-62` only scans
   `application/json`; `application/vnd.api+json`, charsets other than UTF-8,
   and unparseable JSON all silently bypass the scanner.
5. **Header rewriting via regex.** `forward.py:566-584` rewrites
   `content-length` and chunked encoding with `re.sub`. Edge cases in casing,
   multi-line folding, or chunked trailers break it.
6. **Packfile parser is best-effort.** `packfile.py:92-119` skips delta
   objects entirely, can't parse trees, and caps at 1 MB/10 MB to stay safe.
7. **Hardening has platform gaps.** `harden.py:217-229` only tests Linux with
   `slirp4netns` and is untested on macOS. Firewall rule generators need root
   and can conflict with existing rules.
8. **Lossy decoding.** Both the packfile path and `scan.py:129-132` decode
   with `errors="replace"`, so UTF-8 sequences that round-trip badly can hide
   secrets.

Anything we adopt from the alternatives should address at least a handful of
these.

## Categories

### 1. General-purpose MITM HTTPS proxies (replace `forward.py` + `certs.py`)

| Project | Lang | License | Protocols | Fit |
|---|---|---|---|---|
| [mitmproxy](https://github.com/mitmproxy/mitmproxy) | Python | MIT | HTTP/1, H2, H3, QUIC, WebSocket, TCP, UDP, SOCKS5, DNS | **Strong fit.** Python addons get `request`/`response`/`websocket_message` events; body mutation is a first-class API. |
| [Martian](https://github.com/google/martian) | Go | Apache-2.0 | HTTP/1, HTTPS | Good HTTP/1 proxy with JSON-configurable modifiers. No H2/WS. Would force a Go rewrite. |
| [goproxy (elazarl)](https://github.com/elazarl/goproxy) | Go | BSD-3 | HTTP/1, HTTPS | Mature but H2/WS support is weak. |
| [gomitmproxy (AdGuard)](https://github.com/AdguardTeam/gomitmproxy) | Go | Apache-2.0 | HTTP/1, HTTPS | Used in AdGuard Home; simpler than Martian. |

**mitmproxy is the obvious candidate.** It's Python (same stack as
secretgate), ships HTTP/1.1, HTTP/2, HTTP/3, and WebSocket support, handles
CONNECT tunnels and per-domain certs, and the
[addon event loop](https://docs.mitmproxy.org/stable/addons/events/) gives us
exactly the hook points we need (`request`, `response`, `websocket_message`,
`tcp_message`). A `SecretRedactionAddon` would be ~100 lines and would
immediately fix pain points #2, #3, #4, and #5.

The cost: mitmproxy is a ~15 MB dependency with its own CA management. We'd
trade `forward.py`, `h2_handler.py`, `certs.py`, and a chunk of `scan.py` for
an addon that runs inside `mitmdump`. The `wrap`/`harden`/`cli serve`
ergonomics are unaffected — we just embed mitmproxy programmatically via
`mitmproxy.tools.main.mitmdump` or the `Master` API.

**Note for ContextIO-style tools:** ContextIO uses a clever two-track approach —
base-URL swap for tools that respect `ANTHROPIC_BASE_URL`, and mitmproxy as a
fallback for tools that don't. That's exactly what secretgate already does
conceptually (reverse proxy + forward proxy), and is probably the cleanest
split.

### 2. LLM-aware DLP proxies (overlap with secretgate's reverse proxy mode)

These projects are closest to secretgate's actual product: sit between a
coding agent and `api.anthropic.com` / `api.openai.com`, redact secrets.

| Project | Lang | License | Reversible? | Streaming | Notes |
|---|---|---|---|---|---|
| [OpenGuard](https://github.com/Jitera-Labs/openguard) | Python | MIT | No | Yes | Drop-in proxy on `localhost:23294/v1`. Supports `/v1/chat/completions` **and** `/v1/messages` (native Anthropic). YAML policy, `pii_filter`, `keyword_filter`, `llm_input_inspect`. Closest architectural match. |
| [LiteLLM](https://github.com/BerriAI/litellm) | Python | MIT | N/A | Yes | Full AI gateway; Presidio guardrail hook for PII masking. Heavy for our use case. |
| [LLM Guard](https://github.com/protectai/llm-guard) | Python | MIT | Partial (Anonymize via Presidio) | Via API | Library of 15 input + 20 output scanners. **Not a proxy** — wraps a scanner pipeline. Usable as a pluggable scanner backend. |
| [PasteGuard](https://github.com/sgasser/pasteguard) | TypeScript / Bun | Apache-2.0 | No ("you see originals, AI sees placeholders") | Yes | Uses Presidio for 30+ entity types; OpenAI + Anthropic endpoints. |
| [ContextIO](https://github.com/larsderidder/contextio) | TypeScript | MIT | **Yes** | Yes | Reversible `[EMAIL_1]`-style placeholders across Anthropic/OpenAI/Gemini. Base URL swap + mitmproxy fallback. Zero npm deps in core. |
| [Rehydra SDK](https://github.com/rehydra-ai/rehydra-sdk) | TypeScript | MIT | **Yes (AES-256-GCM)** | Yes | Regex + on-device ONNX NER (~280 MB). Consistent placeholders per session; rehydrates tool-call args before local execution. Has CLI proxy and OpenCode plugin. |
| [Portkey Gateway](https://github.com/Portkey-ai/gateway) | TypeScript | MIT | N/A | Yes | Full AI gateway with 50+ guardrails; routes to 200+ LLMs. Overkill but shows the commercial-grade architecture. |

**Worth copying:**

- **Reversible redaction** (ContextIO, Rehydra). Our `REDACTED<slug:hash12>`
  placeholders are deterministic but not reversible. For tool-call arguments
  the LLM generates (e.g. "run `aws s3 cp ... --profile REDACTED<aws:abc>`"),
  the agent actually needs the real value to execute locally. Rehydra's
  approach — encrypt original with AES-GCM, restore on the client side before
  local execution — fixes a real usability hole.
- **Native `/v1/messages` (Anthropic) routing** (OpenGuard). We already speak
  Anthropic, but not as a first-class route; OpenGuard shows a clean way to
  expose both `/v1/chat/completions` and `/v1/messages` from one process.
- **YAML policy files** (OpenGuard). Our config is env-var + Click flags. A
  YAML policy with per-endpoint guards and regex/entity toggles is easier for
  users to reason about than CLI flags.

**Not worth copying:**

- LLM Guard's full scanner pipeline — too much surface area (15 input + 20
  output scanners) and Presidio-heavy. We can cherry-pick individual scanners
  via their API instead.
- LiteLLM's full gateway — it's a multi-provider router, not a DLP tool.

### 3. Enterprise-grade HTTP proxies with external processing

| Project | Lang | License | Hook mechanism | Fit |
|---|---|---|---|---|
| [Envoy + ext_proc](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter) | C++ | Apache-2.0 | gRPC external service for header/body mutation | Overkill for a local dev tool. Interesting architecturally. |
| [Squid + ICAP](https://wiki.squid-cache.org/Features/ICAP) | C++ | GPL-2.0 | ICAP REQMOD/RESPMOD | Legacy enterprise DLP pattern (Symantec/Forcepoint use it). Complex; requires running Squid + an ICAP server. |
| [APISIX AI Gateway](https://apisix.apache.org/ai-gateway/) | Lua (OpenResty) | Apache-2.0 | Plugin system | Full API gateway; too heavy. |

Envoy's `ext_proc` filter is architecturally elegant: Envoy handles all the
HTTP nastiness, and a sidecar gRPC service does body mutation. If secretgate
were deployed inside a service mesh this would be the right answer. For
standalone CLI usage it's not.

One useful finding from Envoy's docs: **when body mutation is enabled,
`ext_proc` always strips `content-length` and lets the proxy re-emit it.** We
should do the same — the current regex-based header rewriter in `forward.py`
is brittle exactly because we try to preserve the original header.

### 4. Process-level outbound firewalls / sandboxes (replace `harden.py`)

| Project | Platform | Mechanism | Fit |
|---|---|---|---|
| [Bubblewrap](https://github.com/containers/bubblewrap) | Linux | user + net namespaces, seccomp | **Strong fit.** Used by Claude Code's own `/sandbox`. No root needed. |
| [Firejail](https://github.com/netblue30/firejail) | Linux | namespaces + seccomp, higher-level profiles | Easier configuration than bubblewrap but has historical SUID concerns. |
| [slirp4netns](https://github.com/rootless-containers/slirp4netns) | Linux | unprivileged user-mode networking for namespaces | Already used by `harden.py` on WSL2. |
| [sandbox-exec (Seatbelt)](https://developer.apple.com/documentation/security/app_sandbox) | macOS | SBPL policy | Already used by `harden.py` on macOS (untested). |
| [OpenSnitch](https://github.com/evilsocket/opensnitch) | Linux | nftables + user prompt | Interactive; not suitable for headless wrap. |
| [Firejail profiles for Claude Code](https://github.com/CaptainMcCrank/SandboxedClaudeCode) | Linux/macOS | bwrap / firejail / Apple Container | Worth cloning as a reference for how to wrap an LLM CLI; they share the network namespace and let proxy allowlisting do the egress filtering. |
| [Claude Code `/sandbox`](https://code.claude.com/docs/en/sandboxing) | macOS/Linux | Seatbelt + bubblewrap + localhost proxy allowlist | **The best reference.** Well-behaved HTTP clients go through a localhost proxy that returns `CONNECT 403` for denied domains. Exactly our model. |

**Takeaway:** Claude Code's sandbox architecture is the same shape as
secretgate (sandbox → localhost proxy → allowlist), and it's already
productized across macOS and Linux. We should read their docs and copy the
allowlist-with-`CONNECT 403`-denied pattern directly. This fixes pain points
#7 and gives us parity with the reference implementation coding agents
already integrate with.

### 5. Git secret scanning (replace the packfile path in `packfile.py`)

| Project | Lang | License | Approach | Fit |
|---|---|---|---|---|
| [gitleaks](https://github.com/gitleaks/gitleaks) | Go | MIT | `git log -p` over patches; regex rules | Proven pre-commit/pre-receive tool. Does not parse packfiles directly. |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) | Go | AGPL-3.0 | Scans repos, S3, Docker, logs; verifies live credentials | Deeper than gitleaks but AGPL limits adoption. |
| [padok-team/git-secret-scanner](https://github.com/padok-team/git-secret-scanner) | Go | Apache-2.0 | Wraps both gitleaks and trufflehog | Useful as prior art; not a library. |

**Key insight:** gitleaks doesn't parse packfiles either — it runs
`git log -p` to get patches. That approach only works server-side on a
checked-out repo, not in-flight during `git push`. **secretgate's packfile
parser is actually more ambitious than the standard tools** because it scans
live push traffic. That's a moat, but also why it's harder: there's no
off-the-shelf library to steal.

The realistic options for #6 (packfile parsing) are:

- **Use [dulwich](https://github.com/jelmer/dulwich)** (pure-Python Git) for
  packfile parsing instead of our hand-rolled parser. It handles delta
  resolution, so we'd no longer need to skip delta objects, and it's
  maintained.
- **Keep block-mode only for `git push`**, and document it. Redacting packfile
  contents would require recomputing SHA-1/SHA-256 object IDs and delta
  bases, which nobody's library does for mid-flight push traffic. Block is
  honest and safe.

## What to actually do

Ordered by effort-to-impact ratio, small-to-large:

### Quick wins (no dependency changes)

1. **Steal mitmproxy's "drop `content-length` on mutation" rule.** When
   redaction changes body length, strip `content-length` and force chunked.
   Kills pain point #5 with ~20 lines in `forward.py`.
2. **Widen the JSON sniff.** Match `application/*json*` and parse whenever
   the body decodes as JSON, not just when the MIME string equals
   `application/json`. Fixes pain point #4.
3. **Document `git push` as block-only** rather than half-broken redact. Fixes
   user confusion around pain point #6.

### Medium wins (small code additions)

4. **Replace hand-rolled packfile parser with dulwich.** Removes the
   delta-skip limitation and the 1 MB/10 MB safety caps. One new dep,
   ~150 lines deleted from `packfile.py`.
5. **Adopt the Claude Code `/sandbox` allowlist-with-`CONNECT 403` pattern**
   for `secretgate wrap --harden`. We already have the proxy; we just need
   to return `403` cleanly for denied domains and document the behavior the
   same way Anthropic does. Fixes pain point #7.
6. **Add reversible placeholders** (optional mode). For values sourced from
   `.env` (known-value scanning already does the detection), store an
   encrypted original and restore it on tool-call arguments before local
   execution. Copy the Rehydra approach: AES-256-GCM, per-session key. This
   is the single biggest UX improvement on the table.

### Larger bet

7. **Embed mitmproxy as the forward-proxy engine.** Delete `forward.py`,
   `h2_handler.py`, and most of `certs.py`. Keep `scan.py`/`steps.py` and
   ship them as a mitmproxy addon. Pros: WebSocket scanning comes for free;
   HTTP/2 flow control becomes someone else's problem; HTTP/3 becomes a
   possibility. Cons: a ~15 MB dep and a bigger CA-trust story (mitmproxy
   has its own `~/.mitmproxy/` CA, we'd want to bridge to `~/.secretgate/`).

### Not recommended

- **Envoy/Squid/APISIX:** far too heavy for a local CLI tool, and user
  install burden would be unacceptable.
- **Go rewrite (Martian, goproxy):** the ecosystem fit is worse and we'd
  lose the Python scanner code.
- **Switch to LLM Guard as the scanner:** its scanner pipeline is too
  opinionated. We can borrow individual ideas (entity-based anonymization)
  without adopting the framework.

## Reference implementations worth reading end-to-end

If we only read three projects' source, these are the ones that would move
the needle the most:

1. **[ContextIO](https://github.com/larsderidder/contextio)** — closest
   architectural twin. Reversible placeholders, dual base-URL/mitmproxy
   strategy, policy JSON. TypeScript but the design translates cleanly.
2. **[OpenGuard](https://github.com/Jitera-Labs/openguard)** — Python, MIT,
   supports native `/v1/messages`, YAML policy. Probably the codebase we'd
   feel most at home in.
3. **[Claude Code sandbox docs](https://code.claude.com/docs/en/sandboxing)
   + [SandboxedClaudeCode](https://github.com/CaptainMcCrank/SandboxedClaudeCode)** —
   the reference for running a coding agent inside a sandbox that routes all
   egress through a localhost allowlist proxy. Directly applicable to
   `harden.py` and `wrap`.

## Sources

- [mitmproxy docs — concepts: modes](https://docs.mitmproxy.org/stable/concepts/modes/)
- [mitmproxy GitHub](https://github.com/mitmproxy/mitmproxy)
- [Envoy ext_proc filter docs](https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_filters/ext_proc_filter)
- [LiteLLM Presidio guardrails](https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2)
- [LLM Guard (Protect AI)](https://github.com/protectai/llm-guard)
- [OpenGuard — openguard.sh](https://openguard.sh/)
- [PasteGuard](https://github.com/sgasser/pasteguard)
- [ContextIO](https://github.com/larsderidder/contextio)
- [Rehydra SDK](https://github.com/rehydra-ai/rehydra-sdk)
- [Google Martian](https://github.com/google/martian)
- [AdGuard gomitmproxy](https://github.com/AdguardTeam/gomitmproxy)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [trufflehog](https://github.com/trufflesecurity/trufflehog)
- [Firejail](https://github.com/netblue30/firejail)
- [SandboxedClaudeCode](https://github.com/CaptainMcCrank/SandboxedClaudeCode)
- [Anthropic — Claude Code sandboxing docs](https://code.claude.com/docs/en/sandboxing)
- [Squid ICAP feature docs](https://wiki.squid-cache.org/Features/ICAP)
- [APISIX AI Gateway](https://apisix.apache.org/ai-gateway/)
- [Portkey Gateway](https://github.com/Portkey-ai/gateway)
