# Hardening: Preventing Proxy Bypass

By default, secretgate uses the `https_proxy` environment variable to route
traffic through the forward proxy. This is cooperative — a determined AI
tool could bypass it by unsetting the env var. This guide covers layered
defenses to prevent that.

## Quick Start

```bash
# Generate and apply all hardening in one go:
eval $(secretgate harden env)           # Lock proxy env vars
secretgate harden iptables | sudo bash  # Block direct LLM connections
secretgate harden hooks -o ~/.claude/settings.json  # Claude Code hooks
```

## Layer 1: Firewall Rules (Strongest)

Block direct outbound connections to LLM API endpoints at the network level.
Even if the AI tool unsets every env var, TCP connections get dropped.

```bash
# Generate and apply iptables rules
secretgate harden iptables | sudo bash

# Add custom domains
secretgate harden iptables --extra-domain api.custom-llm.com | sudo bash

# Remove rules when done
secretgate harden iptables --remove | sudo bash
```

**Blocked domains** (built-in):
- api.anthropic.com
- api.openai.com
- generativelanguage.googleapis.com
- api.mistral.ai
- api.cohere.com
- api.together.xyz
- api.fireworks.ai
- api.groq.com
- openrouter.ai

## Layer 2: Readonly Environment Variables

Lock proxy env vars so they can't be unset or reassigned in the current shell:

```bash
eval $(secretgate harden env)
```

This uses `readonly` in bash/zsh. Subprocesses *can* start a fresh shell to
escape this, so combine with firewall rules for real enforcement.

**Fish shell:**
```fish
secretgate harden env --shell fish | source
```

Note: Fish doesn't support `readonly` — env vars can be overridden.

## Layer 3: Claude Code Hooks

Add pre-tool-call hooks that reject commands attempting to modify proxy vars:

```bash
secretgate harden hooks -o ~/.claude/settings.json
```

This blocks commands containing patterns like `unset https_proxy` or
`export ANTHROPIC_BASE_URL=...`. It's bypassable (encoded commands, Python
subprocess, etc.) but creates an audit trail.

## Layer 4: Container Isolation

Run the AI tool in a Docker container with network restrictions:

```bash
docker run --rm -it \
  --network=host \
  -e https_proxy=http://host.docker.internal:8083 \
  your-coding-image
```

Or use network namespaces for stronger isolation:

```bash
unshare --net -- bash -c '
  ip link set lo up
  socat TCP-LISTEN:8083,fork TCP:host-proxy:8083 &
  claude
'
```

## Recommendation

Use **Layer 1 (iptables) + Layer 3 (hooks)** for the best balance of security
and usability. The firewall is the real enforcement boundary; hooks provide
defense-in-depth and user-visible feedback.

For maximum security (e.g., running untrusted AI tools), add Layer 4
(container/namespace isolation).
