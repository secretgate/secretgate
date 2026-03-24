# Hardening: Preventing Proxy Bypass

By default, secretgate relies on the `https_proxy` environment variable, which
cooperative tools respect. However, an adversarial or misconfigured AI tool
could unset or override these variables, bypassing the proxy entirely.

This guide covers layered defenses to prevent bypass, from strongest to
simplest.

## 1. Firewall Rules (Strongest — Network-Level)

Block direct outbound HTTPS connections, forcing all traffic through the proxy:

### Linux (iptables)

```bash
# Allow traffic to the local proxy
iptables -A OUTPUT -o lo -j ACCEPT

# Block direct connections to LLM API endpoints on port 443
iptables -A OUTPUT -p tcp --dport 443 -m owner --uid-owner $(id -u) -j DROP
```

To be more targeted, block only specific LLM API IPs:

```bash
# Resolve and block specific domains
for domain in api.anthropic.com api.openai.com api.mistral.ai; do
    for ip in $(dig +short "$domain"); do
        iptables -A OUTPUT -p tcp --dport 443 -d "$ip" -j DROP
    done
done
```

### macOS (pf)

```bash
# /etc/pf.anchors/secretgate
block out proto tcp from any to any port 443 user $(whoami)
pass out proto tcp from any to 127.0.0.1 port 8083

# Load:
sudo pfctl -a secretgate -f /etc/pf.anchors/secretgate
sudo pfctl -e
```

The AI tool cannot bypass this — it doesn't have root access to modify
firewall rules.

## 2. Transparent Proxy (No Env Vars Needed)

Use iptables NAT rules to redirect all port-443 traffic through secretgate,
removing any reliance on `https_proxy`:

```bash
# Redirect all outbound HTTPS traffic to the forward proxy
iptables -t nat -A OUTPUT -p tcp --dport 443 \
    -m owner --uid-owner $(id -u) \
    -j REDIRECT --to-port 8083
```

The tool doesn't even know a proxy exists — there are no env vars to unset.

## 3. Container / Namespace Isolation

Run the AI tool in a restricted network namespace:

```bash
# Simple network namespace
unshare --net -- bash -c '
    ip link set lo up
    socat TCP-LISTEN:8083,fork TCP:$(hostname -I | awk "{print \$1}"):8083 &
    export https_proxy=http://localhost:8083
    claude
'
```

Or use Docker:

```bash
docker run --rm -it \
    --network=none \
    -v /path/to/project:/workspace \
    your-coding-image \
    bash -c 'socat TCP-LISTEN:8083,fork TCP:host.docker.internal:8083 & \
             https_proxy=http://localhost:8083 claude'
```

## 4. Readonly Environment Variables

A simple first step — mark proxy variables as readonly in bash:

```bash
export https_proxy=http://localhost:8083
export HTTPS_PROXY=http://localhost:8083
readonly https_proxy HTTPS_PROXY

export http_proxy=http://localhost:8083
export HTTP_PROXY=http://localhost:8083
readonly http_proxy HTTP_PROXY
```

**Limitation:** A subprocess can start a fresh shell that doesn't inherit
`readonly`. This is defense-in-depth, not a hard boundary.

## 5. Claude Code Hooks (Defense-in-Depth)

If using Claude Code, add a pre-tool hook to detect proxy variable manipulation:

```json
{
  "hooks": {
    "pre_tool_call": [
      {
        "matcher": "Bash",
        "command": "echo \"$CLAUDE_TOOL_INPUT\" | grep -qiE '(unset|export)\\s*.*(https?_proxy|ANTHROPIC_BASE_URL|no_proxy|SSL_CERT_FILE)' && echo 'BLOCKED: proxy env modification detected' >&2 && exit 1 || exit 0"
      }
    ]
  }
}
```

## Recommended Approach

Layer **firewall rules + readonly env vars + hooks** for defense-in-depth:

1. **Firewall** — hard enforcement the tool cannot bypass
2. **Readonly vars** — catches accidental/naive override attempts
3. **Hooks** — creates an audit trail and catches the easy cases

No single layer is perfect, but combined they make bypass extremely difficult.

## Related

- [GitHub Issue #33](https://github.com/secretgate/secretgate/issues/33) — Tracking issue for hardening
- `secretgate wrap` — Already sets proxy env vars automatically
