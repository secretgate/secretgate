# Hardening secretgate against proxy bypass

By default, secretgate relies on environment variables (`https_proxy`, etc.)
to route traffic through the proxy. This is cooperative — if the AI tool
removes or overrides those variables, traffic bypasses secretgate entirely.

This guide covers layered defenses to prevent bypass, from strongest to
simplest.

## 1. Firewall rules (strongest — network-level enforcement)

Block direct outbound HTTPS connections from the user running the AI tool,
forcing all traffic through the proxy. The AI tool cannot bypass this without
root access.

### Linux (iptables)

```bash
# Get the UID of the user running the AI tool
AI_USER_UID=$(id -u)

# Allow traffic to the local proxy
iptables -A OUTPUT -o lo -j ACCEPT

# Block direct HTTPS from the AI tool user
iptables -A OUTPUT -m owner --uid-owner $AI_USER_UID \
  -p tcp --dport 443 -j REJECT --reject-with tcp-reset

# Allow the proxy itself (runs as the same user, connects to upstream)
# Option A: If secretgate runs as a different user, allow that user
# Option B: Use a mark-based rule to exempt proxy connections
```

### macOS (pf)

macOS uses `pf` (packet filter) instead of iptables:

```bash
# /etc/pf.anchors/secretgate
# Block direct HTTPS from the current user, allow proxy
block out proto tcp from any to any port 443 user $USER
pass out proto tcp from any to 127.0.0.1 port 8083 user $USER
```

Load with:
```bash
sudo pfctl -a secretgate -f /etc/pf.anchors/secretgate
sudo pfctl -e
```

## 2. Transparent proxy (no env vars needed)

Use iptables REDIRECT to transparently route all port-443 traffic through
secretgate. The AI tool doesn't know a proxy exists — there are no env vars
to unset.

```bash
# Redirect all outbound HTTPS to secretgate's forward proxy
iptables -t nat -A OUTPUT -p tcp --dport 443 \
  -m owner --uid-owner $AI_USER_UID \
  -j REDIRECT --to-port 8083
```

> **Note**: Transparent proxy mode requires secretgate to handle connections
> where the client doesn't send a CONNECT request. This is tracked for future
> implementation.

## 3. Container / namespace isolation

Run the AI tool in a restricted network namespace or container where only the
proxy is reachable:

### Docker

```bash
docker run --rm -it \
  --network=secretgate-net \
  -e https_proxy=http://host.docker.internal:8083 \
  -e SSL_CERT_FILE=/certs/ca.pem \
  -v ~/.secretgate/certs/ca.pem:/certs/ca.pem:ro \
  your-ai-tool-image
```

### Network namespace (Linux)

```bash
# Create isolated namespace with only proxy access
unshare --net -- bash -c '
  ip link set lo up
  socat TCP-LISTEN:8083,fork TCP:$(ip route get 1 | awk "{print \$7}"):8083 &
  export https_proxy=http://localhost:8083
  your-ai-tool
'
```

## 4. Claude Code hooks (defense-in-depth)

Add a pre-tool hook that blocks commands attempting to modify proxy variables:

```json
{
  "hooks": {
    "pre_tool_call": [
      {
        "matcher": "Bash",
        "command": "echo \"$CLAUDE_TOOL_INPUT\" | grep -qiE '(unset|export|set)\\s.*(https?_proxy|ANTHROPIC_BASE_URL|no_proxy|SSL_CERT_FILE|NODE_EXTRA_CA_CERTS)' && echo 'BLOCKED: proxy env modification detected' >&2 && exit 1 || exit 0"
      }
    ]
  }
}
```

> **Limitation**: This is bypassable (the AI can encode commands, use Python
> subprocess, etc.) but raises the bar and creates an audit trail.

## 5. Shell-level readonly variables

The simplest (but weakest) defense — mark proxy variables as readonly:

```bash
export https_proxy=http://localhost:8083
export HTTPS_PROXY=http://localhost:8083
export SSL_CERT_FILE=~/.secretgate/certs/ca-bundle.pem
readonly https_proxy HTTPS_PROXY SSL_CERT_FILE
```

> **Limitation**: A subprocess can start a fresh shell without these
> restrictions. Only effective within the current shell session.

## Recommended setup

Combine multiple layers:

1. **Firewall rules** (iptables/pf) as the hard network-level enforcement
2. **Claude Code hooks** as a soft guardrail with audit trail
3. **Readonly env vars** as a trivial speed bump

The firewall is the actual security boundary — everything else is
defense-in-depth.

## Related

- [Issue #33](https://github.com/secretgate/secretgate/issues/33) — tracking issue
- `secretgate wrap` — the standard (cooperative) setup
