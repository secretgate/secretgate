# Hardening: Preventing Proxy Bypass

By default, secretgate relies on the `https_proxy` environment variable, which
cooperative tools respect. However, an adversarial or misconfigured AI tool
could unset or override these variables, bypassing the proxy entirely.

This guide covers layered defenses to prevent bypass, from strongest to
simplest.

## 1. Firewall Rules (Strongest — Network-Level)

Block direct outbound HTTPS connections, forcing all traffic through the proxy.
The `secretgate harden` command generates platform-specific rules automatically:

```bash
# Auto-detect platform and print rules
secretgate harden

# Specify the tool explicitly
secretgate harden --tool iptables
secretgate harden --tool nftables
secretgate harden --tool pf
secretgate harden --tool windows

# Only block specific domains
secretgate harden -d api.anthropic.com -d api.openai.com

# Restrict to a specific user
secretgate harden -u developer

# Write to a file
secretgate harden -o firewall.sh

# Generate removal commands
secretgate harden --remove
```

Review the generated rules, then apply with appropriate privileges
(e.g., `sudo bash firewall.sh` on Linux).

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

**Firewall rules** (`secretgate harden`) are the primary enforcement — they
block direct HTTPS at the kernel level, which the AI tool cannot bypass
without root. Secretgate itself provides all the observability you need:
scanning, redaction, blocking, and audit logging of every request.

The other layers (readonly vars, hooks, containers) are optional
defense-in-depth. They can help with user feedback and audit trails but
are not required when firewall rules are active.

## Related

- [GitHub Issue #33](https://github.com/secretgate/secretgate/issues/33) — Tracking issue for hardening
- `secretgate wrap` — Already sets proxy env vars automatically
- `secretgate harden` — Generate firewall rules for your platform
