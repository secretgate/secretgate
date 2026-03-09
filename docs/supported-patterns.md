# Supported Secret Patterns

secretgate detects secrets using three methods:

1. **Regex patterns** (~75 patterns in `signatures.yaml`)
2. **Shannon entropy analysis** for high-entropy values in key=value assignments
3. **Optional [detect-secrets](https://github.com/Yelp/detect-secrets) integration** (23 additional regex plugins)

## Pattern Coverage

### Cloud Providers

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| AWS | Access Key | `AKIA...` (20 chars) |
| AWS | Secret Key | `aws_secret_access_key = ...` (40 chars) |
| AWS | MWS Token | `amzn.mws.` + UUID |
| GCP | API Key | `AIza...` (39 chars) |
| GCP | Service Account | `"type": "service_account"` |
| Azure | Connection String | `DefaultEndpointsProtocol=https;AccountName=...` |
| DigitalOcean | Access Token | `dop_v1_` + 64 hex |
| DigitalOcean | OAuth Token | `doo_v1_` + 64 hex |
| Alibaba Cloud | Access Key ID | `LTAI` + 20 chars |

### AI / ML Services

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| OpenAI | API Key | `sk-...T3BlbkFJ...` |
| OpenAI | Project Key | `sk-proj-...` (80+ chars) |
| Anthropic | API Key | `sk-ant-...` (80+ chars) |
| Hugging Face | Access Token | `hf_` + 34 alpha |
| Hugging Face | Org API Token | `api_org_` + 34 alpha |
| Replicate | API Token | `r8_` + 36 alnum |
| Perplexity | API Key | `pplx-` + 48 alnum |

### Source Control

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| GitHub | Personal Access Token | `ghp_` + 36 alnum |
| GitHub | OAuth Token | `gho_` + 36 alnum |
| GitHub | Fine-grained PAT | `github_pat_` + 82 chars |
| GitHub | App Token | `ghs_` / `ghr_` + 36 alnum |
| GitLab | Personal Access Token | `glpat-` + 20 chars |
| GitLab | Pipeline Token | `glptt-` + 40 hex |
| GitLab | Runner Token | `glrt-` + 20 chars |

### Messaging / Communication

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| Slack | Bot Token | `xoxb-...` |
| Slack | User Token | `xoxp-...` |
| Slack | App-Level Token | `xapp-...` |
| Slack | Webhook URL | `https://hooks.slack.com/services/...` |
| Discord | Bot Token | `[MNO]...` (3-part dot-separated) |
| Telegram | Bot API Token | `123456:AA...` (numeric:alpha) |
| Microsoft Teams | Webhook URL | `https://*.webhook.office.com/...` |

### Payments / Finance

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| Stripe | Secret Key | `sk_live_` + 24+ alnum |
| Stripe | Publishable Key | `pk_live_` + 24+ alnum |
| Stripe | Restricted Key | `rk_live_` + 24+ alnum |
| Square | Access Token | `sq0atp-` + 22-60 chars |
| Plaid | Access Token | `access-{env}-` + UUID |
| Flutterwave | Secret Key | `FLWSECK_TEST-...` |

### DevOps / CI/CD

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| Vercel | Personal Token | `vcp_` + 40+ alnum |
| Vercel | Integration Token | `vci_` + 40+ alnum |
| npm | Access Token | `npm_` + 36 alnum |
| PyPI | Upload Token | `pypi-AgEIcHlwaS5vcmc...` |
| RubyGems | API Token | `rubygems_` + 48 hex |
| Postman | API Token | `PMAK-` + hex |
| Doppler | API Token | `dp.pt.` + 43 alnum |
| Buildkite | Agent Token | `bkua_` + 40 hex |
| Octopus Deploy | API Key | `API-` + 26 alnum |

### Infrastructure / Hosting

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| HashiCorp Vault | Service Token | `hvs.` + 90-120 chars |
| HashiCorp Vault | Batch Token | `hvb.` + 138-300 chars |
| HashiCorp Terraform | API Token | `*.atlasv1.*` |
| Pulumi | API Token | `pul-` + 40 hex |
| Fly.io | Access Token | `fo1_` + 43 chars |
| Databricks | API Token | `dapi` + 32 hex |
| PlanetScale | API Token | `pscale_tkn_` + 32-64 chars |
| PlanetScale | Password | `pscale_pw_` + 32-64 chars |
| Supabase | Service Key | `sbp_` + 40 hex |
| Heroku | API Key | `heroku...` + UUID |

### Monitoring / Observability

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| Grafana | Cloud API Token | `glc_` + base64 |
| Grafana | Service Account | `glsa_` + 32 alnum + `_` + 8 hex |
| New Relic | User API Key | `NRAK-` + 27 alnum |
| New Relic | Insert Key | `NRII-` + 32 chars |
| New Relic | Browser API Token | `NRJS-` + 19 hex |
| Sentry | Org Token | `sntrys_eyJpYXQiO...` |
| Sentry | User Token | `sntryu_` + 64 hex |
| Dynatrace | API Token | `dt0c01.` + 24 alnum + `.` + 64 alnum |

### Email / Marketing

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| SendGrid | API Key | `SG.` + base64 |
| Mailchimp | API Key | 32 hex + `-us{1,2}` |
| Mailgun | Private API Token | `key-` + 32 hex |
| Mailgun | Public Key | `pubkey-` + 32 hex |
| Sendinblue/Brevo | API Token | `xkeysib-` + 64 hex + `-` + 16 alnum |

### SaaS / Productivity

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| Shopify | Access Token | `shpat_` + 32 hex |
| Shopify | Custom App Token | `shpca_` + 32 hex |
| Shopify | Private App Token | `shppa_` + 32 hex |
| Shopify | Shared Secret | `shpss_` + 32 hex |
| Atlassian | API Token | `ATATT3` + 186 chars |
| Notion | API Token | `ntn_` + 46 chars |
| Linear | API Key | `lin_api_` + 40 alnum |
| Airtable | PAT | `pat` + 14 alnum + `.` + 64 hex |
| Typeform | API Token | `tfp_` + 59 chars |

### Telephony

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| Twilio | API Key | `SK` + 32 hex |
| Twilio | Account SID | `AC` + 34 alnum |

### Security / Identity

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| 1Password | Service Account Token | `ops_eyJ` + 250+ base64 |
| Age | Secret Key | `AGE-SECRET-KEY-1` + 58 bech32 |

### Artifact Registries

| Service | Pattern | Prefix / Format |
|---------|---------|-----------------|
| Artifactory | API Key | `AKCp` + 69 alnum |
| Artifactory | Reference Token | `cmVmd` + 59 alnum |

### Database Connection Strings

| Type | Format |
|------|--------|
| MongoDB | `mongodb://...` or `mongodb+srv://...` |
| PostgreSQL | `postgresql://...` or `postgres://...` |
| MySQL | `mysql://...` |
| Redis | `redis://...` or `rediss://...` |

### Generic Patterns

| Pattern | Description |
|---------|-------------|
| Private Key | `-----BEGIN ... PRIVATE KEY-----` (RSA, EC, DSA, OPENSSH) |
| JWT Token | `eyJ...` (3-part base64url dot-separated) |
| Bearer Token | `Bearer ...` / `bearer ...` |
| Basic Auth | `Basic ...` (20+ base64 chars) |
| Password in URL | `://user:password@host` |

### Entropy Detection

In addition to regex patterns, secretgate uses Shannon entropy analysis to detect high-entropy values in `KEY=VALUE` assignments (threshold: 4.0 bits/char). This catches secrets that don't match any known pattern but have suspiciously random values.

Entropy scanning can be disabled with `--no-entropy` to reduce false positives.

## Adding Custom Patterns

Drop patterns in `~/.secretgate/signatures.yaml` or pass `--signatures /path/to/file.yaml`:

```yaml
- MyCompany:
    - Internal API Key: "myco_[a-zA-Z0-9]{32}"
    - Database URL: "postgres://.*@prod\\.mycompany\\.com"
```

## Sources

Pattern formats were gathered from:
- [GitHub Secret Scanning](https://docs.github.com/en/code-security/secret-scanning/introduction/supported-secret-scanning-patterns)
- [gitleaks](https://github.com/gitleaks/gitleaks)
- [detect-secrets](https://github.com/Yelp/detect-secrets)
- [secrets-patterns-db](https://github.com/mazen160/secrets-patterns-db)
- Official documentation of each service
