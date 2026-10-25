# dnssentry

Audits SPF, DMARC, DKIM, and MX records for a domain on GoDaddy DNS, and can safely write the missing ones.

- **Zero third-party dependencies** — uses only Python's standard library.
- **Modern GoDaddy API** — authenticates using Personal Access Tokens (PAT).
- **Safe & targeted** — uses record-level endpoints (`PUT /records/{type}/{name}`) and dry-run by default.

---

## Setup

1. Copy the environment template:
```bash
cp env.example .env
```

2. Generate a **Personal Access Token (PAT)** from the [GoDaddy Developer Platform](https://developer.godaddy.com/en/docs/api-users) with permissions to read and update domain DNS records.

3. Edit `.env` and fill in `GODADDY_PAT`:
```env
GODADDY_PAT=your_personal_access_token_here
```

*(You can also pass `--token <PAT>` directly via the CLI).*

---

## Usage

You can run `dnssentry` directly or as an installed CLI:
- Run directly: `python -m dnssentry <command>`
- Or install into your Python environment (`pip install .`) and use: `dnssentry <command>`

### 1. Audit records (dry-run / read-only)

```bash
python -m dnssentry check example.com
```

> **Fast Local Caching**: `dnssentry` caches record snapshots locally for 5 minutes. Subsequent `check` or `fix` commands execute in **~2 milliseconds**. To force a live network refresh, pass `--no-cache` (or `--refresh`):
> ```bash
> python -m dnssentry check example.com --no-cache
> ```

### 2. Preview fixes (dry-run)

Preview automatic Microsoft 365 defaults (SPF: `include:spf.protection.outlook.com -all`, DMARC: `p=reject; sp=reject`):

```bash
python -m dnssentry fix example.com
```

To auto-configure Microsoft 365 dual DKIM CNAME records (`selector1` & `selector2`), pass `--tenant <your-tenant>`:

```bash
python -m dnssentry fix example.com --tenant mycompany
```

### 3. Apply changes (interactive confirmation)

```bash
python -m dnssentry fix example.com --tenant mycompany --apply
```

Add `--yes` to skip interactive `[y/N]` confirmation prompts (useful in CI/CD).

---

## Microsoft 365 Defaults & DKIM

`dnssentry` defaults email authentication records according to Microsoft 365 best practices:

- **SPF**: Defaults to `v=spf1 include:spf.protection.outlook.com -all`
- **DMARC**: Defaults to Microsoft's recommended enforcement policy:
  `v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@<domain>;`
- **DKIM (Dual CNAME Rotation)**: Microsoft 365 uses two CNAME records for automatic key rotation. Pass `--tenant <tenant>` (or set `MS_TENANT` in `.env`), and `dnssentry` automatically provisions both:
  - `selector1._domainkey` -> `selector1-<domain-hyphenated>._domainkey.<tenant>.onmicrosoft.com`
  - `selector2._domainkey` -> `selector2-<domain-hyphenated>._domainkey.<tenant>.onmicrosoft.com`

For non-Microsoft providers (Google Workspace, Zoho, etc.), you can supply custom values:
```bash
python -m dnssentry fix example.com \
  --spf-value "v=spf1 include:_spf.google.com ~all" \
  --dkim-selector google \
  --dkim-value "v=DKIM1; k=rsa; p=MIIBIjANBg..." \
  --apply
```

---

## Safety Notes

- **Surgical updates**: Only ever calls `PUT /v1/domains/{domain}/records/{type}/{name}`. Never replaces the entire domain record set, leaving `A`, `AAAA`, and unrelated `TXT` records untouched.
- **Dry-run default**: Nothing is written unless `--apply` is explicitly passed.
- **Strict RFC validation**: Flags multiple SPF records as invalid per [RFC 7208](https://datatracker.ietf.org/doc/html/rfc7208) rather than silently concatenating them.

---

## Project Structure

```text
dnssentry/
├── dnssentry/
│   ├── __init__.py      # Package exports and version metadata
│   ├── __main__.py      # python -m dnssentry entrypoint
│   ├── client.py        # GoDaddy REST API client (PAT authentication)
│   ├── checker.py       # SPF, DMARC, DKIM, MX inspection & fixes
│   └── cli.py           # CLI argument parser, .env loader & routing
├── tests/               # Standard library unittest suite
├── env.example          # Environment variable template
├── pyproject.toml       # Package metadata and CLI console script
└── README.md
```
