"""
DNS record inspection, remediation, and reporting for SPF, DMARC, DKIM, and MX.
"""

import os
import sys
from typing import Any, Dict, List, Optional

# Reconfigure stdout/stderr to UTF-8 on Windows if supported
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if hasattr(sys.stderr, "reconfigure"):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from .client import GoDaddyClient

DEFAULT_SPF_VALUE = "v=spf1 include:spf.protection.outlook.com -all"
DEFAULT_DMARC_POLICY = "reject"


def build_default_dmarc(domain: str, rua: Optional[str] = None) -> str:
    """Build Microsoft 365 recommended DMARC policy (p=reject)."""
    rua_target = rua or f"dmarc@{domain}"
    return f"v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:{rua_target};"


COMMON_DKIM_SELECTORS = [
    "google", "selector1", "selector2",  # Google Workspace / Microsoft 365
    "s1", "s2", "k1", "k2",
    "default", "dkim", "mail",
    "zoho", "zmail",                      # Zoho Mail
    "everlytickey1", "everlytickey2",     # GoDaddy email
    "mandrill", "sendgrid", "pm",         # Transactional senders
]


# --------------------------------------------------------------------------
# Terminal Styling
# --------------------------------------------------------------------------

# Enable ANSI escape sequences on Windows terminals if possible
if sys.platform == "win32":
    try:
        os.system("")
    except Exception:
        pass


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return True


USE_COLOR = _supports_color()


def style(text: str, color: Optional[str] = None, bold: bool = False) -> str:
    """Apply ANSI colors and styles if supported by terminal."""
    if not USE_COLOR:
        return text
    codes = []
    if bold:
        codes.append("1")
    colors = {
        "green": "32",
        "red": "31",
        "yellow": "33",
        "blue": "34",
        "magenta": "35",
        "cyan": "36",
        "gray": "90",
        "bright_green": "92",
        "bright_red": "91",
        "bright_yellow": "93",
        "bright_cyan": "96",
        "white": "97",
    }
    if color in colors:
        codes.append(colors[color])
    if not codes:
        return text
    return f"\033[{';'.join(codes)}m{text}\033[0m"


# --------------------------------------------------------------------------
# Inspection
# --------------------------------------------------------------------------

def check_spf(
    client: GoDaddyClient, domain: str, records: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Check for SPF records on the domain root."""
    if records is None:
        root_txt = client.get_records(domain, "TXT", "@")
    else:
        root_txt = [
            r for r in records
            if r.get("type") == "TXT" and r.get("name") in ("@", domain, "")
        ]

    spf_records = [r for r in root_txt if r.get("data", "").strip().startswith("v=spf1")]
    return {
        "present": len(spf_records) > 0,
        "multiple": len(spf_records) > 1,  # multiple SPF TXT records is invalid per RFC 7208
        "records": spf_records,
        "all_root_txt": root_txt,
    }


def check_dmarc(
    client: GoDaddyClient, domain: str, records: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Check for DMARC records at _dmarc.<domain>."""
    if records is None:
        dmarc_txt = client.get_records(domain, "TXT", "_dmarc")
    else:
        dmarc_txt = [
            r for r in records
            if r.get("type") == "TXT" and r.get("name") in ("_dmarc", f"_dmarc.{domain}")
        ]

    dmarc_records = [r for r in dmarc_txt if r.get("data", "").strip().startswith("v=DMARC1")]
    return {
        "present": len(dmarc_records) > 0,
        "records": dmarc_records,
    }


def check_dkim(
    client: GoDaddyClient,
    domain: str,
    selectors: Optional[List[str]] = None,
    records: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Check for DKIM records under <selector>._domainkey.<domain>."""
    found = {}
    if records is not None:
        # Fast in-memory scan: inspect all records matching *._domainkey
        for r in records:
            r_type = r.get("type")
            if r_type not in ("TXT", "CNAME"):
                continue
            name = r.get("name", "")
            if "._domainkey" in name:
                selector = name.split("._domainkey")[0].split(".")[-1]
                if selectors and selector not in selectors:
                    continue
                if selector not in found:
                    found[selector] = {"TXT": [], "CNAME": []}
                found[selector][r_type].append(r)
    else:
        selectors = selectors or COMMON_DKIM_SELECTORS
        for selector in selectors:
            name = f"{selector}._domainkey"
            txt = client.get_records(domain, "TXT", name)
            cname = client.get_records(domain, "CNAME", name)
            if txt or cname:
                found[selector] = {"TXT": txt, "CNAME": cname}

    return {
        "present": len(found) > 0,
        "selectors_found": found,
    }


def check_mx(
    client: GoDaddyClient, domain: str, records: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """Check for MX records at the domain root."""
    if records is None:
        mx_records = client.get_records(domain, "MX", "@")
    else:
        mx_records = [
            r for r in records
            if r.get("type") == "MX" and r.get("name") in ("@", domain, "")
        ]

    return {
        "present": len(mx_records) > 0,
        "records": mx_records,
    }


# --------------------------------------------------------------------------
# Remediation
# --------------------------------------------------------------------------

def confirm(prompt: str) -> bool:
    """Prompt user for confirmation."""
    answer = input(f"{prompt} [y/N] ").strip().lower()
    return answer in ("y", "yes")


def fix_spf(
    client: GoDaddyClient,
    domain: str,
    spf_value: str,
    ttl: int,
    apply: bool,
    auto_yes: bool,
) -> bool:
    """Write or preview an SPF TXT record at the root."""
    print(f"\n{style('SPF Remediation', 'cyan', bold=True)}")
    print(f'  Target Record: TXT @ = "{spf_value}" (ttl={ttl})')
    if not apply:
        print(f"  {style('DRY RUN ONLY', 'yellow', bold=True)} — Pass --apply to write this change to GoDaddy DNS.")
        return False
    if not auto_yes and not confirm(f"  Write SPF record for {domain}?"):
        print(f"  {style('SKIPPED', 'gray')}")
        return False
    client.put_records(domain, "TXT", "@", [{"data": spf_value, "ttl": ttl}])
    print(f"  {style('✔ Written successfully.', 'green', bold=True)}")
    return True


def fix_dmarc(
    client: GoDaddyClient,
    domain: str,
    dmarc_value: str,
    ttl: int,
    apply: bool,
    auto_yes: bool,
) -> bool:
    """Write or preview a DMARC TXT record at _dmarc."""
    print(f"\n{style('DMARC Remediation', 'cyan', bold=True)}")
    print(f'  Target Record: TXT _dmarc = "{dmarc_value}" (ttl={ttl})')
    if not apply:
        print(f"  {style('DRY RUN ONLY', 'yellow', bold=True)} — Pass --apply to write this change to GoDaddy DNS.")
        return False
    if not auto_yes and not confirm(f"  Write DMARC record for {domain}?"):
        print(f"  {style('SKIPPED', 'gray')}")
        return False
    client.put_records(domain, "TXT", "_dmarc", [{"data": dmarc_value, "ttl": ttl}])
    print(f"  {style('✔ Written successfully.', 'green', bold=True)}")
    return True


def fix_dkim(
    client: GoDaddyClient,
    domain: str,
    selector: str,
    dkim_value: str,
    ttl: int,
    apply: bool,
    auto_yes: bool,
    record_type: str = "TXT",
) -> bool:
    """Write or preview a DKIM TXT or CNAME record at <selector>._domainkey."""
    name = f"{selector}._domainkey"
    print(f"\n{style('DKIM Remediation', 'cyan', bold=True)}")
    print(f'  Target Record: {record_type} {name} = "{dkim_value}" (ttl={ttl})')
    if not apply:
        print(f"  {style('DRY RUN ONLY', 'yellow', bold=True)} — Pass --apply to write this change to GoDaddy DNS.")
        return False
    if not auto_yes and not confirm(f"  Write DKIM record ({selector}) for {domain}?"):
        print(f"  {style('SKIPPED', 'gray')}")
        return False
    client.put_records(domain, record_type, name, [{"data": dkim_value, "ttl": ttl}])
    print(f"  {style('✔ Written successfully.', 'green', bold=True)}")
    return True


def fix_ms_dkim(
    client: GoDaddyClient,
    domain: str,
    tenant: str,
    ttl: int,
    apply: bool,
    auto_yes: bool,
) -> bool:
    """Configure Microsoft 365 DKIM dual CNAME records (selector1 and selector2)."""
    domain_dashed = domain.replace(".", "-")
    tenant_domain = tenant if tenant.endswith(".onmicrosoft.com") else f"{tenant}.onmicrosoft.com"

    target1 = f"selector1-{domain_dashed}._domainkey.{tenant_domain}"
    target2 = f"selector2-{domain_dashed}._domainkey.{tenant_domain}"

    print(f"\n{style('Microsoft 365 DKIM Remediation (Dual CNAME Rotation)', 'cyan', bold=True)}")
    print(f'  Target 1: CNAME selector1._domainkey = "{target1}" (ttl={ttl})')
    print(f'  Target 2: CNAME selector2._domainkey = "{target2}" (ttl={ttl})')

    if not apply:
        print(f"  {style('DRY RUN ONLY', 'yellow', bold=True)} — Pass --apply to write to GoDaddy DNS.")
        return False

    if not auto_yes and not confirm(f"  Write Microsoft 365 DKIM CNAME records for {domain}?"):
        print(f"  {style('SKIPPED', 'gray')}")
        return False

    client.put_records(domain, "CNAME", "selector1._domainkey", [{"data": target1, "ttl": ttl}])
    client.put_records(domain, "CNAME", "selector2._domainkey", [{"data": target2, "ttl": ttl}])
    print(f"  {style('✔ Both Microsoft 365 DKIM CNAME records written successfully.', 'green', bold=True)}")
    return True


# --------------------------------------------------------------------------
# Terminal Reporting
# --------------------------------------------------------------------------

def _parse_dmarc_tags(raw: str) -> Dict[str, str]:
    tags = {}
    for part in raw.split(";"):
        part = part.strip()
        if "=" in part:
            k, _, v = part.partition("=")
            tags[k.strip().lower()] = v.strip()
    return tags


def _parse_spf_policy(raw: str) -> str:
    parts = raw.split()
    for p in reversed(parts):
        if p == "-all":
            return "HardFail (-all) — Strict rejection of unauthorized senders"
        if p == "~all":
            return "SoftFail (~all) — Unauthorized senders accepted but flagged as suspicious"
        if p == "?all":
            return "Neutral (?all) — No policy asserted"
        if p == "+all":
            return "Pass (+all) — INSECURE: Allows any server to send"
    return "Not specified"


def print_report(
    domain: str,
    spf: Dict[str, Any],
    dmarc: Dict[str, Any],
    dkim: Dict[str, Any],
    mx: Dict[str, Any],
) -> None:
    """Print an improvised, polished email-security report."""
    border = "═" * 74
    line = "─" * 74

    print(f"\n{style('╔' + border + '╗', 'cyan')}")
    title = f" DNS Sentry  •  Email Security Audit for {domain}"
    print(f"{style('║', 'cyan')}{style(title.ljust(74), 'white', bold=True)}{style('║', 'cyan')}")
    print(f"{style('╚' + border + '╝', 'cyan')}")

    total_checks = 4
    passed_checks = 0

    # 1. SPF
    print(f"\n{style('● SPF (Sender Policy Framework)', 'bright_cyan', bold=True)}")
    if spf["present"]:
        passed_checks += 1
        for r in spf["records"]:
            data = r.get("data", "").strip()
            print(f"  Status:  {style('✔ CONFIGURED', 'green', bold=True)}")
            print(f"  Record:  {data}")
            policy_desc = _parse_spf_policy(data)
            print(f"  Policy:  {policy_desc}")
        if spf["multiple"]:
            print(f"  {style('▲ WARNING: Multiple SPF records found! RFC 7208 permits only one per domain.', 'bright_yellow', bold=True)}")
    else:
        print(f"  Status:  {style('✖ MISSING', 'bright_red', bold=True)}")
        print("  Impact:  Receiving mail servers cannot verify whether sending servers are authorized.")
        print(f"  Default: {DEFAULT_SPF_VALUE}")

    # 2. DMARC
    print(f"\n{style('● DMARC (Domain-based Message Authentication)', 'bright_cyan', bold=True)}")
    if dmarc["present"]:
        passed_checks += 1
        for r in dmarc["records"]:
            data = r.get("data", "").strip()
            tags = _parse_dmarc_tags(data)
            policy = tags.get("p", "none").lower()
            
            if policy == "reject":
                badge = style("✔ ENFORCED (p=reject)", "green", bold=True)
                p_desc = "Reject unauthorized emails (Highest Protection)"
            elif policy == "quarantine":
                badge = style("✔ ACTIVE (p=quarantine)", "bright_green", bold=True)
                p_desc = "Quarantine unauthorized emails into Spam/Junk"
            else:
                badge = style("▲ MONITORING ONLY (p=none)", "bright_yellow", bold=True)
                p_desc = "Monitoring mode only — no emails are blocked"

            print(f"  Status:  {badge}")
            print(f"  Record:  {data}")
            print(f"  Policy:  {p_desc}")
            if "sp" in tags:
                print(f"  Subdomain: sp={tags['sp']}")
            if "rua" in tags:
                print(f"  Reports: Aggregate (rua) -> {tags['rua']}")
            if "ruf" in tags:
                print(f"           Forensic (ruf)  -> {tags['ruf']}")
    else:
        print(f"  Status:  {style('✖ MISSING', 'bright_red', bold=True)}")
        print("  Impact:  No domain-level policy to protect against domain impersonation and spoofing.")

    # 3. DKIM
    print(f"\n{style('● DKIM (DomainKeys Identified Mail)', 'bright_cyan', bold=True)}")
    if dkim["present"]:
        passed_checks += 1
        count = len(dkim["selectors_found"])
        plural = "s" if count != 1 else ""
        print(f"  Status:  {style(f'✔ ACTIVE ({count} selector{plural} discovered)', 'green', bold=True)}")
        for selector, recs in dkim["selectors_found"].items():
            for r in recs["CNAME"]:
                target = r.get("data", "").strip()
                print(f"  • {selector}._domainkey {style('(CNAME)', 'gray')} -> {target}")
            for r in recs["TXT"]:
                data = r.get("data", "").strip()
                preview = data[:70] + ("..." if len(data) > 70 else "")
                print(f"  • {selector}._domainkey {style('(TXT)', 'gray')}   -> {preview}")
    else:
        print(f"  Status:  {style('▲ NOT DETECTED', 'bright_yellow', bold=True)} among common selector names")
        print(f"           ({', '.join(COMMON_DKIM_SELECTORS[:7])}...)")
        print("  Note:    Your mail provider may use a custom selector name.")
        print("           Check your mail provider's admin console for the exact selector.")

    # 4. MX
    print(f"\n{style('● MX (Mail Routing & Delivery)', 'bright_cyan', bold=True)}")
    if mx["present"]:
        passed_checks += 1
        count = len(mx["records"])
        plural = "s" if count != 1 else ""
        print(f"  Status:  {style(f'✔ CONFIGURED ({count} mail server{plural})', 'green', bold=True)}")
        for r in sorted(mx["records"], key=lambda r: r.get("priority", 0)):
            print(f"  • Priority {r.get('priority', 0)}: {r.get('data', '').strip()}")
    else:
        print(f"  Status:  {style('✖ MISSING', 'bright_red', bold=True)}")
        print("  Impact:  Domain has no mail exchange records configured and cannot receive inbound email.")

    # Overall Summary
    print(f"\n{style(line, 'gray')}")
    score_str = f"{passed_checks}/{total_checks} PASSED"
    
    if passed_checks == total_checks:
        # Check if DMARC policy is strict
        dmarc_recs = dmarc.get("records", [])
        dmarc_tags = _parse_dmarc_tags(dmarc_recs[0]["data"]) if dmarc_recs else {}
        p = dmarc_tags.get("p", "").lower()
        if p == "reject":
            verdict = style("OPTIMAL SECURITY (p=reject)", "green", bold=True)
            note = "Domain is fully guarded against spoofing, phishing, and domain impersonation."
        elif p == "quarantine":
            verdict = style("STRONG SECURITY (p=quarantine)", "bright_green", bold=True)
            note = "Domain is well-protected. Consider promoting DMARC to p=reject when ready."
        else:
            verdict = style("MONITORING (p=none)", "bright_yellow", bold=True)
            note = "All records exist, but DMARC policy is not yet enforcing rejection of fake emails."
    else:
        verdict = style("ACTION REQUIRED (Missing Records)", "bright_red", bold=True)
        note = f"Run 'dnssentry fix {domain} --apply' to automatically remediate missing records."

    print(f"  Security Score: {style(score_str, 'white', bold=True)}")
    print(f"  Verdict:        {verdict}")
    print(f"  Summary:        {note}")
    print(f"{style(line, 'gray')}\n")
