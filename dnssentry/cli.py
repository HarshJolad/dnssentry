"""
Command-line interface (CLI) for dnssentry.
"""

import argparse
import os
from pathlib import Path
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

from .checker import (
    COMMON_DKIM_SELECTORS,
    DEFAULT_SPF_VALUE,
    build_default_dmarc,
    check_dkim,
    check_dmarc,
    check_mx,
    check_spf,
    confirm,
    fix_dkim,
    fix_dmarc,
    fix_ms_dkim,
    fix_spf,
    print_report,
    style,
)
from .client import GoDaddyClient, GoDaddyError, get_cached_records


def load_env_file(path: Optional[Path]) -> None:
    """Parse a simple key=value .env file without external dependencies."""
    if not path or not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        os.environ.setdefault(key, value)


def build_client(args: argparse.Namespace) -> GoDaddyClient:
    """Instantiate GoDaddyClient with PAT credentials from CLI or environment."""
    env_file = Path(args.env_file) if getattr(args, "env_file", None) else Path(".env")
    load_env_file(env_file if env_file.exists() else None)

    token = (
        getattr(args, "token", None)
        or os.environ.get("GODADDY_PAT")
        or os.environ.get("GODADDY_TOKEN")
        or os.environ.get("GODADDY_API_TOKEN")
    )
    use_ote = os.environ.get("GODADDY_ENV", "production").lower() == "ote"
    return GoDaddyClient(token=token, use_ote=use_ote)


def _fetch_domain_records(
    client: GoDaddyClient, domain: str, use_cache: bool = True
) -> List[Dict[str, Any]]:
    """Fetch domain records, utilizing local cache when fresh."""
    cached_info = get_cached_records(domain) if use_cache else None
    if cached_info is not None:
        records, age = cached_info
        age_str = f"{int(age)}s ago" if age < 60 else f"{int(age // 60)}m ago"
        print(f"\n[*] Using cached DNS records for {style(domain, 'cyan', bold=True)} ({age_str}, use --no-cache to refresh)")
        return records

    print(f"\n[*] Connecting to GoDaddy API...")
    print(f"[*] Retrieving live DNS records for {style(domain, 'cyan', bold=True)}...")
    return client.get_records(domain, use_cache=use_cache)


def _apply_fixes(
    client: GoDaddyClient,
    domain: str,
    spf: Dict[str, Any],
    dmarc: Dict[str, Any],
    dkim: Dict[str, Any],
    spf_value: Optional[str] = None,
    dmarc_value: Optional[str] = None,
    dmarc_rua: Optional[str] = None,
    tenant: Optional[str] = None,
    dkim_selector: Optional[str] = None,
    dkim_value: Optional[str] = None,
    dkim_type: str = "TXT",
    ttl: int = 3600,
    apply: bool = False,
    auto_yes: bool = False,
) -> None:
    """Core remediation execution logic."""
    if not spf["present"] or spf_value:
        target_spf = spf_value or DEFAULT_SPF_VALUE
        fix_spf(client, domain, target_spf, ttl, apply, auto_yes)

    if not dmarc["present"] or dmarc_value:
        target_dmarc = dmarc_value or build_default_dmarc(domain, dmarc_rua)
        fix_dmarc(client, domain, target_dmarc, ttl, apply, auto_yes)

    resolved_tenant = tenant or os.environ.get("MS_TENANT") or os.environ.get("MICROSOFT_TENANT")
    if not dkim["present"] or (dkim_selector and dkim_value) or resolved_tenant:
        if resolved_tenant:
            fix_ms_dkim(client, domain, resolved_tenant, ttl, apply, auto_yes)
        elif dkim_selector and dkim_value:
            fix_dkim(
                client,
                domain,
                dkim_selector,
                dkim_value,
                ttl,
                apply,
                auto_yes,
                record_type=dkim_type,
            )
        else:
            domain_dashed = domain.replace(".", "-")
            print(
                f"\n[DKIM] Not detected. Microsoft 365 uses dual CNAME selectors (selector1, selector2).\n"
                f"       To auto-create both Microsoft 365 CNAME records, re-run with:\n"
                f"       --tenant <your-tenant> (or set MS_TENANT in .env)\n"
                f"       Target: selector1-{domain_dashed}._domainkey.<tenant>.onmicrosoft.com"
            )

    if not apply:
        print(f"\n{style('This was a dry run.', 'yellow', bold=True)} Re-run with {style('--apply', 'white', bold=True)} to write changes.")


def cmd_check(args: argparse.Namespace) -> None:
    """Execute the 'check' command."""
    client = build_client(args)
    use_cache = not getattr(args, "no_cache", False)
    all_records = _fetch_domain_records(client, args.domain, use_cache=use_cache)
    selectors = [args.dkim_selector] if args.dkim_selector else None

    print(f"[*] Auditing DNS email-security records for {style(args.domain, 'cyan', bold=True)}:")

    print("  ├── [1/4] Checking SPF (TXT @)...", end="", flush=True)
    spf = check_spf(client, args.domain, records=all_records)
    spf_status = style("✔ Found", "green") if spf["present"] else style("✖ Missing", "bright_red")
    print(f" {spf_status}")

    print("  ├── [2/4] Checking DMARC (TXT _dmarc)...", end="", flush=True)
    dmarc = check_dmarc(client, args.domain, records=all_records)
    dmarc_status = style("✔ Found", "green") if dmarc["present"] else style("✖ Missing", "bright_red")
    print(f" {dmarc_status}")

    sel_label = f"selector '{args.dkim_selector}'" if args.dkim_selector else "active selectors"
    print(f"  ├── [3/4] Checking DKIM (_domainkey across {sel_label})...", end="", flush=True)
    dkim = check_dkim(client, args.domain, selectors, records=all_records)
    if dkim["present"]:
        found_names = ", ".join(dkim["selectors_found"].keys())
        dkim_status = style(f"✔ Found ({found_names})", "green")
    else:
        dkim_status = style("▲ None detected", "bright_yellow")
    print(f" {dkim_status}")

    print("  └── [4/4] Checking MX records...", end="", flush=True)
    mx = check_mx(client, args.domain, records=all_records)
    mx_plural = "s" if len(mx['records']) != 1 else ""
    mx_status = (
        style(f"✔ Found ({len(mx['records'])} host{mx_plural})", "green")
        if mx["present"]
        else style("✖ Missing", "bright_red")
    )
    print(f" {mx_status}")

    print_report(args.domain, spf, dmarc, dkim, mx)

    missing = []
    if not spf["present"]:
        missing.append("SPF")
    if not dmarc["present"]:
        missing.append("DMARC")
    if not dkim["present"]:
        missing.append("DKIM")

    if missing:
        print(f"{style('Remediation Available:', 'yellow', bold=True)} Missing: {', '.join(missing)}.")
        # Interactive prompt to stage fixes immediately using records already in memory
        if hasattr(sys.stdin, "isatty") and sys.stdin.isatty():
            answer = input(f"Would you like to preview fixes for {args.domain} now? [y/N] ").strip().lower()
            if answer in ("y", "yes"):
                _apply_fixes(
                    client=client,
                    domain=args.domain,
                    spf=spf,
                    dmarc=dmarc,
                    dkim=dkim,
                    ttl=3600,
                    apply=False,
                    auto_yes=False,
                )
                return
        sys.exit(1)


def cmd_fix(args: argparse.Namespace) -> None:
    """Execute the 'fix' command."""
    client = build_client(args)
    use_cache = not getattr(args, "no_cache", False)
    all_records = _fetch_domain_records(client, args.domain, use_cache=use_cache)
    selectors = [args.dkim_selector] if args.dkim_selector else None

    spf = check_spf(client, args.domain, records=all_records)
    dmarc = check_dmarc(client, args.domain, records=all_records)
    dkim = check_dkim(client, args.domain, selectors, records=all_records)
    mx = check_mx(client, args.domain, records=all_records)
    print_report(args.domain, spf, dmarc, dkim, mx)

    _apply_fixes(
        client=client,
        domain=args.domain,
        spf=spf,
        dmarc=dmarc,
        dkim=dkim,
        spf_value=args.spf_value,
        dmarc_value=args.dmarc_value,
        dmarc_rua=args.dmarc_rua,
        tenant=getattr(args, "tenant", None),
        dkim_selector=getattr(args, "dkim_selector", None),
        dkim_value=getattr(args, "dkim_value", None),
        dkim_type=getattr(args, "dkim_type", "TXT"),
        ttl=args.ttl,
        apply=args.apply,
        auto_yes=args.yes,
    )


def create_parser() -> argparse.ArgumentParser:
    """Construct argument parser for CLI."""
    parser = argparse.ArgumentParser(
        prog="dnssentry",
        description="Check and fix SPF/DMARC/DKIM email security records on GoDaddy DNS.",
    )
    parser.add_argument(
        "--env-file",
        help="Path to .env file (default: ./.env)",
    )
    parser.add_argument(
        "--token",
        help="GoDaddy Personal Access Token (PAT). Overrides GODADDY_PAT in .env",
    )
    parser.add_argument(
        "--no-cache",
        "--refresh",
        action="store_true",
        help="Bypass local cache and force fresh retrieval from GoDaddy API.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # Subcommand: check
    p_check = sub.add_parser(
        "check",
        help="Report on SPF/DMARC/DKIM/MX without changing anything.",
    )
    p_check.add_argument("domain", help="Domain name to check (e.g. example.com)")
    p_check.add_argument(
        "--dkim-selector",
        help="Check only this DKIM selector instead of the common-selector list.",
    )
    p_check.add_argument(
        "--no-cache",
        "--refresh",
        action="store_true",
        help="Bypass local cache and force fresh retrieval from GoDaddy API.",
    )
    p_check.set_defaults(func=cmd_check)

    # Subcommand: fix
    p_fix = sub.add_parser(
        "fix",
        help="Report, and optionally write missing records.",
    )
    p_fix.add_argument("domain", help="Domain name to fix (e.g. example.com)")
    p_fix.add_argument(
        "--no-cache",
        "--refresh",
        action="store_true",
        help="Bypass local cache and force fresh retrieval from GoDaddy API.",
    )
    p_fix.add_argument(
        "--spf-value",
        help=f'Full SPF TXT value to write. If omitted, defaults to "{DEFAULT_SPF_VALUE}".',
    )
    p_fix.add_argument(
        "--dmarc-value",
        help='Full DMARC TXT value to write. If omitted, defaults to Microsoft 365 "v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc@{domain};"',
    )
    p_fix.add_argument(
        "--dmarc-rua",
        help="Email address for DMARC aggregate reports (used if --dmarc-value is omitted, default: dmarc@{domain}).",
    )
    p_fix.add_argument(
        "--tenant",
        help="Microsoft 365 tenant name (e.g. 'mycompany' or 'mycompany.onmicrosoft.com') to automatically write dual DKIM CNAME records (selector1 & selector2).",
    )
    p_fix.add_argument(
        "--dkim-selector",
        help="DKIM selector to check/write, e.g. 'google' or 'selector1'.",
    )
    p_fix.add_argument(
        "--dkim-value",
        help="Full DKIM value to write (TXT or CNAME target).",
    )
    p_fix.add_argument(
        "--dkim-type",
        choices=["TXT", "CNAME"],
        default="TXT",
        help="Record type when writing a custom --dkim-selector (default: TXT).",
    )
    p_fix.add_argument(
        "--ttl",
        type=int,
        default=3600,
        help="TTL in seconds for any record written (default: 3600).",
    )
    p_fix.add_argument(
        "--apply",
        action="store_true",
        help="Actually write changes to GoDaddy DNS (dry run if omitted).",
    )
    p_fix.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive confirmation prompt for each record write.",
    )
    p_fix.set_defaults(func=cmd_fix)

    return parser


def main(argv=None) -> None:
    """CLI entrypoint."""
    parser = create_parser()
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except GoDaddyError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)
