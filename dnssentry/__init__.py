"""
dnssentry: Automated SPF, DMARC, DKIM, and MX audit and repair for GoDaddy DNS.
"""

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
)
from .client import GoDaddyClient, GoDaddyError

__version__ = "0.2.0"

__all__ = [
    "__version__",
    "GoDaddyClient",
    "GoDaddyError",
    "check_spf",
    "check_dmarc",
    "check_dkim",
    "check_mx",
    "fix_spf",
    "fix_dmarc",
    "fix_dkim",
    "fix_ms_dkim",
    "confirm",
    "print_report",
    "COMMON_DKIM_SELECTORS",
    "DEFAULT_SPF_VALUE",
    "build_default_dmarc",
]
