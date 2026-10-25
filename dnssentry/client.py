"""
GoDaddy API Client using Personal Access Token (PAT) authentication.
"""

import json
from pathlib import Path
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib import error, request

DEFAULT_CACHE_TTL = 300  # 5 minutes


def _resolve_cache_dir() -> Path:
    """Resolve writable cache directory, trying user home first then local .cache."""
    home_dir = Path.home() / ".dnssentry" / "cache"
    try:
        home_dir.mkdir(parents=True, exist_ok=True)
        test_file = home_dir / ".write_test"
        test_file.touch()
        test_file.unlink()
        return home_dir
    except (OSError, PermissionError):
        pass

    local_dir = Path(".cache") / "dnssentry"
    local_dir.mkdir(parents=True, exist_ok=True)
    return local_dir


def _get_cache_path(domain: str) -> Path:
    safe_name = "".join(c if c.isalnum() or c in ".-_" else "_" for c in domain.lower())
    return _resolve_cache_dir() / f"{safe_name}.json"


def get_cached_records(
    domain: str, max_age: int = DEFAULT_CACHE_TTL
) -> Optional[Tuple[List[Dict[str, Any]], float]]:
    """
    Return (records, age_in_seconds) if cache exists and age <= max_age.
    """
    cache_file = _get_cache_path(domain)
    if not cache_file.exists():
        return None
    try:
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        cached_time = data.get("timestamp", 0)
        age = time.time() - cached_time
        if age <= max_age:
            return data.get("records", []), age
    except Exception:
        pass
    return None


def set_cached_records(domain: str, records: List[Dict[str, Any]]) -> None:
    """Save records to local disk cache."""
    try:
        cache_dir = _resolve_cache_dir()
        cache_dir.mkdir(parents=True, exist_ok=True)
        cache_file = _get_cache_path(domain)
        payload = {
            "domain": domain.lower(),
            "timestamp": time.time(),
            "records": records,
        }
        cache_file.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    except Exception:
        pass


def clear_cache(domain: Optional[str] = None) -> None:
    """Invalidate cache for a domain or all domains."""
    try:
        cache_dir = _resolve_cache_dir()
        if domain:
            cache_file = _get_cache_path(domain)
            if cache_file.exists():
                cache_file.unlink()
        elif cache_dir.exists():
            for f in cache_dir.glob("*.json"):
                f.unlink()
    except Exception:
        pass


class GoDaddyError(Exception):
    """Raised when a GoDaddy API call fails or credentials are missing."""
    pass


class GoDaddyClient:
    PROD_BASE = "https://api.godaddy.com"
    OTE_BASE = "https://api.ote-godaddy.com"  # GoDaddy's test environment

    def __init__(self, token: Optional[str] = None, use_ote: bool = False, timeout: int = 15):
        if not token or not token.strip():
            raise GoDaddyError(
                "Missing GoDaddy Personal Access Token (PAT).\n"
                "Set GODADDY_PAT in your .env file or pass --token <PAT>.\n"
                "Create a PAT at: https://developer.godaddy.com/en/docs/api-users"
            )
        self.token = token.strip()
        self.base = self.OTE_BASE if use_ote else self.PROD_BASE
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Optional[Any] = None, max_retries: int = 2) -> Any:
        url = f"{self.base}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None

        for attempt in range(max_retries + 1):
            req = request.Request(url, data=data, method=method)
            req.add_header("Authorization", f"Bearer {self.token}")
            req.add_header("Accept", "application/json")
            if data is not None:
                req.add_header("Content-Type", "application/json")

            try:
                with request.urlopen(req, timeout=self.timeout) as resp:
                    raw = resp.read()
                    return json.loads(raw.decode("utf-8")) if raw else None
            except error.HTTPError as e:
                detail = e.read().decode("utf-8", errors="replace")
                if e.code == 404:
                    return []
                if e.code in (429, 502, 503, 504) and attempt < max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                if e.code == 401:
                    raise GoDaddyError(
                        f"Authentication failed (HTTP 401): {detail}\n"
                        "Please verify your GoDaddy Personal Access Token (PAT)."
                    ) from e
                if e.code == 403:
                    raise GoDaddyError(
                        f"Access forbidden (HTTP 403): {detail}\n"
                        "Ensure your Personal Access Token has the necessary scopes for Domain and DNS management."
                    ) from e
                raise GoDaddyError(f"{method} {path} -> HTTP {e.code}: {detail}") from e
            except error.URLError as e:
                if attempt < max_retries:
                    time.sleep(1.0 * (attempt + 1))
                    continue
                raise GoDaddyError(
                    f"{method} {path} -> Connection timed out or host unreachable: {e.reason}"
                ) from e

    def get_records(
        self,
        domain: str,
        record_type: Optional[str] = None,
        name: Optional[str] = None,
        use_cache: bool = True,
        max_age: int = DEFAULT_CACHE_TTL,
    ) -> List[Dict[str, Any]]:
        """
        Fetch records for a domain. When fetching all records (record_type=None),
        checks local cache first if use_cache is True.
        """
        if use_cache and not record_type and not name:
            cached_result = get_cached_records(domain, max_age=max_age)
            if cached_result is not None:
                records, _ = cached_result
                return records

        path = f"/v1/domains/{domain}/records"
        if record_type:
            path += f"/{record_type}"
            if name:
                path += f"/{name}"
        result = self._request("GET", path)
        records = result or []

        # Cache full domain snapshot
        if use_cache and not record_type and not name and records:
            set_cached_records(domain, records)

        return records

    def put_records(
        self, domain: str, record_type: str, name: str, records: List[Dict[str, Any]]
    ) -> None:
        """Replace records for exactly this type+name and invalidate local cache."""
        path = f"/v1/domains/{domain}/records/{record_type}/{name}"
        self._request("PUT", path, body=records)
        clear_cache(domain)
