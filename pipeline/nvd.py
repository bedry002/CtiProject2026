"""NVD CPE to CVE enrichment with file-based cache (7-day TTL)."""

from __future__ import annotations

import json
import logging
import os
import pathlib
import time
from urllib.error import URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

logger = logging.getLogger(__name__)

_NVD_URL   = os.environ.get("NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
_CACHE_TTL = 7 * 24 * 3600  # seconds


def _load_cache(cache_path: pathlib.Path) -> dict:
    if cache_path.exists():
        try:
            return json.loads(cache_path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def _save_cache(cache_path: pathlib.Path, data: dict) -> None:
    cache_path.parent.mkdir(parents=True, exist_ok=True)
    cache_path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def fetch_cves_for_cpe(cpe: str, api_key: str | None = None) -> list[str]:
    """Query NVD and return CVE IDs for the given CPE string."""
    params  = urlencode({"cpeName": cpe, "resultsPerPage": 100})
    headers = {"apiKey": api_key} if api_key else {}
    req     = Request(f"{_NVD_URL}?{params}", headers=headers)
    with urlopen(req, timeout=15) as resp:
        data = json.loads(resp.read())
    return [vuln["cve"]["id"] for vuln in data.get("vulnerabilities", []) if "cve" in vuln]


def enrich_cpe_list(
    cpe_list: list[str],
    cache_path: pathlib.Path,
    api_key: str | None = None,
    delay: float = 0.65,  # NVD: 5 req/30 s without key → ~0.6 s/req
) -> dict[str, list[str]]:
    """Return {cpe: [cve_id, ...]} for every CPE, using cache where still fresh."""
    cache   = _load_cache(cache_path)
    now     = time.time()
    result  = {}
    changed = False

    for cpe in cpe_list:
        entry = cache.get(cpe)
        if entry and (now - entry.get("fetched_at", 0)) < _CACHE_TTL:
            result[cpe] = entry["cves"]
            continue
        try:
            cves = fetch_cves_for_cpe(cpe, api_key)
            cache[cpe] = {"cves": cves, "fetched_at": now}
            result[cpe] = cves
            changed = True
            logger.info("NVD: %s → %d CVEs", cpe, len(cves))
            time.sleep(delay)
        except (URLError, OSError) as exc:
            logger.warning("NVD fetch failed for %s: %s", cpe, exc)
            result[cpe] = entry["cves"] if entry else []

    if changed:
        _save_cache(cache_path, cache)
    return result
