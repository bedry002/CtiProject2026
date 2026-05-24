"""MITRE ATT&CK STIX bundle loader and TTP relevance scorer."""

from __future__ import annotations

import json
import logging
import os
import pathlib
from urllib.request import urlretrieve

logger = logging.getLogger(__name__)

_BUNDLE_URL = os.environ.get(
    "ATTACK_BUNDLE_URL",
    "https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json",
)

# ATT&CK platform name (lowercase) → profile technology keywords that imply it
_PLATFORM_KEYWORDS: dict[str, tuple[str, ...]] = {
    "windows":    ("windows", "exchange", "active directory", "entra", "microsoft 365"),
    "linux":      ("ubuntu", "rhel", "red hat", "centos", "debian"),
    "macos":      ("macos", "mac os", "apple", "macbook"),
    "containers": ("docker", "kubernetes", "eks", "aks", "openshift", "gke", "cloud run"),
    "iaas":       ("aws", "azure", "gcp", "ec2", "s3"),
    "saas":       ("google workspace", "microsoft 365", "salesforce", "okta", "gmail"),
    "network":    ("palo alto", "fortinet", "fortigate", "f5", "cisco", "ubiquiti", "unifi"),
    "mobile":     ("android", "ios"),
}


def load_or_download(cache_path: str) -> dict:
    """Return the STIX bundle dict, downloading and caching locally if needed."""
    p = pathlib.Path(cache_path)
    if not p.exists():
        logger.info("ATT&CK bundle not cached — downloading (~30 MB) to %s …", p)
        p.parent.mkdir(parents=True, exist_ok=True)
        urlretrieve(_BUNDLE_URL, p)
        logger.info("ATT&CK bundle saved.")
    return json.loads(p.read_text(encoding="utf-8"))


def build_ttp_lookup(bundle: dict) -> dict[str, dict]:
    """Return {technique_id: {"platforms": set, "tactics": list, "name": str}}."""
    lookup: dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        tid = next(
            (
                r["external_id"]
                for r in obj.get("external_references", [])
                if r.get("source_name") == "mitre-attack"
            ),
            None,
        )
        if not tid:
            continue
        lookup[tid] = {
            "platforms": {p.lower() for p in obj.get("x_mitre_platforms", [])},
            "tactics": [
                p["phase_name"]
                for p in obj.get("kill_chain_phases", [])
                if p.get("kill_chain_name") == "mitre-attack"
            ],
            "name": obj.get("name", ""),
        }
    return lookup


def org_attack_platforms(technologies: list[str]) -> set[str]:
    """Map profile technology terms to the ATT&CK platform names they imply."""
    tech_lower = " ".join(t.lower() for t in technologies)
    return {
        platform
        for platform, keywords in _PLATFORM_KEYWORDS.items()
        if any(kw in tech_lower for kw in keywords)
    }


def ttp_relevance_score(
    event_ttps: list[dict],
    lookup: dict[str, dict],
    org_platforms: set[str],
    saturation: float = 0.30,
) -> float:
    """Fraction of event TTPs that target at least one org platform, saturated."""
    if not event_ttps or not lookup or not org_platforms:
        return 0.0
    relevant = sum(
        1
        for t in event_ttps
        if lookup.get(t.get("text", ""), {}).get("platforms", set()) & org_platforms
    )
    return round(min(1.0, relevant / len(event_ttps) / saturation), 4)
