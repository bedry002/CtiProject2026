"""Central configuration — edit this to describe your organisation and MISP connection."""

from __future__ import annotations

import json
import os
import pathlib

from dotenv import load_dotenv

load_dotenv(override=True)

from pipeline.sbom import load_sbom
from stages.scoring import BusinessProfile

MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY") or os.getenv("MISP_API_KEY")
MISP_VERIFYCERT = False
PIPELINE_CONTINUE_ON_STAGE_ERROR = os.getenv("PIPELINE_CONTINUE_ON_STAGE_ERROR", "false").strip().lower() == "true"

_BASE         = pathlib.Path(__file__).parent / "Assets"
_PROFILE_PATH = _BASE / "Test-bed Profile.json"
_SBOM_PATH    = _BASE / "SBOM.json"

_SKIP_TECH_VALUES = {
    "n/a", "none", "true", "false", "hybrid", "basic",
    "intermediate", "advanced", "co-managed", "in-house",
    "on-prem", "public", "private", "current", "offline",
    "partial", "significant", "minimal", "internal_only",
}


def _tech_from_profile(data: dict) -> list[str]:
    """Walk technology_stack and collect ≤4-word strings as product names; ≥5 words are policy prose."""
    terms: list[str] = []

    def walk(obj: object) -> None:
        if isinstance(obj, dict):
            for v in obj.values():
                walk(v)
        elif isinstance(obj, list):
            for item in obj:
                walk(item)
        elif isinstance(obj, str):
            s = obj.strip()
            s_lower = s.lower()
            if (s
                    and len(s) > 2
                    and len(s.split()) <= 4
                    and s_lower not in _SKIP_TECH_VALUES
                    and not s[0].isdigit()):
                terms.append(s_lower)

    walk(data.get("technology_stack", {}))
    return list(dict.fromkeys(terms))


def _load_business_profile(data: dict) -> BusinessProfile:
    org = data["organisation"]

    sectors = [s.lower() for s in org.get("naics_label", "").replace(" and ", ", ").split(", ") if s]
    if not sectors:
        sectors = [bu.lower() for bu in org.get("business_units", [])]

    technologies = _tech_from_profile(data)

    geographies = [p.strip() for p in org.get("primary_headquarters", "").split(",") if p.strip()]

    keywords = [
        # Retail-specific threats
        "pos malware", "point of sale malware", "skimmer", "card skimmer",
        "magecart", "web skimmer", "formjacking",
        "credential stuffing", "account takeover",
        "payment card", "cardholder data", "pci dss",
        # Identity / access
        "phishing", "spear phishing", "business email compromise", "bec",
        "oauth", "token theft", "session hijacking",
        "password spray", "brute force",
        # Ransomware / destructive
        "ransomware", "esxiargs", "lockbit", "blackcat",
        "data exfiltration", "double extortion",
        # Vulnerabilities
        "exploit", "vulnerability", "cve", "zero day", "0day",
        "remote code execution", "rce", "sql injection",
        # Supply chain
        "supply chain", "malicious package", "dependency confusion",
        "typosquatting", "npm", "pypi",
        # Threat actors relevant to retail
        "fin7", "scattered spider", "lapsus",
    ]

    return BusinessProfile(
        name=org["name"],
        sectors=sectors,
        technologies=technologies,
        geographies=geographies,
        keywords=keywords,
    )


# Read profile JSON once — shared by RAW_PROFILE and BusinessProfile
RAW_PROFILE      = json.loads(_PROFILE_PATH.read_text(encoding="utf-8"))
SBOM_PROFILE     = load_sbom(_SBOM_PATH)
BUSINESS_PROFILE = _load_business_profile(RAW_PROFILE)
BUSINESS_PROFILE.specific_keywords = SBOM_PROFILE.specific_threat_phrases()

# Scoring
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.20"))

# Polling loop
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
POLL_STATE_PATH       = os.getenv("POLL_STATE_PATH", "data/poll_state.txt")
POLL_RUN_ONCE         = os.getenv("POLL_RUN_ONCE", "false").strip().lower() == "true"
POLL_LOOKBACK_HOURS   = int(os.getenv("POLL_LOOKBACK_HOURS", "24"))
POLL_RESET_STATE      = os.getenv("POLL_RESET_STATE", "false").strip().lower() == "true"
TAGGER_DRY_RUN        = os.getenv("TAGGER_DRY_RUN", "true").strip().lower() == "true"
