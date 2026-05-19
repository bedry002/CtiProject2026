"""Central configuration — edit this to describe your organisation and MISP connection."""
import os
import json
from dotenv import load_dotenv
load_dotenv()
import pathlib
import re
from stages.scoring import BusinessProfile
from pipeline.sbom import load_sbom

MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_KEY') or os.getenv('MISP_API_KEY')
MISP_VERIFYCERT = False
PIPELINE_CONTINUE_ON_STAGE_ERROR = (os.getenv("PIPELINE_CONTINUE_ON_STAGE_ERROR", "false").strip().lower() == "true")

_STRIP_PARENS = re.compile(r"\s*\([^)]*\)")

_BASE = pathlib.Path(__file__).parent / "Assets"
_PROFILE_PATH = _BASE / "Test-bed Profile.json"
_SBOM_PATH    = _BASE / "SBOM.json"


_SKIP_TECH_VALUES = {
    "n/a", "none", "true", "false", "hybrid", "basic",
    "intermediate", "advanced", "co-managed", "in-house",
    "on-prem", "public", "private", "current", "offline",
    "partial", "significant", "minimal", "internal_only",
}


def _tech_from_profile(data: dict) -> list[str]:
    """Auto-derive technology terms from the profile's technology_stack section.

    Uses a word-count heuristic: strings with ≤4 words are product/service names;
    strings with ≥5 words are policy prose and are skipped.  Works for any
    compliant profile JSON without a manually maintained key allowlist — switching
    to a different business profile requires no code changes.
    """
    tech_stack = data.get("technology_stack", {})
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

    walk(tech_stack)
    return list(dict.fromkeys(terms))  # deduplicate, preserve order


def _load_business_profile(path: pathlib.Path) -> BusinessProfile:
    data = json.loads(path.read_text(encoding="utf-8"))
    org  = data["organisation"]

    sectors = [s.lower() for s in org.get("naics_label", "").replace(" and ", ", ").split(", ") if s]
    # Fall back to business unit names if NAICS label is absent
    if not sectors:
        sectors = [bu.lower() for bu in org.get("business_units", [])]

    # Auto-derived from technology_stack — no manual list to maintain when
    # switching business profiles.
    technologies = _tech_from_profile(data)

    geographies: list[str] = []
    for part in org.get("primary_headquarters", "").split(","):
        part = part.strip()
        if part:
            geographies.append(part)

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


SBOM_PROFILE     = load_sbom(_SBOM_PATH)
BUSINESS_PROFILE = _load_business_profile(_PROFILE_PATH)

# Enrich the profile with SBOM-derived compound threat phrases.
# e.g. "openssh exploit", "brute force ubuntu", "virtualbox escape"
# These are far more discriminating than single-word generic keywords.
BUSINESS_PROFILE.specific_keywords = SBOM_PROFILE.specific_threat_phrases()

# Confidence threshold for "relevant" — on the new 0–1 scale
CONFIDENCE_THRESHOLD = 0.10
