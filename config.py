"""Central configuration — edit this to describe your organisation and MISP connection."""

import json
import pathlib
import re
from stages.scoring import BusinessProfile
from pipeline.sbom import load_sbom

MISP_URL = "https://192.168.1.173:4433"
MISP_KEY = "0ueVwp81PO3iEbUOJfA07sPAx1Jj78rRwTbFW1vM"
MISP_VERIFYCERT = False

_STRIP_PARENS = re.compile(r"\s*\([^)]*\)")

_BASE = pathlib.Path(__file__).parent / "Assets"
_PROFILE_PATH = _BASE / "Test-bed Profile.json"
_SBOM_PATH    = _BASE / "SBOM.json"


def _load_business_profile(path: pathlib.Path) -> BusinessProfile:
    data = json.loads(path.read_text(encoding="utf-8"))
    org  = data["organisation"]
    risk = data["risk_profile"]

    sectors = [
        "security research",
        "vulnerability analysis",
        "system administration",
        "computer systems design",
    ]

    # General tech terms — broad aliases that appear in threat intel text.
    # Precise component matching is handled by the SBOM scorer.
    technologies = [
        "windows", "linux", "ubuntu", "debian",
        "virtualbox", "oracle virtualbox",
        "ufw", "windows defender", "firewall",
        "ssh", "openssh", "rdp",
        "sudo", "privilege escalation",
        "python", "bash",
    ]

    geographies = []
    for part in org.get("primary_headquarters", "").split(","):
        part = part.strip()
        if part:
            geographies.append(part)

    keywords = [
        # Threat types directly relevant to this environment
        "brute force", "brute-force", "bruteforce",
        "backdoor", "rootkit", "exploit", "vulnerability", "cve",
        "malware", "ransomware", "trojan",
        "misconfiguration", "unpatched", "patch",
        "privilege escalation", "lateral movement",
        "remote code execution", "rce",
    ]

    return BusinessProfile(
        name=org["name"],
        sectors=sectors,
        technologies=technologies,
        geographies=geographies,
        keywords=keywords,
    )


BUSINESS_PROFILE = _load_business_profile(_PROFILE_PATH)
SBOM_PROFILE     = load_sbom(_SBOM_PATH)

# Confidence threshold for "relevant" — on the new 0–1 scale
CONFIDENCE_THRESHOLD = 0.10
