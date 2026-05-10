"""Central configuration — edit this to describe your organisation and MISP connection."""
import os
import json
import pathlib
import re
from stages.scoring import BusinessProfile
from pipeline.sbom import load_sbom

MISP_URL = os.getenv('MISP_URL')
MISP_KEY = os.getenv('MISP_KEY')
MISP_VERIFYCERT = False

_STRIP_PARENS = re.compile(r"\s*\([^)]*\)")

_BASE = pathlib.Path(__file__).parent / "Assets"
_PROFILE_PATH = _BASE / "Test-bed Profile.json"
_SBOM_PATH    = _BASE / "SBOM.json"


def _load_business_profile(path: pathlib.Path) -> BusinessProfile:
    data = json.loads(path.read_text(encoding="utf-8"))
    org  = data["organisation"]

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
    geographies: list[str] = []
    for part in org.get("primary_headquarters", "").split(","):
        part = part.strip()
        if part:
            geographies.append(part)

    keywords = [
        # Attack techniques
        "brute force", "brute-force", "bruteforce",
        "exploit", "vulnerability", "cve", "remote code execution", "rce",
        "privilege escalation", "lateral movement",
        "credential", "credential theft", "credential harvesting",
        "exfiltration", "data exfiltration",
        "persistence", "command and control", "c2",
        # Malware classes
        "backdoor", "rootkit", "malware", "ransomware", "trojan",
        "rat", "remote access trojan", "keylogger", "stealer",
        "botnet", "worm", "dropper", "loader",
        # Supply chain & software threats
        "supply chain", "typosquatting", "malicious package",
        "pypi", "npm", "open source",
        # Patch / defence posture
        "unpatched", "patch", "misconfiguration", "zero day", "0day",
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
