"""Central configuration — edit this to describe your organisation and MISP connection."""

from __future__ import annotations

import json
import logging
import os
import pathlib

from dotenv import load_dotenv

load_dotenv(override=True)

from pipeline.naics import expand_naics
from pipeline.sbom import load_sbom, inject_profile_cpes
from stages.scoring import BusinessProfile

logger = logging.getLogger(__name__)

MISP_URL = os.getenv("MISP_URL")
MISP_KEY = os.getenv("MISP_KEY") or os.getenv("MISP_API_KEY")
MISP_VERIFYCERT = False
PIPELINE_CONTINUE_ON_STAGE_ERROR = os.getenv("PIPELINE_CONTINUE_ON_STAGE_ERROR", "false").strip().lower() == "true"

_BASE         = pathlib.Path(__file__).parent / "Assets"
_PROFILE_PATH = pathlib.Path(os.getenv("ORG_PROFILE_PATH", str(_BASE / "Test-bed Profile.json")))
_SBOM_PATH    = pathlib.Path(os.getenv("ORG_SBOM_PATH",    str(_BASE / "SBOM.json")))

def _load_business_profile(data: dict) -> BusinessProfile:
    org     = data.get("organisation", {})
    naics   = str(org.get("naics_code", ""))
    sectors = [s.lower() for s in data.get("sectors", [])]
    naics_terms = expand_naics(naics)
    combined = list(dict.fromkeys(sectors + [t for t in naics_terms if t not in sectors]))
    return BusinessProfile(
        name         = org.get("name", "Unknown"),
        sectors      = combined,
        technologies = [t.lower() for t in data.get("technologies", [])],
        geographies  = [g.lower() for g in data.get("geographies", [])],
    )


# Read profile JSON once — shared by RAW_PROFILE and BusinessProfile
RAW_PROFILE      = json.loads(_PROFILE_PATH.read_text(encoding="utf-8"))
SBOM_PROFILE     = load_sbom(_SBOM_PATH)
inject_profile_cpes(SBOM_PROFILE, RAW_PROFILE.get("cpe_list", []))
BUSINESS_PROFILE = _load_business_profile(RAW_PROFILE)
BUSINESS_PROFILE.specific_keywords = (
    [kw.lower() for kw in RAW_PROFILE.get("keywords", [])]
    + SBOM_PROFILE.specific_threat_phrases()
)

# Scoring
CONFIDENCE_THRESHOLD = float(os.getenv("CONFIDENCE_THRESHOLD", "0.20"))

# Polling loop
POLL_INTERVAL_SECONDS = int(os.getenv("POLL_INTERVAL_SECONDS", "30"))
POLL_STATE_PATH       = os.getenv("POLL_STATE_PATH", "data/poll_state.txt")
POLL_RUN_ONCE         = os.getenv("POLL_RUN_ONCE", "false").strip().lower() == "true"
POLL_LOOKBACK_HOURS   = int(os.getenv("POLL_LOOKBACK_HOURS", "24"))
POLL_RESET_STATE      = os.getenv("POLL_RESET_STATE", "false").strip().lower() == "true"
TAGGER_DRY_RUN        = os.getenv("TAGGER_DRY_RUN", "true").strip().lower() == "true"
LLM_SKIP              = os.getenv("LLM_SKIP", "false").strip().lower() == "true"

# --- Option B: NVD CVE enrichment ---
NVD_ENRICH     = os.getenv("NVD_ENRICH", "false").strip().lower() == "true"
NVD_API_KEY    = os.getenv("NVD_API_KEY") or None
NVD_CACHE_PATH = pathlib.Path(os.getenv("NVD_CACHE_PATH", "data/nvd_cache.json"))

if NVD_ENRICH:
    from pipeline.sbom import enrich_with_nvd
    enrich_with_nvd(SBOM_PROFILE, NVD_CACHE_PATH, NVD_API_KEY)
    logger.info("NVD enrichment applied to SBOM.")

# --- Option A: ATT&CK TTP scoring ---
ATTACK_ENABLED     = os.getenv("ATTACK_ENABLED", "false").strip().lower() == "true"
ATTACK_BUNDLE_PATH = os.getenv("ATTACK_BUNDLE_PATH", "data/mitre_attack_cache.json")

if ATTACK_ENABLED:
    from pipeline.attack import load_or_download, build_ttp_lookup
    from pipeline.attack import org_attack_platforms as _org_plat
    _bundle              = load_or_download(ATTACK_BUNDLE_PATH)
    ATTACK_LOOKUP        = build_ttp_lookup(_bundle)
    ORG_ATTACK_PLATFORMS = _org_plat(BUSINESS_PROFILE.technologies)
    logger.info(
        "ATT&CK: %d techniques loaded, org platforms: %s",
        len(ATTACK_LOOKUP), ORG_ATTACK_PLATFORMS,
    )
else:
    ATTACK_LOOKUP        = {}
    ORG_ATTACK_PLATFORMS = set()
