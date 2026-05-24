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
_PROFILE_PATH = pathlib.Path(os.getenv("ORG_PROFILE_PATH", str(_BASE / "Test-bed Profile.json")))
_SBOM_PATH    = pathlib.Path(os.getenv("ORG_SBOM_PATH",    str(_BASE / "SBOM.json")))

def _load_business_profile(data: dict) -> BusinessProfile:
    return BusinessProfile(
        name        = data.get("organisation", {}).get("name", "Unknown"),
        sectors     = [s.lower() for s in data.get("sectors", [])],
        technologies = [t.lower() for t in data.get("technologies", [])],
        geographies  = [g.lower() for g in data.get("geographies", [])],
    )


# Read profile JSON once — shared by RAW_PROFILE and BusinessProfile
RAW_PROFILE      = json.loads(_PROFILE_PATH.read_text(encoding="utf-8"))
SBOM_PROFILE     = load_sbom(_SBOM_PATH)
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
