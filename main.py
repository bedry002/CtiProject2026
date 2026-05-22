"""Entry point; continuous polling loop that curates MISP events as they arrive."""

from __future__ import annotations

import logging
import pathlib
import time

import urllib3
from dotenv import load_dotenv

load_dotenv(override=True)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from pymisp import PyMISP

from config import (
    MISP_URL, MISP_KEY, MISP_VERIFYCERT,
    BUSINESS_PROFILE, SBOM_PROFILE, RAW_PROFILE, CONFIDENCE_THRESHOLD,
    PIPELINE_CONTINUE_ON_STAGE_ERROR,
    POLL_INTERVAL_SECONDS, POLL_STATE_PATH, POLL_RUN_ONCE,
    POLL_LOOKBACK_HOURS, POLL_RESET_STATE, TAGGER_DRY_RUN,
)
from pipeline.runner import Pipeline
from stages.ingest import MISPIngestStage
from stages.llm_enricher import LLMEnricherStage
from stages.ner import NERStage
from stages.report import ReportStage
from stages.scoring import ScoringStage
from stages.tagger import MISPTaggerStage

REPORT_PATH = pathlib.Path(__file__).parent / "reports" / "curation_report.html"
_STATE_FILE = pathlib.Path(POLL_STATE_PATH)

_LLM_PROFILE_CTX = {
    "sectors": BUSINESS_PROFILE.sectors,
    "technologies": BUSINESS_PROFILE.technologies,
    "threat_actor_watchlist": RAW_PROFILE.get("threat_actor_watch_list", []),
    "component_versions": {
        c.bom_ref: {"name": c.name, "version": c.version, "criticality": c.criticality}
        for c in (SBOM_PROFILE.components if SBOM_PROFILE else [])
    },
}


def _load_last_seen() -> int | None:
    if _STATE_FILE.exists():
        try:
            return int(_STATE_FILE.read_text(encoding="utf-8").strip())
        except ValueError:
            logging.warning("Corrupt poll state file — treating as first run")
    return None


def _save_last_seen(timestamp: int) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(str(timestamp), encoding="utf-8")


def build_pipeline(misp_client: PyMISP) -> Pipeline:
    return Pipeline([
        NERStage(),
        ScoringStage(BUSINESS_PROFILE, SBOM_PROFILE, threshold=CONFIDENCE_THRESHOLD),
        LLMEnricherStage(profile_context=_LLM_PROFILE_CTX, min_confidence=CONFIDENCE_THRESHOLD),
        MISPTaggerStage(misp_client, dry_run=TAGGER_DRY_RUN),
        ReportStage(REPORT_PATH, threshold=CONFIDENCE_THRESHOLD),
    ], continue_on_stage_error=PIPELINE_CONTINUE_ON_STAGE_ERROR)


def main() -> None:
    if not MISP_URL or not MISP_KEY:
        raise RuntimeError("MISP_URL and MISP_KEY environment variables must be set")

    misp_client = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    ingest = MISPIngestStage(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    pipeline = build_pipeline(misp_client)

    if POLL_RESET_STATE and _STATE_FILE.exists():
        _STATE_FILE.unlink()
        logging.info("POLL_RESET_STATE=true — cleared poll state, starting fresh")

    last_seen = _load_last_seen()

    if last_seen is None:
        last_seen = int(time.time()) - (POLL_LOOKBACK_HOURS * 3600)
        logging.info("First run — looking back %dh, polling every %ds", POLL_LOOKBACK_HOURS, POLL_INTERVAL_SECONDS)
    else:
        logging.info("Resuming from last poll, polling every %ds", POLL_INTERVAL_SECONDS)

    while True:
        poll_start = int(time.time())
        events = ingest.fetch(since_timestamp=last_seen)

        if events:
            # ScoringStage already drops below-threshold events, so results == relevant
            results = pipeline.run(events)
            logging.info("Poll complete — %d/%d events above threshold", len(results), len(events))
            for e in sorted(results, key=lambda e: e.confidence or 0.0, reverse=True):
                logging.info("  [%.4f] Event %s | sbom-hits=%s", e.confidence, e.misp_id, e.matched_sbom_components)
        else:
            logging.info("No new events")

        _save_last_seen(poll_start)
        last_seen = poll_start

        if POLL_RUN_ONCE:
            logging.info("POLL_RUN_ONCE=true — exiting after single batch")
            break

        logging.info("Next poll in %ds", POLL_INTERVAL_SECONDS)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
