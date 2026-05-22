"""Entry point; continuous polling loop that curates MISP events as they arrive."""

import logging
import pathlib
import time
import urllib3
from dotenv import load_dotenv

load_dotenv()

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")

from pipeline.runner import Pipeline
from pymisp import PyMISP
from stages.ingest import MISPIngestStage
from stages.ner import NERStage
from stages.scoring import ScoringStage
from stages.llm_enricher import LLMEnricherStage
from stages.report import ReportStage
from stages.tagger import MISPTaggerStage
from config import (
    MISP_URL, MISP_KEY, MISP_VERIFYCERT,
    BUSINESS_PROFILE, SBOM_PROFILE, RAW_PROFILE, CONFIDENCE_THRESHOLD,
    PIPELINE_CONTINUE_ON_STAGE_ERROR,
    POLL_INTERVAL_SECONDS, POLL_STATE_PATH, POLL_RUN_ONCE,
)

REPORT_PATH = pathlib.Path(__file__).parent / "reports" / "curation_report.html"
_STATE_FILE = pathlib.Path(POLL_STATE_PATH)

# Set to False once the tags are confirmed correct
TAGGER_DRY_RUN = True


def _load_last_seen() -> int | None:
    """Return the saved Unix timestamp from the last successful poll, or None on first run."""
    if _STATE_FILE.exists():
        try:
            return int(_STATE_FILE.read_text(encoding="utf-8").strip())
        except ValueError:
            logging.warning("Corrupt poll state file — treating as first run")
    return None


def _save_last_seen(timestamp: int) -> None:
    _STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    _STATE_FILE.write_text(str(timestamp), encoding="utf-8")


_LLM_PROFILE_CTX = {
    "sectors": BUSINESS_PROFILE.sectors,
    "technologies": BUSINESS_PROFILE.technologies,
    "threat_actor_watchlist": RAW_PROFILE.get("threat_actor_watch_list", []),
    "component_versions": {
        c.bom_ref: {"name": c.name, "version": c.version, "criticality": c.criticality}
        for c in (SBOM_PROFILE.components if SBOM_PROFILE else [])
    },
}


def build_pipeline(misp_client: PyMISP) -> Pipeline:
    return Pipeline([
        NERStage(),
        ScoringStage(BUSINESS_PROFILE, SBOM_PROFILE, threshold=CONFIDENCE_THRESHOLD),
        LLMEnricherStage(profile_context=_LLM_PROFILE_CTX,min_confidence=CONFIDENCE_THRESHOLD,),
        MISPTaggerStage(misp_client, dry_run=TAGGER_DRY_RUN),
        ReportStage(REPORT_PATH, threshold=CONFIDENCE_THRESHOLD),
    ], continue_on_stage_error=PIPELINE_CONTINUE_ON_STAGE_ERROR)


def main() -> None:
    if not MISP_URL or not MISP_KEY:
        raise RuntimeError("MISP_URL and MISP_KEY environment variables must be set")

    misp_client = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    ingest = MISPIngestStage(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    pipeline = build_pipeline(misp_client)

    last_seen = _load_last_seen()

    if last_seen is None:
        last_seen = int(time.time()) - 86400  # 24 hours ago
        logging.info("First run — starting from 24h ago (timestamp=%d), polling every %ds", last_seen, POLL_INTERVAL_SECONDS)
    else:
        logging.info("Resuming — last seen timestamp=%d, polling every %ds", last_seen, POLL_INTERVAL_SECONDS)

    while True:
        # Record poll start BEFORE fetching so any event posted during processing
        # is captured in the next poll rather than silently missed.
        poll_start = int(time.time())

        events = ingest.fetch(since_timestamp=last_seen)

        if events:
            results = pipeline.run(events)
            relevant = [e for e in results if (e.confidence or 0) >= CONFIDENCE_THRESHOLD]
            logging.info(
                "Poll complete — %d/%d events relevant",
                len(relevant), len(results),
            )
            for event in sorted(relevant, key=lambda e: e.confidence or 0.0, reverse=True):
                logging.info(
                    "  [%.4f] Event %s | sbom-hits=%s",
                    event.confidence, event.misp_id, event.matched_sbom_components,
                )
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
