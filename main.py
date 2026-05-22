"""Entry point; wire stages together and run the pipeline."""

import logging
import pathlib
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
from stages.ollama import OllamaStage
from stages.report import ReportStage
from stages.tagger import MISPTaggerStage
from config import (
    MISP_URL, MISP_KEY, MISP_VERIFYCERT,
    BUSINESS_PROFILE, SBOM_PROFILE, CONFIDENCE_THRESHOLD,
    PIPELINE_CONTINUE_ON_STAGE_ERROR,
    OLLAMA_ENABLED, OLLAMA_BASE_URL, OLLAMA_MODEL, OLLAMA_THRESHOLD,
)

REPORT_PATH = pathlib.Path(__file__).parent / "reports" / "curation_report.html"

# Set to False once the tags are correct
TAGGER_DRY_RUN = True


def build_pipeline(misp_client: PyMISP, event_count: int) -> Pipeline:
    stages = [
        NERStage(),
        ScoringStage(BUSINESS_PROFILE, SBOM_PROFILE),
    ]

    # LLM justification runs AFTER scoring so the deterministic confidence
    # number stays untouched; it only enriches events that already crossed
    # the gate. If Ollama is unreachable the stage logs and skips — the
    # rest of the pipeline carries on.
    if OLLAMA_ENABLED:
        stages.append(
            OllamaStage(
                base_url=OLLAMA_BASE_URL,
                model=OLLAMA_MODEL,
                threshold=OLLAMA_THRESHOLD,
                profile=BUSINESS_PROFILE,
            )
        )

    stages.extend([
        MISPTaggerStage(misp_client, dry_run=TAGGER_DRY_RUN),
        ReportStage(REPORT_PATH, threshold=CONFIDENCE_THRESHOLD, all_count=event_count),
    ])

    return Pipeline(stages, continue_on_stage_error=PIPELINE_CONTINUE_ON_STAGE_ERROR)


def main() -> None:
    if not MISP_URL or not MISP_KEY:
        raise RuntimeError("MISP_URL and MISP_KEY environment variables must be set")
    misp_client = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)

    ingest = MISPIngestStage(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    events = ingest.fetch(limit=100)

    if not events:
        print("No events returned from MISP.")
        return

    pipeline = build_pipeline(misp_client, len(events))
    results = pipeline.run(events)

    relevant = [e for e in results if (e.confidence or 0) >= CONFIDENCE_THRESHOLD]
    print(f"\n--- Curation Results: {len(relevant)}/{len(results)} relevant ---")
    for event in sorted(relevant, key=lambda e: e.confidence or 0.0, reverse=True):
        print(
            f"  [{event.confidence:.4f}] Event {event.misp_id} | "
            f"matched={event.matched_sbom_components}"
        )
    print(f"\nReport: {REPORT_PATH}")


if __name__ == "__main__":
    main()
