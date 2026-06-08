"""
run_offline.py — run the REAL curation engine offline, for demonstration & docs.

This is the same NERStage -> ScoringStage -> ReportStage that main.py uses, but it
reads events from a local JSONL file instead of connecting to MISP, and it skips
the LLM stage (no API key needed). It produces the SAME HTML report the live system
produces, so you can see the engine working and screenshot the result.

It does NOT modify any Asset file and does NOT touch MISP.

Usage (from the repo root):
  # default: synthetic corpus, Apex Retail testbed profile, CVE-enriched eval SBOM
  python eval/run_offline.py

  # try a different org (see Assets/ for the JSON names):
  python eval/run_offline.py \
      --profile "Assets/vanguard_biopharma.json" \
      --sbom    "Assets/vanguard_biopharma_sbom.json"

  # change the drop threshold (default reads CONFIDENCE_THRESHOLD or 0.20):
  python eval/run_offline.py --threshold 0.10
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent


def main() -> None:
    ap = argparse.ArgumentParser(description="Offline curation-engine demo runner")
    ap.add_argument("--corpus", default=str(HERE / "synthetic_corpus.jsonl"))
    ap.add_argument("--profile", default=str(ROOT / "Assets" / "Test-bed Profile.json"))
    ap.add_argument("--sbom", default=str(HERE / "Apex_SBOM_eval.json"))
    ap.add_argument("--threshold", type=float, default=None)
    ap.add_argument("--report", default=str(ROOT / "reports" / "offline_demo_report.html"))
    args = ap.parse_args()

    # Point the engine at the chosen org BEFORE importing config/stages.
    os.environ["ORG_PROFILE_PATH"] = args.profile
    os.environ["ORG_SBOM_PATH"] = args.sbom
    os.environ.setdefault("SPACY_AUTO_DOWNLOAD", "false")  # offline: regex-only NER is fine
    os.environ.setdefault("LLM_SKIP", "true")

    sys.path.insert(0, str(ROOT))
    from config import BUSINESS_PROFILE, SBOM_PROFILE, CONFIDENCE_THRESHOLD
    from pipeline.event import CurationEvent
    from pipeline.runner import Pipeline
    from stages.ner import NERStage
    from stages.scoring import ScoringStage
    from stages.report import ReportStage

    threshold = args.threshold if args.threshold is not None else CONFIDENCE_THRESHOLD

    # Load the synthetic corpus from disk (this replaces the MISP ingest stage).
    events = []
    with open(args.corpus, encoding="utf-8") as f:
        for line in f:
            o = json.loads(line)
            events.append(CurationEvent(misp_id=o["synthetic_id"],
                                        misp_uuid=o["synthetic_id"],
                                        raw=o["raw"]))

    print(f"Org profile : {args.profile}")
    print(f"SBOM        : {args.sbom}")
    print(f"Corpus      : {args.corpus}  ({len(events)} events)")
    print(f"Threshold   : {threshold}\n")

    report_path = pathlib.Path(args.report)
    pipeline = Pipeline([
        NERStage(),
        ScoringStage(BUSINESS_PROFILE, SBOM_PROFILE, threshold=0.0),   # keep all, so report shows every score
        ReportStage(report_path, threshold=threshold, all_count=len(events)),
    ])
    scored = pipeline.run(events)

    # Console summary (this is what you screenshot alongside the HTML report).
    scored.sort(key=lambda e: e.confidence or 0, reverse=True)
    print(f"{'EVENT':10} {'SCORE':>7}  {'BAND':12} CVE-floor  DROPPED?")
    print("-" * 60)
    for e in scored:
        c = e.confidence or 0
        band = ("HIGH" if c >= 0.50 else "MEDIUM" if c >= 0.25 else
                "LOW" if c >= 0.10 else "not-relevant")
        floor = "yes" if e.score_breakdown.get("cve_floor_applied") else "-"
        dropped = "" if c >= threshold else "DROPPED"
        print(f"{e.misp_id:10} {c:7.4f}  {band:12} {floor:9} {dropped}")

    kept = sum(1 for e in scored if (e.confidence or 0) >= threshold)
    print("-" * 60)
    print(f"{kept}/{len(scored)} events at or above threshold {threshold}")
    print(f"\nHTML report written -> {report_path}")


if __name__ == "__main__":
    main()
