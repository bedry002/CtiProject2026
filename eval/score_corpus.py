"""
score_corpus.py — run the synthetic corpus through the REAL production stages
(NERStage -> ScoringStage) and emit eval/corpus.scored.jsonl for evaluate.py sweep.

This uses the live ScoringStage (not evaluate.py's embedded reimplementation), so the
precision/recall/F1 numbers reflect exactly what main.py would produce in the testbed.

Run:
  ORG_PROFILE_PATH="Assets/Test-bed Profile.json" \
  ORG_SBOM_PATH="eval/Apex_SBOM_eval.json" \
  SPACY_AUTO_DOWNLOAD=false LLM_SKIP=true \
  python eval/score_corpus.py
"""
from __future__ import annotations

import json
import os
import pathlib
import sys

os.environ.setdefault("ORG_PROFILE_PATH", "Assets/Test-bed Profile.json")
os.environ.setdefault("ORG_SBOM_PATH", "eval/Apex_SBOM_eval.json")
os.environ.setdefault("SPACY_AUTO_DOWNLOAD", "false")
os.environ.setdefault("LLM_SKIP", "true")

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from config import BUSINESS_PROFILE, SBOM_PROFILE          # noqa: E402
from pipeline.event import CurationEvent                   # noqa: E402
from pipeline.runner import Pipeline                       # noqa: E402
from stages.ner import NERStage                            # noqa: E402
from stages.scoring import ScoringStage                    # noqa: E402

HERE = pathlib.Path(__file__).resolve().parent


def main() -> None:
    corpus = []
    with (HERE / "synthetic_corpus.jsonl").open(encoding="utf-8") as f:
        for line in f:
            o = json.loads(line)
            corpus.append(CurationEvent(misp_id=o["synthetic_id"],
                                        misp_uuid=o["synthetic_id"],
                                        raw=o["raw"]))

    # threshold=0 so NOTHING is dropped — the sweep needs every event's score.
    pipeline = Pipeline([
        NERStage(),
        ScoringStage(BUSINESS_PROFILE, SBOM_PROFILE, threshold=0.0),
    ])
    scored = pipeline.run(corpus)

    out = HERE / "corpus.scored.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for e in scored:
            f.write(json.dumps({
                "synthetic_id": e.misp_id,
                "confidence": e.confidence,
                "breakdown": e.score_breakdown,
                "matched_sbom_components": e.matched_sbom_components,
            }) + "\n")
    print(f"Scored {len(scored)} events (real ScoringStage) -> {out.name}")
    for e in sorted(scored, key=lambda x: x.confidence or 0, reverse=True):
        print(f"  {e.misp_id:9} {e.confidence:.4f}  {e.score_breakdown}")


if __name__ == "__main__":
    main()
