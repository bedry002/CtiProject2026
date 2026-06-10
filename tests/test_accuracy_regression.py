"""
test_accuracy_regression.py — end-to-end accuracy gate.

Runs the labelled synthetic corpus through the real NER + Scoring stages and
asserts:
  * full-set accuracy at the default threshold meets the scope's >=80% target,
  * substring-trap events score below band (precision protection),
  * the out-of-stack CVE control event is correctly rejected,
  * deterministic-only accuracy (excluding by-design oblique misses) is perfect.

If this goes red, something regressed scoring quality at the corpus level. The
sandbox tests (test_cve_match_floor, test_scoring_integration) tell you WHICH
behaviour broke; this test tells you the cumulative effect.

Skips automatically if the eval/ corpus files are not present (so this test
is safe to ship even before the eval/ folder is committed).
"""
from __future__ import annotations

import csv
import json
import os
import pathlib
import unittest


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CORPUS = REPO_ROOT / "eval" / "synthetic_corpus.jsonl"
LABELS = REPO_ROOT / "eval" / "synthetic_labels.csv"
SBOM_PATH = REPO_ROOT / "Assets" / "SBOM.json"
PROFILE_PATH = REPO_ROOT / "Assets" / "Test-bed Profile.json"

# Acceptance criterion from the project scope.
SCOPE_ACCURACY_TARGET = 0.80
DEFAULT_THRESHOLD = 0.20


def _have_corpus() -> bool:
    return CORPUS.exists() and LABELS.exists() and SBOM_PATH.exists()


@unittest.skipUnless(_have_corpus(),
                     "Synthetic corpus not present (eval/synthetic_corpus.jsonl + labels). "
                     "Skipping accuracy regression test.")
class TestAccuracyRegression(unittest.TestCase):
    """Acceptance-criterion check for the curation engine."""

    @classmethod
    def setUpClass(cls) -> None:
        # Point the engine at the testbed profile + real SBOM before importing config.
        os.environ["ORG_PROFILE_PATH"] = str(PROFILE_PATH)
        os.environ["ORG_SBOM_PATH"] = str(SBOM_PATH)
        os.environ["SPACY_AUTO_DOWNLOAD"] = "false"
        # Make sure the floor is on at its production default for this test.
        os.environ["SCORING_CVE_MATCH_FLOOR"] = "0.50"

        # Reload scoring so any earlier test's env tweak doesn't leak in.
        import importlib
        import stages.scoring as scoring_module
        importlib.reload(scoring_module)

        from config import BUSINESS_PROFILE, SBOM_PROFILE
        from pipeline.event import CurationEvent
        from pipeline.runner import Pipeline
        from stages.ner import NERStage
        ScoringStage = scoring_module.ScoringStage

        # Load corpus + labels.
        events = []
        with CORPUS.open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                obj = json.loads(line)
                events.append(CurationEvent(misp_id=obj["synthetic_id"],
                                            misp_uuid=obj["synthetic_id"],
                                            raw=obj["raw"]))
        labels = {row["synthetic_id"]: row
                  for row in csv.DictReader(LABELS.open(encoding="utf-8"))}

        # Score with threshold=0 so we see every score (we apply the production
        # threshold below ourselves to check what the engine would drop).
        pipeline = Pipeline([
            NERStage(),
            ScoringStage(BUSINESS_PROFILE, SBOM_PROFILE, threshold=0.0),
        ])
        scored = pipeline.run(events)

        cls.scores = {e.misp_id: (e.confidence or 0.0) for e in scored}
        cls.breakdowns = {e.misp_id: e.score_breakdown for e in scored}
        cls.labels = labels

    def _confusion(self, threshold: float, exclude_expect_miss: bool = False):
        tp = fp = fn = tn = 0
        for sid, label in self.labels.items():
            if exclude_expect_miss and label["expect_miss"] == "1":
                continue
            gold_relevant = label["gold_label"] == "relevant"
            pred_relevant = self.scores[sid] >= threshold
            if gold_relevant and pred_relevant:     tp += 1
            elif gold_relevant and not pred_relevant: fn += 1
            elif not gold_relevant and pred_relevant: fp += 1
            else:                                     tn += 1
        return tp, fp, fn, tn

    def test_full_set_accuracy_meets_scope_target(self) -> None:
        tp, fp, fn, tn = self._confusion(DEFAULT_THRESHOLD)
        total = tp + fp + fn + tn
        accuracy = (tp + tn) / total
        self.assertGreaterEqual(
            accuracy, SCOPE_ACCURACY_TARGET,
            f"Full-set accuracy at threshold {DEFAULT_THRESHOLD} dropped to {accuracy:.3f} "
            f"(TP={tp} FP={fp} FN={fn} TN={tn}); scope target is {SCOPE_ACCURACY_TARGET}.")

    def test_deterministic_only_accuracy_is_perfect(self) -> None:
        """Excluding the 5 by-design oblique cases (the LLM stage's job),
        the deterministic scorer should still get every case right."""
        tp, fp, fn, tn = self._confusion(DEFAULT_THRESHOLD, exclude_expect_miss=True)
        total = tp + fp + fn + tn
        accuracy = (tp + tn) / total
        self.assertEqual(fp, 0, f"Expected zero false positives, got {fp}.")
        self.assertEqual(accuracy, 1.0,
            f"Deterministic-only accuracy regressed: {accuracy:.3f} ({fn} FN, {fp} FP).")

    def test_substring_traps_score_below_band(self) -> None:
        """Substring-trap events (klass=substring_trap) must score below the LOW band (0.10).
        These probe the word-boundary protection in NER + Scoring."""
        trap_ids = [sid for sid, lab in self.labels.items()
                    if lab["klass"] == "substring_trap"]
        self.assertGreater(len(trap_ids), 0, "No substring-trap events in labels?")
        for sid in trap_ids:
            score = self.scores[sid]
            self.assertLess(score, 0.10,
                f"Substring trap {sid} scored {score:.4f} (>=0.10) — "
                f"word-boundary protection may have regressed.")

    def test_out_of_stack_cve_correctly_rejected(self) -> None:
        """The control case (klass=out_of_stack_cve) references a real CVE
        but for software we do NOT run. The CVE floor must NOT promote it."""
        controls = [sid for sid, lab in self.labels.items()
                    if lab["klass"] == "out_of_stack_cve"]
        self.assertGreater(len(controls), 0,
            "Out-of-stack CVE control is missing from the labels — please keep at least one.")
        for sid in controls:
            score = self.scores[sid]
            floor_flag = self.breakdowns[sid].get("cve_floor_applied", 0.0)
            self.assertEqual(floor_flag, 0.0,
                f"{sid} is out-of-stack but CVE floor fired — floor precision regressed.")
            self.assertLess(score, DEFAULT_THRESHOLD,
                f"{sid} (out-of-stack CVE) scored {score:.4f} >= threshold — should be dropped.")


if __name__ == "__main__":
    unittest.main()
