"""
test_cve_match_floor.py — guards the ICP2-59 CVE-to-SBOM confidence floor.

The floor fix in stages/scoring.py promotes events that reference a CVE matching
a documented risk in the org's SBOM. These tests prove the fix:
  * fires for an in-stack CVE,
  * stays off for an out-of-stack CVE (precision control),
  * is honest about firing via score_breakdown["cve_floor_applied"],
  * is fully reversible via SCORING_CVE_MATCH_FLOOR=0.0,
  * never lowers a score that was already above the floor.

If any of these tests go red, the engine has stopped treating CVE-on-own-kit as
the decisive signal it should be.
"""
from __future__ import annotations

import importlib
import os
import unittest

from pipeline.event import CurationEvent
from pipeline.sbom import SBOMComponent, SBOMProfile, SBOMRisk


def _profile():
    from stages.scoring import BusinessProfile
    return BusinessProfile(
        name="test-org",
        sectors=["retail"],
        technologies=["vmware esxi"],
        geographies=["chicago"],
        keywords=[],
        specific_keywords=[],
    )


def _sbom():
    """A small SBOM with one risk that maps CVE-2025-1111 to comp-esxi."""
    components = [
        SBOMComponent(bom_ref="comp-esxi", name="VMware ESXi", version="8.0",
                      supplier="VMware",
                      cpe="cpe:2.3:o:vmware:esxi:*:*:*:*:*:*:*:*",
                      criticality="high", weight=1.0),
        SBOMComponent(bom_ref="comp-nginx", name="Nginx", version="1.24",
                      supplier="NGINX",
                      cpe="cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                      criticality="medium", weight=0.6),
    ]
    risks = [SBOMRisk(risk_id="risk-1",
                      description="ESXi remote code execution",
                      affected_refs=["comp-esxi"],
                      severity="high",
                      known_cves=["CVE-2025-1111"])]
    return SBOMProfile(components=components, risks=risks)


def _event(cve, misp_id="e1"):
    return CurationEvent(
        misp_id=misp_id, misp_uuid="u-" + misp_id,
        raw={"info": "advisory", "Attribute": []},
        entities={"cves": [{"text": cve, "confidence": 1.0}]},
    )


def _scoring_stage_with_floor(floor_value: str):
    """Reload scoring.py with a specific SCORING_CVE_MATCH_FLOOR env value.
    Module-level constants are evaluated at import time, so we must reload."""
    import stages.scoring as scoring_module
    os.environ["SCORING_CVE_MATCH_FLOOR"] = floor_value
    importlib.reload(scoring_module)
    return scoring_module.ScoringStage(profile=_profile(), sbom=_sbom())


class TestCveMatchFloor(unittest.TestCase):

    def setUp(self) -> None:
        # Snapshot env so each test starts clean.
        self._saved_env = os.environ.get("SCORING_CVE_MATCH_FLOOR")

    def tearDown(self) -> None:
        if self._saved_env is None:
            os.environ.pop("SCORING_CVE_MATCH_FLOOR", None)
        else:
            os.environ["SCORING_CVE_MATCH_FLOOR"] = self._saved_env
        # Restore the module to its default state for other test files.
        import stages.scoring as scoring_module
        importlib.reload(scoring_module)

    def test_floor_fires_for_in_stack_cve(self) -> None:
        """CVE that matches a risk affecting an SBOM component → confidence floors at 0.50."""
        stage = _scoring_stage_with_floor("0.50")
        scored = stage.process(_event("CVE-2025-1111"))

        self.assertGreaterEqual(scored.confidence, 0.50,
            "In-stack CVE should be floored to at least 0.50 (HIGH band).")
        self.assertEqual(scored.score_breakdown.get("cve_floor_applied"), 1.0,
            "Breakdown must record that the floor fired.")

    def test_floor_does_not_fire_for_out_of_stack_cve(self) -> None:
        """CVE that does NOT appear in any SBOM risk → floor must stay off (precision control)."""
        stage = _scoring_stage_with_floor("0.50")
        scored = stage.process(_event("CVE-9999-0000"))

        self.assertEqual(scored.score_breakdown.get("cve_floor_applied"), 0.0,
            "Out-of-stack CVE must NOT trigger the floor — would create false positives.")
        # And the score shouldn't have been bumped to 0.50 by chance.
        self.assertLess(scored.confidence, 0.50,
            "Out-of-stack CVE with no other signals should score below the floor.")

    def test_floor_disabled_when_env_zero_restores_original_behaviour(self) -> None:
        """Setting SCORING_CVE_MATCH_FLOOR=0.0 must restore the original weighted-average behaviour."""
        stage = _scoring_stage_with_floor("0.0")
        scored = stage.process(_event("CVE-2025-1111"))

        self.assertEqual(scored.score_breakdown.get("cve_floor_applied"), 0.0,
            "With floor=0, the flag must stay off even on a confirmed match.")
        # The CVE still cross-references the SBOM (existing behaviour), so confidence
        # is non-zero — but it should be the diluted, pre-fix value, not the floor.
        self.assertLess(scored.confidence, 0.50,
            "With floor disabled, the confidence is the original diluted weighted average.")

    def test_floor_does_not_lower_already_high_confidence(self) -> None:
        """If the weighted average already exceeds the floor, the floor must not change it.
        The fix is one-directional (raise, never lower)."""
        stage = _scoring_stage_with_floor("0.50")
        # Build an event that scores high on its own merits (matches sector + tech + sbom asset)
        # AND has the in-stack CVE — confidence should be the weighted-average result,
        # which on this profile is > 0.50, and cve_floor_applied should be 0.0
        # because the floor never had to step in.
        event = CurationEvent(
            misp_id="e-high", misp_uuid="u-e-high",
            raw={"info": "VMware ESXi advisory targeting retail merchants in Chicago",
                 "Attribute": [{"type": "vulnerability", "value": "CVE-2025-1111"}]},
            entities={
                "cves": [{"text": "CVE-2025-1111", "confidence": 1.0}],
                "sbom_assets": [{"text": "esxi", "bom_ref": "comp-esxi", "confidence": 0.95}],
                "sectors": [{"text": "retail", "confidence": 1.0}],
                "software": [{"text": "vmware esxi", "confidence": 0.95}],
                "geographies": [{"text": "chicago", "confidence": 1.0}],
            },
        )
        scored = stage.process(event)
        self.assertGreater(scored.confidence, 0.50,
            "Weighted average should already exceed floor for a strongly-matching event.")
        self.assertEqual(scored.score_breakdown.get("cve_floor_applied"), 0.0,
            "Floor must not fire when weighted average is already above it.")


if __name__ == "__main__":
    unittest.main()
