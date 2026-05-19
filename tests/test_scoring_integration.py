import unittest

from pipeline.event import CurationEvent
from pipeline.sbom import SBOMComponent, SBOMProfile, SBOMRisk
from stages.scoring import BusinessProfile, ScoringStage


class TestScoringIntegration(unittest.TestCase):
    def _profile(self) -> BusinessProfile:
        return BusinessProfile(
            name="test-org",
            sectors=["retail"],
            technologies=["vmware esxi"],
            geographies=["chicago"],
            keywords=[],
            specific_keywords=[],
        )

    def _sbom(self) -> SBOMProfile:
        components = [
            SBOMComponent(
                bom_ref="comp-esxi",
                name="VMware ESXi",
                version="8.0",
                supplier="VMware",
                cpe="cpe:2.3:o:vmware:esxi:*:*:*:*:*:*:*:*",
                criticality="high",
                weight=1.0,
            ),
            SBOMComponent(
                bom_ref="comp-nginx",
                name="Nginx",
                version="1.24",
                supplier="NGINX",
                cpe="cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
                criticality="medium",
                weight=0.6,
            ),
        ]
        risks = [
            SBOMRisk(
                risk_id="risk-1",
                description="ESXi remote code execution",
                affected_refs=["comp-esxi"],
                severity="high",
                known_cves=["CVE-2025-1111"],
            )
        ]
        return SBOMProfile(components=components, risks=risks)

    def test_cve_cross_reference_adds_sbom_component(self) -> None:
        stage = ScoringStage(profile=self._profile(), sbom=self._sbom())
        event = CurationEvent(
            misp_id="1",
            misp_uuid="u1",
            raw={"info": "generic bulletin", "Attribute": []},
            entities={"cves": [{"text": "CVE-2025-1111", "confidence": 1.0}]},
        )

        scored = stage.process(event)

        self.assertIn("comp-esxi", scored.matched_sbom_components)
        self.assertGreater(scored.score_breakdown.get("sbom_cve", 0.0), 0.0)

    def test_sbom_assets_boost_handles_multi_ref_string(self) -> None:
        stage = ScoringStage(profile=self._profile(), sbom=self._sbom())
        event = CurationEvent(
            misp_id="2",
            misp_uuid="u2",
            raw={"info": "esxi advisory", "Attribute": []},
            entities={
                "sbom_assets": [
                    {
                        "text": "esxi",
                        "bom_ref": "comp-esxi, comp-nginx",
                        "confidence": 0.95,
                    }
                ]
            },
        )

        scored = stage.process(event)

        self.assertIn("comp-esxi", scored.matched_sbom_components)
        self.assertIn("comp-nginx", scored.matched_sbom_components)
        self.assertGreater(scored.score_breakdown.get("sbom", 0.0), 0.0)


if __name__ == "__main__":
    unittest.main()
