import unittest
from pathlib import Path

from stages.ner import _build_org_assets


class TestNerProfileAssets(unittest.TestCase):
    def test_testbed_profile_loads_watchlist_and_asset_terms(self) -> None:
        assets = _build_org_assets(
            profile_path=Path("Assets/Test-bed Profile.json"),
            sbom_path=Path("Assets/SBOM.json"),
        )

        self.assertIn("fin7", assets.threat_actors)
        self.assertIn("scattered spider", assets.threat_actors)
        self.assertIn("vmware esxi hypervisor", assets.technologies)

    def test_vanguard_profile_loads_watchlist_and_os_terms(self) -> None:
        assets = _build_org_assets(
            profile_path=Path("Assets/vanguard_biopharma.json"),
            sbom_path=Path("Assets/SBOM.json"),
        )

        self.assertIn("apt29", assets.threat_actors)
        self.assertIn("windows server", assets.technologies)
        self.assertIn("windows server 2022", assets.technologies)


if __name__ == "__main__":
    unittest.main()
