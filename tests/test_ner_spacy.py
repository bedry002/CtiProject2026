"""Tests for spaCy integration inside NERStage.

Covers: model loading (with auto-skip if spaCy/model absent), entity extraction
on real CTI text, and a full end-to-end run verifying that spaCy-derived
entities are surfaced by the engine (software, geography, threat actors).
"""

from __future__ import annotations

import unittest

from pipeline.event import CurationEvent

# ── spaCy availability guards ──────────────────────────────────────────────────

try:
    import spacy as _spacy
    _SPACY_AVAILABLE = True
except ImportError:
    _SPACY_AVAILABLE = False

_MODEL_NAME = "en_core_web_lg"

def _model_available() -> bool:
    if not _SPACY_AVAILABLE:
        return False
    try:
        _spacy.load(_MODEL_NAME)
        return True
    except OSError:
        return False


_SKIP_NO_SPACY = unittest.skipUnless(_SPACY_AVAILABLE, "spaCy not installed — skipping spaCy tests")
_SKIP_NO_MODEL = unittest.skipUnless(_model_available(), f"spaCy model '{_MODEL_NAME}' not installed — run: python -m spacy download {_MODEL_NAME}")


# ── spaCy model load and basic sanity ─────────────────────────────────────────

@_SKIP_NO_SPACY
@_SKIP_NO_MODEL
class TestSpacyModelLoads(unittest.TestCase):

    def test_model_loads_without_error(self) -> None:
        nlp = _spacy.load(_MODEL_NAME)
        self.assertIsNotNone(nlp)

    def test_model_has_ner_component(self) -> None:
        nlp = _spacy.load(_MODEL_NAME)
        self.assertIn("ner", nlp.pipe_names)

    def test_model_processes_simple_sentence(self) -> None:
        nlp = _spacy.load(_MODEL_NAME)
        doc = nlp("Google was founded in California.")
        self.assertGreater(len(doc.ents), 0)

    def test_model_extracts_org_and_gpe(self) -> None:
        nlp = _spacy.load(_MODEL_NAME)
        doc = nlp("Microsoft reported that APT29 targeted organisations in Ukraine.")
        labels = {ent.label_ for ent in doc.ents}
        self.assertTrue(labels & {"ORG", "GPE"}, f"Expected ORG or GPE in {labels}")


# ── NERStage spaCy integration ─────────────────────────────────────────────────

@_SKIP_NO_SPACY
@_SKIP_NO_MODEL
class TestNERStageSpacyIntegration(unittest.TestCase):
    """NERStage with real spaCy model (no mocking) against a minimal org profile."""

    _CTI_TEXT = (
        "APT29, also known as Cozy Bear, has been observed exploiting CVE-2023-44487 "
        "(HTTP/2 Rapid Reset) to conduct distributed denial-of-service attacks against "
        "VMware ESXi servers in Germany and the United Kingdom. "
        "The campaign abuses Microsoft Exchange misconfigurations to establish persistence."
    )

    def _make_stage(self):
        from stages.ner import NERStage
        return NERStage(
            spacy_auto_download=False,
            profile_path="does-not-exist.json",
            sbom_path="does-not-exist.json",
        )

    def test_ner_stage_loads_spacy_model(self) -> None:
        stage = self._make_stage()
        loaded = stage.ensure_model()
        self.assertTrue(loaded, "NERStage.ensure_model() should return True when model is available")

    def test_nlp_unavailable_flag_is_false(self) -> None:
        stage = self._make_stage()
        stage.ensure_model()
        self.assertFalse(stage.nlp_unavailable)

    def test_spacy_extracts_entities_from_cti_text(self) -> None:
        stage = self._make_stage()
        nlp = stage._get_nlp()
        self.assertIsNotNone(nlp)
        doc = nlp(self._CTI_TEXT)
        labels = {ent.label_ for ent in doc.ents}
        self.assertTrue(
            labels & {"ORG", "GPE", "PRODUCT"},
            f"Expected at least one of ORG/GPE/PRODUCT in spaCy output; got {labels}",
        )

    def test_spacy_finds_geographic_entity(self) -> None:
        stage = self._make_stage()
        nlp = stage._get_nlp()
        doc = nlp(self._CTI_TEXT)
        gpe_texts = {ent.text for ent in doc.ents if ent.label_ == "GPE"}
        self.assertTrue(
            gpe_texts & {"Germany", "United Kingdom"},
            f"Expected Germany or United Kingdom in GPE entities; got {gpe_texts}",
        )

    def test_process_event_runs_without_error(self) -> None:
        stage = self._make_stage()
        event = CurationEvent(misp_id="99", misp_uuid="zz", raw={"info": self._CTI_TEXT, "Attribute": []})
        result = stage.process(event)
        self.assertIsNotNone(result)
        self.assertIsInstance(result.entities, dict)

    def test_process_event_extracts_cve(self) -> None:
        stage = self._make_stage()
        event = CurationEvent(misp_id="99", misp_uuid="zz", raw={"info": self._CTI_TEXT, "Attribute": []})
        result = stage.process(event)
        cve_texts = [item.get("text") for item in result.entities.get("cves", [])]
        self.assertIn("CVE-2023-44487", cve_texts, f"Expected CVE-2023-44487 in extracted CVEs; got {cve_texts}")

    def test_process_event_extracts_ttp(self) -> None:
        text = "T1190 Exploit Public-Facing Application was used alongside T1078 Valid Accounts."
        stage = self._make_stage()
        event = CurationEvent(misp_id="100", misp_uuid="aa", raw={"info": text, "Attribute": []})
        result = stage.process(event)
        ttp_texts = [item.get("text") for item in result.entities.get("ttps", [])]
        self.assertIn("T1190", ttp_texts, f"Expected T1190 in TTPs; got {ttp_texts}")


# ── NERStage with org profile assets (end-to-end usefulness) ──────────────────

@_SKIP_NO_SPACY
@_SKIP_NO_MODEL
class TestNERStageWithOrgAssets(unittest.TestCase):
    """Verify spaCy + org asset matching surfaces relevant entities in the output."""

    def _make_stage_with_assets(self):
        """Build a NERStage with injected org assets matching the test CTI text."""
        from stages.ner import NERStage
        stage = NERStage(
            spacy_auto_download=False,
            profile_path="does-not-exist.json",
            sbom_path="does-not-exist.json",
        )
        # Inject minimal org assets relevant to the CTI text below
        stage._org_technologies  = frozenset({"vmware esxi", "microsoft exchange", "esxi"})
        stage._org_software      = frozenset({"vmware esxi", "esxi"})
        stage._org_geographies   = frozenset({"germany", "united kingdom"})
        stage._org_threat_actors = frozenset({"apt29", "cozy bear"})
        stage._org_sectors       = frozenset({"financial services"})
        stage._org_cpe_products  = frozenset()
        stage._org_sbom_term_map = {}
        stage._all_tech_terms    = stage._org_software | stage._org_technologies | stage._org_cpe_products
        stage._remaining_terms   = (stage._org_technologies | stage._org_cpe_products) - stage._org_sbom_term_map.keys()
        stage._sorted_extract_terms = sorted(
            stage._all_tech_terms | stage._org_geographies | stage._org_threat_actors,
            key=len, reverse=True,
        )
        return stage

    def test_software_entities_contain_esxi(self) -> None:
        stage = self._make_stage_with_assets()
        text = (
            "APT29 is exploiting CVE-2023-44487 against VMware ESXi hypervisors "
            "in Germany. Microsoft Exchange servers are also targeted."
        )
        event = CurationEvent(misp_id="1", misp_uuid="u1", raw={"info": text, "Attribute": []})
        result = stage.process(event)
        software_texts = {
            (item.get("text") or "").lower()
            for item in result.entities.get("software", [])
        }
        self.assertTrue(
            any("esxi" in t for t in software_texts),
            f"Expected 'esxi' in software entities; got {software_texts}",
        )

    def test_geographies_populated_from_text(self) -> None:
        stage = self._make_stage_with_assets()
        text = "Threat actors launched attacks from Russia targeting Germany and the United Kingdom."
        event = CurationEvent(misp_id="2", misp_uuid="u2", raw={"info": text, "Attribute": []})
        result = stage.process(event)
        geo_texts = {
            (item.get("text") or "").lower()
            for item in result.entities.get("geographies", [])
        }
        self.assertTrue(
            geo_texts & {"germany", "united kingdom"},
            f"Expected germany or united kingdom in geographies; got {geo_texts}",
        )

    def test_threat_actors_recognised(self) -> None:
        stage = self._make_stage_with_assets()
        text = "Cozy Bear, a Russian APT group also known as APT29, conducted the operation."
        event = CurationEvent(misp_id="3", misp_uuid="u3", raw={"info": text, "Attribute": []})
        result = stage.process(event)
        actor_texts = {
            (item.get("text") or "").lower()
            for item in result.entities.get("threat_actors", [])
        }
        self.assertTrue(
            actor_texts & {"apt29", "cozy bear"},
            f"Expected apt29 or cozy bear in threat_actors; got {actor_texts}",
        )


# ── spaCy auto-download (functional test) ─────────────────────────────────────

@_SKIP_NO_SPACY
class TestSpacyAutoDownload(unittest.TestCase):
    """Verify that NERStage.ensure_model() actually loads or downloads the model."""

    def test_ensure_model_returns_bool(self) -> None:
        from stages.ner import NERStage
        stage = NERStage(spacy_auto_download=False, profile_path="does-not-exist.json", sbom_path="does-not-exist.json")
        result = stage.ensure_model()
        self.assertIsInstance(result, bool)

    @unittest.skipUnless(_model_available(), f"Model '{_MODEL_NAME}' must be pre-installed for this test")
    def test_ensure_model_true_when_model_present(self) -> None:
        from stages.ner import NERStage
        stage = NERStage(spacy_auto_download=False, profile_path="does-not-exist.json", sbom_path="does-not-exist.json")
        self.assertTrue(stage.ensure_model())


if __name__ == "__main__":
    unittest.main()
