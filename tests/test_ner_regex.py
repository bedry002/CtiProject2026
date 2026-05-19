import unittest

from stages.ner import NERStage


class TestNerRegexExtraction(unittest.TestCase):
    def setUp(self) -> None:
        self.stage = NERStage(
            spacy_auto_download=False,
            profile_path="does-not-exist.json",
            sbom_path="does-not-exist.json",
        )

    def test_rejects_invalid_ipv4(self) -> None:
        text = "Indicators include 999.999.1.1 and 300.1.1.1"
        entities = self.stage._regex_entities(text)
        iocs = entities.get("iocs", [])
        self.assertFalse(any(ioc.get("type") == "ipv4" for ioc in iocs))

    def test_accepts_public_ipv4_and_modern_tld_domain(self) -> None:
        text = "Observed 8.8.8.8 beaconing to control.example.museum"
        entities = self.stage._regex_entities(text)
        iocs = entities.get("iocs", [])

        self.assertTrue(any(ioc.get("type") == "ipv4" and ioc.get("text") == "8.8.8.8" for ioc in iocs))
        self.assertTrue(any(ioc.get("type") == "domain" and ioc.get("text") == "control.example.museum" for ioc in iocs))

    def test_doc_scoped_only_suppresses_generic_signals(self) -> None:
        stage = NERStage(
            spacy_auto_download=False,
            profile_path="does-not-exist.json",
            sbom_path="does-not-exist.json",
            doc_scoped_only=True,
        )
        entities = stage._regex_entities("CVE-2024-12345 seen from 8.8.8.8 via control.example.museum")
        self.assertEqual(entities.get("cves"), [])
        self.assertEqual(entities.get("iocs"), [])


if __name__ == "__main__":
    unittest.main()
