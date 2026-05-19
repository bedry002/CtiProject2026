import unittest

from stages.ner import NERStage


class TestNerMatching(unittest.TestCase):
    def setUp(self) -> None:
        self.stage = NERStage(
            spacy_auto_download=False,
            profile_path="does-not-exist.json",
            sbom_path="does-not-exist.json",
        )
        self.stage._org_software = set()
        self.stage._org_technologies = {"active"}
        self.stage._org_sectors = {"retail"}
        self.stage._org_geographies = set()
        self.stage._org_cpe_products = set()
        self.stage._org_sbom_term_map = {}

    def test_term_boundary_prevents_substring_false_positive(self) -> None:
        entities = self.stage._regex_entities("proactive monitoring in operations")
        self.assertEqual(entities.get("software", []), [])

    def test_term_boundary_allows_exact_word_match(self) -> None:
        entities = self.stage._regex_entities("active exploitation reported")
        self.assertTrue(any(item.get("text") == "active" for item in entities.get("software", [])))

    def test_extract_relevant_chunks_returns_text_and_offset(self) -> None:
        self.stage._org_technologies = {"esxi"}
        chunks = self.stage._extract_relevant_chunks("prefix text about esxi and more", context_window=5)

        self.assertTrue(chunks)
        chunk_text, chunk_start = chunks[0]
        self.assertIsInstance(chunk_text, str)
        self.assertIsInstance(chunk_start, int)
        self.assertGreaterEqual(chunk_start, 0)


if __name__ == "__main__":
    unittest.main()
