import unittest

from pipeline.text import event_to_text


class TestEventTextBuilder(unittest.TestCase):
    def test_event_to_text_includes_core_fields(self) -> None:
        raw = {
            "info": "Incident title",
            "description": "Detailed description",
            "Tag": [{"name": "tlp:white"}],
            "Attribute": [
                {"type": "text", "value": "analyst note"},
                {"type": "vulnerability", "value": "CVE-2024-1234"},
                {"type": "md5", "value": "ignored-for-text-builder"},
            ],
            "Galaxy": [
                {
                    "GalaxyCluster": [
                        {"value": "APT29", "description": "threat actor cluster"}
                    ]
                }
            ],
        }

        text = event_to_text(raw)

        self.assertIn("Incident title", text)
        self.assertIn("Detailed description", text)
        self.assertIn("tlp:white", text)
        self.assertIn("analyst note", text)
        self.assertIn("CVE-2024-1234", text)
        self.assertIn("APT29", text)
        self.assertNotIn("ignored-for-text-builder", text)


if __name__ == "__main__":
    unittest.main()
