"""Unit tests for stages/ollama.py.

The stage hits a local HTTP service; in tests we patch `requests.post` so
nothing actually leaves the process. Coverage:

  - confidence below threshold is gated out (no HTTP call)
  - confidence above threshold produces a justification on the event
  - requests.RequestException is caught and recorded on llm_metadata
  - HTTP 5xx (raise_for_status) is caught the same way
  - the prompt includes the org name and matched SBOM refs
"""

import unittest
from unittest.mock import patch, MagicMock

import requests

from pipeline.event import CurationEvent
from stages.ollama import OllamaStage
from stages.scoring import BusinessProfile


def _profile() -> BusinessProfile:
    return BusinessProfile(
        name="Acme Retail",
        sectors=["retail"],
        technologies=["vmware esxi", "nginx"],
        geographies=["chicago"],
        keywords=[],
        specific_keywords=[],
    )


def _stage(threshold: float = 0.25) -> OllamaStage:
    return OllamaStage(
        base_url="http://127.0.0.1:11434",
        model="llama3.1:8b",
        threshold=threshold,
        profile=_profile(),
    )


def _event(confidence: float, **kw) -> CurationEvent:
    return CurationEvent(
        misp_id=kw.pop("misp_id", "1"),
        misp_uuid=kw.pop("misp_uuid", "u1"),
        raw=kw.pop("raw", {"info": "esxi rce advisory", "Attribute": []}),
        confidence=confidence,
        matched_sbom_components=kw.pop("matched_sbom_components", ["comp-esxi"]),
        matched_profile_terms=kw.pop("matched_profile_terms", ["esxi"]),
    )


class TestOllamaStageGating(unittest.TestCase):
    def test_below_threshold_skips_http_call(self) -> None:
        stage = _stage(threshold=0.25)
        event = _event(confidence=0.10)

        with patch("stages.ollama.requests.post") as mock_post:
            result = stage.process(event)

        mock_post.assert_not_called()
        self.assertEqual(result.llm_justification, "")
        self.assertEqual(result.llm_metadata, {})

    def test_at_threshold_triggers_http_call(self) -> None:
        stage = _stage(threshold=0.25)
        event = _event(confidence=0.25)

        with patch("stages.ollama.requests.post") as mock_post:
            mock_post.return_value = MagicMock(
                status_code=200,
                json=lambda: {"response": "  Relevant: ESXi is in the SBOM.  "},
            )
            mock_post.return_value.raise_for_status = MagicMock()
            result = stage.process(event)

        mock_post.assert_called_once()
        self.assertEqual(result.llm_justification, "Relevant: ESXi is in the SBOM.")
        self.assertEqual(result.llm_metadata["model"], "llama3.1:8b")
        self.assertIn("latency_ms", result.llm_metadata)
        self.assertNotIn("error", result.llm_metadata)


class TestOllamaStageResilience(unittest.TestCase):
    def test_request_exception_is_caught_and_recorded(self) -> None:
        stage = _stage()
        event = _event(confidence=0.40)

        with patch(
            "stages.ollama.requests.post",
            side_effect=requests.ConnectionError("connection refused"),
        ):
            result = stage.process(event)

        # Pipeline must not see the exception.
        self.assertEqual(result.llm_justification, "")
        self.assertIn("connection refused", result.llm_metadata["error"])
        self.assertEqual(result.llm_metadata["model"], "llama3.1:8b")

    def test_http_5xx_is_caught_and_recorded(self) -> None:
        stage = _stage()
        event = _event(confidence=0.40)

        bad_response = MagicMock(status_code=500)
        bad_response.raise_for_status.side_effect = requests.HTTPError("500 server error")

        with patch("stages.ollama.requests.post", return_value=bad_response):
            result = stage.process(event)

        self.assertEqual(result.llm_justification, "")
        self.assertIn("500", result.llm_metadata["error"])

    def test_malformed_json_is_caught(self) -> None:
        stage = _stage()
        event = _event(confidence=0.40)

        bad = MagicMock(status_code=200)
        bad.json.side_effect = ValueError("not json")
        bad.raise_for_status = MagicMock()

        with patch("stages.ollama.requests.post", return_value=bad):
            result = stage.process(event)

        self.assertEqual(result.llm_justification, "")
        self.assertEqual(result.llm_metadata["error"], "invalid_json")


class TestOllamaPromptShape(unittest.TestCase):
    def test_prompt_includes_org_and_sbom_context(self) -> None:
        stage = _stage()
        event = _event(confidence=0.60, matched_sbom_components=["comp-esxi", "comp-nginx"])

        captured = {}

        def fake_post(url, json, timeout):
            captured["url"] = url
            captured["payload"] = json
            mock = MagicMock(status_code=200, json=lambda: {"response": "ok"})
            mock.raise_for_status = MagicMock()
            return mock

        with patch("stages.ollama.requests.post", side_effect=fake_post):
            stage.process(event)

        self.assertEqual(captured["url"], "http://127.0.0.1:11434/api/generate")
        prompt = captured["payload"]["prompt"]
        self.assertIn("Acme Retail", prompt)
        self.assertIn("comp-esxi", prompt)
        self.assertIn("comp-nginx", prompt)
        self.assertIn("0.60", prompt)
        # Sanity-check the generation options are passed through.
        self.assertEqual(captured["payload"]["model"], "llama3.1:8b")
        self.assertFalse(captured["payload"]["stream"])
        self.assertLess(captured["payload"]["options"]["temperature"], 0.5)


if __name__ == "__main__":
    unittest.main()
