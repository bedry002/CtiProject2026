"""Tests for stages/llm_enricher.py.

Covers: helper functions, skip logic, mocked HTTP calls, retry behaviour,
and an optional live integration test (skipped when LLM_API_KEY is absent).
"""

from __future__ import annotations

import json
import os
import unittest
from io import BytesIO
from unittest.mock import MagicMock, patch

from pipeline.event import CurationEvent
from stages.llm_enricher import (
    LLMEnricherStage,
    _extract_json_payload,
    _normalise_result,
    _sanitise_cti_text,
)


def _make_event(confidence: float = 0.60) -> CurationEvent:
    e = CurationEvent(misp_id="1", misp_uuid="abc", raw={"info": "Test event"})
    e.confidence = confidence
    return e


def _mock_response(payload: dict) -> MagicMock:
    """Return a context-manager mock that yields an HTTP response with *payload*.

    urlopen() is used as: ``with urlopen(req) as resp: data = json.loads(resp.read())``.
    So urlopen() must return a CM whose __enter__ yields an object with .read().
    """
    body = json.dumps({"choices": [{"message": {"content": json.dumps(payload)}}]}).encode()
    inner = MagicMock()
    inner.read = lambda: body
    cm = MagicMock()
    cm.__enter__ = MagicMock(return_value=inner)
    cm.__exit__ = MagicMock(return_value=False)
    return cm


#  Helper: _sanitise_cti_text 

class TestSanitiseCtiText(unittest.TestCase):

    def test_passes_through_plain_text(self) -> None:
        self.assertEqual(_sanitise_cti_text("Hello world"), "Hello world")

    def test_strips_null_bytes(self) -> None:
        self.assertNotIn("\x00", _sanitise_cti_text("bad\x00text"))

    def test_strips_unicode_direction_overrides(self) -> None:
        # U+202E RIGHT-TO-LEFT OVERRIDE (category Cf)
        self.assertNotIn("\u202E", _sanitise_cti_text("normal\u202Eevil"))

    def test_preserves_newlines_and_tabs(self) -> None:
        text = "line1\nline2\ttabbed"
        self.assertEqual(_sanitise_cti_text(text), text)

    def test_truncates_to_1200_chars(self) -> None:
        long_text = "A" * 2000
        self.assertEqual(len(_sanitise_cti_text(long_text)), 1200)

    def test_empty_string(self) -> None:
        self.assertEqual(_sanitise_cti_text(""), "")


#  Helper: _extract_json_payload 

class TestExtractJsonPayload(unittest.TestCase):

    def test_clean_json_object(self) -> None:
        payload = {"analyst_summary": "ok", "matched_dimensions": [], "implicit_relevance_flags": []}
        result = _extract_json_payload(json.dumps(payload))
        self.assertEqual(result["analyst_summary"], "ok")

    def test_json_embedded_in_prose(self) -> None:
        prose = 'Here is my answer: {"analyst_summary": "embedded", "matched_dimensions": [], "implicit_relevance_flags": []} Done.'
        result = _extract_json_payload(prose)
        self.assertEqual(result["analyst_summary"], "embedded")

    def test_raises_on_no_json(self) -> None:
        with self.assertRaises(ValueError):
            _extract_json_payload("no braces here")

    def test_raises_on_unbalanced_braces(self) -> None:
        with self.assertRaises(ValueError):
            _extract_json_payload('{"key": "value"')

    def test_nested_json_extracts_outer(self) -> None:
        payload = {"outer": {"inner": 1}, "analyst_summary": "nested", "matched_dimensions": [], "implicit_relevance_flags": []}
        result = _extract_json_payload(json.dumps(payload))
        self.assertIn("outer", result)


#  Helper: _normalise_result 

class TestNormaliseResult(unittest.TestCase):

    def test_fills_missing_keys(self) -> None:
        result = _normalise_result({})
        self.assertEqual(result["analyst_summary"], "")
        self.assertEqual(result["matched_dimensions"], [])
        self.assertEqual(result["implicit_relevance_flags"], [])

    def test_strips_whitespace_from_summary(self) -> None:
        result = _normalise_result({"analyst_summary": "  hello  "})
        self.assertEqual(result["analyst_summary"], "hello")

    def test_coerces_non_list_dimensions(self) -> None:
        result = _normalise_result({"matched_dimensions": "not a list"})
        self.assertEqual(result["matched_dimensions"], [])

    def test_non_dict_input_returns_defaults(self) -> None:
        result = _normalise_result("garbage")  # type: ignore[arg-type]
        self.assertEqual(result["analyst_summary"], "")

    def test_preserves_valid_flags(self) -> None:
        result = _normalise_result({"implicit_relevance_flags": ["supply-chain"]})
        self.assertEqual(result["implicit_relevance_flags"], ["supply-chain"])


#  LLMEnricherStage: skip logic 

class TestLLMEnricherSkipLogic(unittest.TestCase):

    def test_skips_when_no_api_key(self) -> None:
        stage = LLMEnricherStage(api_key="", min_confidence=0.10)
        event = _make_event(confidence=0.80)
        result = stage.process(event)
        self.assertIsNone(result.analyst_summary)

    def test_skips_when_confidence_below_threshold(self) -> None:
        stage = LLMEnricherStage(api_key="test-key", min_confidence=0.50)
        event = _make_event(confidence=0.30)

        with patch("stages.llm_enricher._urllib_request.urlopen") as mock_open:
            stage.process(event)
            mock_open.assert_not_called()

        self.assertIsNone(event.analyst_summary)

    def test_processes_when_confidence_meets_threshold(self) -> None:
        stage = LLMEnricherStage(api_key="test-key", min_confidence=0.50)
        event = _make_event(confidence=0.50)

        good_response = {
            "analyst_summary": "A critical threat targeting financial systems.",
            "matched_dimensions": ["sector"],
            "implicit_relevance_flags": [],
        }
        with patch("stages.llm_enricher._urllib_request.urlopen", return_value=_mock_response(good_response)):
            stage.process(event)

        self.assertEqual(event.analyst_summary, "A critical threat targeting financial systems.")


#  LLMEnricherStage: mocked HTTP 

class TestLLMEnricherHTTP(unittest.TestCase):

    def _stage(self, model: str = "test-model", **kw) -> LLMEnricherStage:
        return LLMEnricherStage(
            api_key="test-key",
            api_url="http://fake.local/v1/chat/completions",
            model=model,
            min_confidence=0.10,
            **kw,
        )

    def test_sends_post_with_bearer_token(self) -> None:
        stage = self._stage()
        event = _make_event()

        captured: list = []

        def fake_urlopen(req, timeout=None):
            captured.append(req)
            return _mock_response({"analyst_summary": "ok", "matched_dimensions": [], "implicit_relevance_flags": []})

        with patch("stages.llm_enricher._urllib_request.urlopen", side_effect=fake_urlopen):
            stage.process(event)

        self.assertEqual(len(captured), 1)
        req = captured[0]
        self.assertEqual(req.get_header("Authorization"), "Bearer test-key")
        self.assertEqual(req.get_method(), "POST")

    def test_analyst_summary_written_to_event(self) -> None:
        stage = self._stage()
        event = _make_event()

        resp = {"analyst_summary": "Ransomware targeting healthcare.", "matched_dimensions": ["sector"], "implicit_relevance_flags": ["supply-chain"]}
        with patch("stages.llm_enricher._urllib_request.urlopen", return_value=_mock_response(resp)):
            stage.process(event)

        self.assertEqual(event.analyst_summary, "Ransomware targeting healthcare.")
        self.assertIn("supply-chain", event.implicit_relevance_flags)

    def test_payload_contains_model_and_messages(self) -> None:
        stage = self._stage(model="my-model")
        event = _make_event()

        captured_body: list[dict] = []

        def fake_urlopen(req, timeout=None):
            captured_body.append(json.loads(req.data))
            return _mock_response({"analyst_summary": "x", "matched_dimensions": [], "implicit_relevance_flags": []})

        with patch("stages.llm_enricher._urllib_request.urlopen", side_effect=fake_urlopen):
            stage.process(event)

        body = captured_body[0]
        self.assertEqual(body["model"], "my-model")
        roles = [m["role"] for m in body["messages"]]
        self.assertIn("system", roles)
        self.assertIn("user", roles)

    def test_graceful_fallback_on_empty_choices(self) -> None:
        stage = self._stage()
        event = _make_event()

        empty_response = json.dumps({"choices": []}).encode()
        cm = MagicMock()
        cm.__enter__ = lambda s: MagicMock(read=lambda: empty_response)
        cm.__exit__ = MagicMock(return_value=False)

        with patch("stages.llm_enricher._urllib_request.urlopen", return_value=cm):
            with patch("time.sleep"):
                stage.process(event)

        self.assertEqual(event.analyst_summary, "")


#  LLMEnricherStage: retry behaviour 

class TestLLMEnricherRetry(unittest.TestCase):

    def test_retries_on_url_error_then_succeeds(self) -> None:
        from urllib.error import URLError

        stage = LLMEnricherStage(api_key="test-key", min_confidence=0.10)
        event = _make_event()

        good_resp = _mock_response({"analyst_summary": "ok after retry", "matched_dimensions": [], "implicit_relevance_flags": []})

        call_count = 0

        def fail_then_succeed(req, timeout=None):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise URLError("transient")
            return good_resp

        with patch("stages.llm_enricher._urllib_request.urlopen", side_effect=fail_then_succeed):
            with patch("time.sleep"):
                stage.process(event)

        self.assertEqual(call_count, 2)
        self.assertEqual(event.analyst_summary, "ok after retry")

    def test_exhausts_retries_and_falls_back(self) -> None:
        from urllib.error import URLError

        stage = LLMEnricherStage(api_key="test-key", min_confidence=0.10)
        event = _make_event()

        with patch("stages.llm_enricher._urllib_request.urlopen", side_effect=URLError("always fails")):
            with patch("time.sleep"):
                stage.process(event)

        self.assertEqual(event.analyst_summary, "")

    def test_retry_uses_exponential_backoff(self) -> None:
        from urllib.error import URLError

        stage = LLMEnricherStage(api_key="test-key", min_confidence=0.10)
        event = _make_event()
        sleep_calls: list[int] = []

        with patch("stages.llm_enricher._urllib_request.urlopen", side_effect=URLError("fail")):
            with patch("time.sleep", side_effect=lambda d: sleep_calls.append(d)):
                stage.process(event)

        # Exponential: attempt 0 → sleep(1), attempt 1 → sleep(2), attempt 2 → no sleep
        self.assertEqual(sleep_calls, [1, 2])


#  Live integration test (skipped unless LLM_API_KEY is set) 

@unittest.skipUnless(os.environ.get("LLM_API_KEY"), "LLM_API_KEY not set — skipping live LLM test")
class TestLLMEnricherLiveIntegration(unittest.TestCase):

    def test_returns_non_empty_analyst_summary(self) -> None:
        stage = LLMEnricherStage(min_confidence=0.10)
        event = _make_event(confidence=0.75)
        event.raw = {"info": "APT29 exploited CVE-2023-44487 (HTTP/2 Rapid Reset) against cloud infrastructure."}
        event.entities = {"_raw_text": event.raw["info"], "threat_actors": [{"text": "APT29"}], "cves": [{"text": "CVE-2023-44487"}]}
        event.score_breakdown = {"asset": 0.40, "tech": 0.20}
        event.matched_profile_terms = ["cloud", "infrastructure"]
        event.matched_sbom_components = []

        stage.process(event)

        self.assertIsNotNone(event.analyst_summary)
        self.assertGreater(len(event.analyst_summary), 20, "Expected a substantive analyst summary")


if __name__ == "__main__":
    unittest.main()
