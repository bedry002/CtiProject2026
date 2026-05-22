"""Stage 5 — LLM-based relevance justification via a local Ollama daemon.

Runs *after* ScoringStage, so the deterministic confidence score is
already set. Only events whose confidence meets `threshold` are sent to
the model — that keeps the per-batch wall time bounded even on a CPU-only
host where each call is ~2–10s.

The stage never raises into the pipeline. Any error (Ollama down, model
not pulled, HTTP timeout, malformed JSON) is logged and recorded on
`event.llm_metadata["error"]`; the event continues downstream with an
empty `llm_justification`.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING

import requests

from pipeline.base import Stage
from pipeline.event import CurationEvent
from pipeline.text import event_to_text

if TYPE_CHECKING:
    from stages.scoring import BusinessProfile

logger = logging.getLogger(__name__)


_PROMPT_TEMPLATE = """You are a CTI analyst assistant.

A scoring pipeline has flagged the MISP event below as potentially relevant
to the following organisation. Decide whether the event is genuinely
relevant and, in 2–3 sentences, explain *why* — naming the specific
component, technology, or attacker behaviour that ties the event to the
organisation. If the event is not actually relevant, say so plainly and
briefly explain what about the scoring signal was misleading.

Do not restate the event. Do not include preambles like "Here is my
analysis". Output the justification text only.

--- ORGANISATION ---
Name: {org_name}
Sectors: {sectors}
Key technologies: {technologies}
Matched SBOM components: {matched_components}
Matched profile terms: {matched_terms}
Confidence score: {confidence:.2f}

--- EVENT ---
{event_text}
""".strip()


# Hard cap on the event text we send — large MISP events with hundreds of
# IOCs can blow past the model's context window. The first ~6k chars
# cover the info field, tags, and the head of the attribute list, which
# is what the model needs to reason about relevance.
_EVENT_TEXT_BUDGET = 6000


class OllamaStage(Stage):
    """Post-scoring enrichment: writes a natural-language justification."""

    @property
    def name(self) -> str:
        return "ollama"

    def __init__(
        self,
        base_url: str,
        model: str,
        threshold: float,
        profile: "BusinessProfile",
        timeout_s: float = 60.0,
        num_predict: int = 220,
    ) -> None:
        self._url = base_url.rstrip("/") + "/api/generate"
        self._model = model
        self._threshold = threshold
        self._profile = profile
        self._timeout = timeout_s
        self._num_predict = num_predict

    def process(self, event: CurationEvent) -> CurationEvent:
        conf = event.confidence or 0.0
        if conf < self._threshold:
            # Gated out — don't even build the prompt.
            return event

        prompt = self._build_prompt(event)
        started = time.monotonic()

        try:
            response = requests.post(
                self._url,
                json={
                    "model": self._model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,        # low — we want stable justifications
                        "num_predict": self._num_predict,
                    },
                },
                timeout=self._timeout,
            )
            response.raise_for_status()
            text = (response.json().get("response") or "").strip()
        except requests.RequestException as exc:
            elapsed_ms = int((time.monotonic() - started) * 1000)
            logger.warning(
                "Ollama call failed for event %s (%.0fms): %s",
                event.misp_id, elapsed_ms, exc,
            )
            event.llm_metadata = {
                "model": self._model,
                "latency_ms": elapsed_ms,
                "error": str(exc),
            }
            return event
        except ValueError as exc:  # json decode failed
            elapsed_ms = int((time.monotonic() - started) * 1000)
            logger.warning(
                "Ollama returned non-JSON for event %s (%.0fms): %s",
                event.misp_id, elapsed_ms, exc,
            )
            event.llm_metadata = {
                "model": self._model,
                "latency_ms": elapsed_ms,
                "error": "invalid_json",
            }
            return event

        elapsed_ms = int((time.monotonic() - started) * 1000)
        event.llm_justification = text
        event.llm_metadata = {
            "model": self._model,
            "latency_ms": elapsed_ms,
        }
        logger.info(
            "Ollama enriched event %s in %dms (%d chars)",
            event.misp_id, elapsed_ms, len(text),
        )
        return event

    def _build_prompt(self, event: CurationEvent) -> str:
        event_text = event_to_text(event.raw)
        if len(event_text) > _EVENT_TEXT_BUDGET:
            event_text = event_text[:_EVENT_TEXT_BUDGET] + "\n[... truncated ...]"

        return _PROMPT_TEMPLATE.format(
            org_name=self._profile.name,
            sectors=", ".join(self._profile.sectors) or "n/a",
            technologies=", ".join(self._profile.technologies[:25]) or "n/a",
            matched_components=", ".join(event.matched_sbom_components) or "none",
            matched_terms=", ".join(event.matched_profile_terms[:15]) or "none",
            confidence=event.confidence or 0.0,
            event_text=event_text,
        )
