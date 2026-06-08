"""Stage 5 — Tags each MISP event with a relevance label based on its confidence score."""

from __future__ import annotations

import logging

from pymisp import MISPAttribute, MISPEvent, MISPTag, PyMISP

from pipeline.base import Stage
from pipeline.constants import BAND_HIGH, BAND_MEDIUM, BAND_LOW
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)

TAG_NAMESPACE = "curation"

_CURATION_TAGS = [
    "curation:relevance=high",
    "curation:relevance=medium",
    "curation:relevance=low",
    "curation:relevance=not-relevant",
]


def get_relevance_tag(confidence: float) -> str:
    if confidence >= BAND_HIGH:
        return "curation:relevance=high"
    if confidence >= BAND_MEDIUM:
        return "curation:relevance=medium"
    if confidence >= BAND_LOW:
        return "curation:relevance=low"
    return "curation:relevance=not-relevant"


class MISPTaggerStage(Stage):
    """Writes a relevance tag and curation attributes to each event in MISP.

    Set ``dry_run=True`` to log what would be written without touching MISP.
    """

    @property
    def name(self) -> str:
        return "tagger"

    def __init__(self, client: PyMISP, dry_run: bool = True) -> None:
        self.client  = client
        self.dry_run = dry_run
        self._setup_tags()

    def _setup_tags(self) -> None:
        required_tags = {
            "curation:relevance=high":         "#721c24",  # red
            "curation:relevance=medium":       "#856404",  # amber
            "curation:relevance=low":          "#1a7a3e",  # green
            "curation:relevance=not-relevant": "#6c757d",  # grey
            "tlp:white":                       "#ffffff",
            "feed:curated":                    "#0d6efd",
        }
        if self.dry_run:
            logger.info("[dry-run] Would create tags if missing: %s", list(required_tags.keys()))
            return
        try:
            existing = {t.name for t in self.client.tags(pythonify=True)}
        except Exception as exc:
            logger.error("Couldn't fetch existing tags from MISP: %s", exc)
            return
        for tag_name, colour in required_tags.items():
            if tag_name not in existing:
                new_tag = MISPTag()
                new_tag.from_dict(name=tag_name, colour=colour, exportable=False)
                self.client.add_tag(new_tag)
                logger.info("Created missing tag in MISP: %s", tag_name)

    def process(self, event: CurationEvent) -> CurationEvent:
        if event.confidence is None:
            logger.warning("Event %s has no confidence score, skipping tagger", event.misp_id)
            return event

        tag        = get_relevance_tag(event.confidence)
        is_relevant = tag != "curation:relevance=not-relevant"

        if self.dry_run:
            logger.info(
                "[dry-run] Would tag event %s (confidence=%.4f) → %s | breakdown: %s",
                event.misp_id, event.confidence, tag,
                ", ".join(f"{k}={v:.3f}" for k, v in event.score_breakdown.items()),
            )
            if event.analyst_summary:
                logger.info(
                    "[dry-run] Would write analyst summary to event %s: %s",
                    event.misp_id, event.analyst_summary[:120],
                )
            if not is_relevant:
                logger.info("[dry-run] Event %s would be excluded from curated feed", event.misp_id)
            return event

        try:
            uuid       = event.misp_uuid
            misp_event = self.client.get_event(uuid, pythonify=True)

            self._remove_old_curation_tags(uuid)
            self.client.tag(uuid, tag)
            if is_relevant:
                self.client.tag(uuid, "tlp:white")
                self.client.tag(uuid, "feed:curated")

            self._upsert_score_attribute(misp_event, uuid, event)
            self._upsert_analyst_summary_attribute(misp_event, uuid, event)

            logger.info("Tagged event %s → %s (confidence=%.4f)", event.misp_id, tag, event.confidence)
        except Exception as exc:
            logger.error("Failed to tag event %s: %s", event.misp_id, exc)

        return event

    def _remove_old_curation_tags(self, uuid: str) -> None:
        """Brute-force remove all curation tags by UUID — avoids stale event object issues."""
        for tag_name in _CURATION_TAGS:
            try:
                self.client.untag(uuid, tag_name)
                logger.debug("Removed tag '%s' from event %s", tag_name, uuid)
            except Exception:
                pass  # tag wasn't present, that's fine

    def _upsert_score_attribute(self, misp_event: MISPEvent, uuid: str, event: CurationEvent) -> None:
        breakdown   = event.score_breakdown
        score_lines = [f"curation-confidence: {event.confidence:.4f}"]
        if breakdown:
            score_lines.append("breakdown: " + ", ".join(f"{k}={v:.3f}" for k, v in breakdown.items()))
        if event.matched_sbom_components:
            score_lines.append(f"sbom-hits: {', '.join(event.matched_sbom_components)}")
        if event.matched_profile_terms:
            score_lines.append(f"keyword-hits: {', '.join(event.matched_profile_terms[:8])}")

        try:
            for attr in misp_event.attributes:
                if getattr(attr, "comment", "") == "curation-score":
                    self.client.delete_attribute(attr.id)
            attr = MISPAttribute()
            attr.from_dict(type="text", category="External analysis",
                           value="\n".join(score_lines), comment="curation-score",
                           to_ids=False, distribution=0)
            self.client.add_attribute(uuid, attr)
            logger.debug("Added curation score attribute to event %s", uuid)
        except Exception as exc:
            logger.error("Failed to write score attribute to event %s: %s", uuid, exc)

    def _upsert_analyst_summary_attribute(self, misp_event: MISPEvent, uuid: str, event: CurationEvent) -> None:
        if not event.analyst_summary:
            return
        lines = [event.analyst_summary]
        if event.implicit_relevance_flags:
            lines.append("Flags: " + "; ".join(event.implicit_relevance_flags))
        try:
            for attr in misp_event.attributes:
                if getattr(attr, "comment", "") == "curation-summary":
                    self.client.delete_attribute(attr.id)
            attr = MISPAttribute()
            attr.from_dict(type="text", category="External analysis",
                           value="\n".join(lines), comment="curation-summary",
                           to_ids=False, distribution=0)
            self.client.add_attribute(uuid, attr)
            logger.debug("Added curation summary attribute to event %s", uuid)
        except Exception as exc:
            logger.error("Failed to write summary attribute to event %s: %s", uuid, exc)
