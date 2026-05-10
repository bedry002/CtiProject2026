"""Stage — write curation confidence scores back to MISP as custom tags."""

import logging
from typing import cast
from pymisp import PyMISP, MISPTag, MISPEvent
from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)

# Tag namespace used for all curation tags on MISP events
_NS = "curation"

_BANDS = [
    (0.50, "high"),
    (0.25, "medium"),
    (0.10, "low"),
]


def _confidence_tag(confidence: float) -> str:
    for threshold, label in _BANDS:
        if confidence >= threshold:
            return f"{_NS}:relevance={label}"
    return f"{_NS}:relevance=not-relevant"


class MISPTaggerStage(Stage):
    """Adds a curation relevance tag to each event in MISP.

    Tags applied:
      curation:relevance=high      confidence >= 0.15
      curation:relevance=medium    confidence >= 0.08
      curation:relevance=low       confidence >= 0.05
      curation:relevance=not-relevant  below threshold

    Only events whose confidence has been set are tagged.
    Existing curation tags on the event are replaced.
    """

    @property
    def name(self) -> str:
        return "misp_tagger"

    def __init__(self, client: PyMISP, dry_run: bool = True) -> None:
        self._client = client
        self._dry_run = dry_run
        self._ensure_tags_exist()

    def _ensure_tags_exist(self) -> None:
        """Create the curation taxonomy tags in MISP if they don't exist yet."""
        needed = {
            f"{_NS}:relevance=high":         ("#1a7a3e", False),
            f"{_NS}:relevance=medium":       ("#856404", False),
            f"{_NS}:relevance=low":          ("#721c24", False),
            f"{_NS}:relevance=not-relevant": ("#6c757d", False),
        }
        if self._dry_run:
            logger.info("[dry-run] Would ensure tags exist: %s", list(needed))
            return

        existing = {t.name for t in cast(list[MISPTag], self._client.tags(pythonify=True))} 
        for name, (colour, exportable) in needed.items():
            if name not in existing:
                tag_obj = MISPTag()
                tag_obj.from_dict(name=name, colour=colour, exportable=exportable)
                self._client.add_tag(tag_obj)  
                logger.info("Created MISP tag: %s", name)

    def _remove_old_curation_tags(self, event_id: str) -> None:
        """Strip any existing curation tags before applying the new one."""
        misp_event = cast(MISPEvent, self._client.get_event(event_id, pythonify=True)) 
        for tag in misp_event.tags:
            if tag.name.startswith(f"{_NS}:"):
                self._client.untag(event_id, tag.name)  

    def process(self, event: CurationEvent) -> CurationEvent:
        if event.confidence is None:
            return event

        tag = _confidence_tag(event.confidence)

        if self._dry_run:
            logger.info("[dry-run] Would tag event %s → %s", event.misp_id, tag)
            return event

        try:
            self._remove_old_curation_tags(event.misp_id)
            self._client.tag(event.misp_id, tag)
            logger.debug("Tagged event %s → %s", event.misp_id, tag)
        except Exception:
            logger.exception("Failed to tag event %s", event.misp_id)

        return event
