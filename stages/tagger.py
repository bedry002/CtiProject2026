"""
Stage 5 - Tags each MISP event with a relevance label based on its confidence score.
"""

import logging
from pymisp import PyMISP, MISPTag, MISPAttribute
from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)

# namespace for all tags this stage creates
TAG_NAMESPACE = "curation"

# confidence thresholds for each band
# these match the scoring bands defined in scoring.py
BAND_HIGH   = 0.50
BAND_MEDIUM = 0.25
BAND_LOW    = 0.10


def get_relevance_tag(confidence):
    # work out which tag to apply based on the confidence score
    if confidence >= BAND_HIGH:
        return "curation:relevance=high"
    elif confidence >= BAND_MEDIUM:
        return "curation:relevance=medium"
    elif confidence >= BAND_LOW:
        return "curation:relevance=low"
    else:
        return "curation:relevance=not-relevant"


class MISPTaggerStage(Stage):
    
    #Writes a relevance tag to each event in MISP after it has been scored.

    #Set dry_run=True to test without actually writing to MISP.
    

    @property
    def name(self):
        return "misp_tagger"

    def __init__(self, client, dry_run=True):
        self.client = client
        self.dry_run = dry_run

        # create the tags in MISP if they don't already exist
        self._setup_tags()

    def _setup_tags(self):

        # all the tags we need
        required_tags = {
            "curation:relevance=high":         "#1a7a3e",
            "curation:relevance=medium":       "#856404",
            "curation:relevance=low":          "#721c24",
            "curation:relevance=not-relevant": "#6c757d",
            "tlp:white":                       "#ffffff",
            "feed:curated":                    "#0d6efd",
        }

        if self.dry_run:
            logger.info("[dry-run] Would create tags if missing: %s", list(required_tags.keys()))
            return

        # get all the tags that already exist in MISP
        try:
            existing_tags = {t.name for t in self.client.tags(pythonify=True)}
        except Exception as e:
            logger.error("Couldn't fetch existing tags from MISP: %s", e)
            return

        # create any that are missing
        for tag_name, colour in required_tags.items():
            if tag_name not in existing_tags:
                new_tag = MISPTag()
                new_tag.from_dict(name=tag_name, colour=colour, exportable=False)
                self.client.add_tag(new_tag)
                logger.info("Created missing tag in MISP: %s", tag_name)

    def _remove_old_curation_tags(self, event_uuid: str) -> None:
        """Remove existing curation:* tags before applying the updated one."""
        try:
            misp_event = self.client.get_event(event_uuid, pythonify=True)
            for tag in misp_event.tags:
                if tag.name.startswith("curation:"):
                    self.client.untag(event_uuid, tag.name)
                    logger.debug("Removed old tag '%s' from event %s", tag.name, event_uuid)
        except Exception as e:
            logger.error("Failed to remove old tags from event %s: %s", event_uuid, e)

    def _upsert_score_attribute(self, event_uuid: str, event: CurationEvent) -> None:
        """Write the curation confidence score as a text attribute on the event.

        If a curation score attribute already exists (from a previous run) it is
        deleted first so re-runs update rather than accumulate attributes.
        The attribute is marked to_ids=False and non-exportable so it stays local
        to this MISP instance and doesn't pollute shared feeds.
        """
        # Build the score string — include breakdown for auditability
        breakdown = event.score_breakdown
        score_lines = [f"curation-confidence: {event.confidence:.4f}"]
        if breakdown:
            score_lines.append(
                "breakdown: "
                + ", ".join(f"{k}={v:.3f}" for k, v in breakdown.items())
            )
        if event.topic_label:
            score_lines.append(f"topic: {event.topic_label}")
        if event.matched_sbom_components:
            score_lines.append(f"sbom-hits: {', '.join(event.matched_sbom_components)}")
        if event.matched_profile_terms:
            score_lines.append(f"keyword-hits: {', '.join(event.matched_profile_terms[:8])}")
        score_value = "\n".join(score_lines)

        try:
            misp_event = self.client.get_event(event_uuid, pythonify=True)

            # Remove any existing curation score attribute from previous runs
            for attr in misp_event.attributes:
                if getattr(attr, "comment", "") == "curation-score":
                    self.client.delete_attribute(attr.id)
                    logger.debug("Deleted old curation score attribute from event %s", event_uuid)

            # Add fresh score attribute
            attr = MISPAttribute()
            attr.from_dict(
                type="text",
                category="External analysis",
                value=score_value,
                comment="curation-score",
                to_ids=False,
                distribution=0,   # local only — not exported with the event
            )
            self.client.add_attribute(event_uuid, attr)
            logger.debug("Added curation score attribute to event %s", event_uuid)

        except Exception as e:
            logger.error("Failed to write score attribute to event %s: %s", event_uuid, e)

    def process(self, event: CurationEvent) -> CurationEvent:
        if event.confidence is None:
            logger.warning("Event %s has no confidence score, skipping tagger", event.misp_id)
            return event

        tag = get_relevance_tag(event.confidence)
        is_relevant = tag != "curation:relevance=not-relevant"

        if self.dry_run:
            logger.info(
                "[dry-run] Would tag event %s (confidence=%.4f) → %s | breakdown: %s",
                event.misp_id, event.confidence, tag,
                ", ".join(f"{k}={v:.3f}" for k, v in event.score_breakdown.items()),
            )
            if not is_relevant:
                logger.info(
                    "[dry-run] Event %s would be excluded from curated feed",
                    event.misp_id,
                )
            return event

        try:
            # UUID is required by MISP's tag/untag API — numeric ID causes 500
            uuid = event.misp_uuid or event.raw.get("uuid", event.misp_id)

            self._remove_old_curation_tags(uuid)
            self.client.tag(uuid, tag)

            if is_relevant:
                self.client.tag(uuid, "tlp:white")
                self.client.tag(uuid, "feed:curated")

            self._upsert_score_attribute(uuid, event)

            logger.debug(
                "Tagged event %s → %s (confidence=%.4f)",
                event.misp_id, tag, event.confidence,
            )
        except Exception as e:
            logger.error("Failed to tag event %s: %s", event.misp_id, e)

        return event
