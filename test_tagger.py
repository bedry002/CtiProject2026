"""
Stage 5 - Tags each MISP event with a relevance label based on its confidence score.
"""

import logging
from pymisp import PyMISP, MISPTag
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

    def _remove_old_curation_tags(self, event_id):
        
        #Removes any existing curation:* tags from an event before we add the new one.
        #This means if you re-run the pipeline the tags don't stack up.
        
        try:
            event = self.client.get_event(event_id, pythonify=True)
            for tag in event.tags:
                if tag.name.startswith("curation:"):
                    self.client.untag(event_id, tag.name)
                    logger.debug("Removed old tag '%s' from event %s", tag.name, event_id)
        except Exception as e:
            logger.error("Failed to remove old tags from event %s: %s", event_id, e)

    def process(self, event):
        """
        Tags a single event in MISP based on its confidence score.
        Called automatically by the pipeline runner for each event.
        """
        # skip if the event hasn't been scored yet
        if event.confidence is None:
            logger.warning("Event %s has no confidence score, skipping tagger", event.misp_id)
            return event

        tag = get_relevance_tag(event.confidence)
        is_relevant = tag != "curation:relevance=not-relevant"

        if self.dry_run:
            logger.info(
                "[dry-run] Would tag event %s (confidence=%.4f) → %s",
                event.misp_id, event.confidence, tag
            )
            if not is_relevant:
                logger.info("[dry-run] Event %s would be filtered out of OpenCTI", event.misp_id)
            return event

        try:
            # clear old curation tags first so we don't get duplicates
            self._remove_old_curation_tags(event.misp_id)

            # apply the relevance tag
            self.client.tag(event.misp_id, tag)

            # apply the static tags every event gets
            self.client.tag(event.misp_id, "tlp:white")
            self.client.tag(event.misp_id, "feed:curated")

            logger.debug(
                "Tagged event %s → %s (confidence=%.4f)",
                event.misp_id, tag, event.confidence
            )

        except Exception as e:
            logger.error("Failed to tag event %s: %s", event.misp_id, e)

        return event
