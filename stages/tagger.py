"""Stage 5 — Tags each MISP event with a relevance label based on its confidence score."""

from __future__ import annotations #this allows python to refer to classes before fully loaded

import logging #used for messages

from pymisp import MISPAttribute, MISPEvent, MISPTag, PyMISP #these all come from pymisp
#mispevent is broken down into: ip, domain, tags. misptag represents a tag
#pymisp is the api client library for misp
from pipeline.base import Stage # this imports the base stage class
from pipeline.constants import BAND_HIGH, BAND_MEDIUM, BAND_LOW #scoring thresholds
from pipeline.event import CurationEvent #the shared event object flowing through pipeline

logger = logging.getLogger(__name__) #creates a logger for this file

TAG_NAMESPACE = "curation" #namespace used for custom tags

_CURATION_TAGS = [
    "curation:relevance=high",
    "curation:relevance=medium",
    "curation:relevance=low",
    "curation:relevance=not-relevant",
]
#these are the relevancy tags also used later to remove old tags

def get_relevance_tag(confidence: float) -> str: #takes confidence score
    if confidence >= BAND_HIGH:
        return "curation:relevance=high"
    if confidence >= BAND_MEDIUM:
        return "curation:relevance=medium"
    if confidence >= BAND_LOW:
        return "curation:relevance=low"
    return "curation:relevance=not-relevant"
#if confidence =0.91 then it get_relevance_tag will return "curation:relevance=high"
#if not relevant it will return "curation:relevance=not-relevant"
class MISPTaggerStage(Stage): #creates the tagging stage
    """Writes a relevance tag and curation attributes to each event in MISP.

    Set ``dry_run=True`` to log what would be written without touching MISP.
    """

    @property
    def name(self) -> str:
        return "tagger" #this returns the name of the stage

    def __init__(self, client: PyMISP, dry_run: bool = True) -> None: #called when stage is created
        self.client  = client #stores misp connection
        self.dry_run = dry_run #controls whether or not the chanes actually happen, if dryrun=true then it only logs
        self._setup_tags() #makes sure the tags actually exist

    def _setup_tags(self) -> None: #checks if tags exists, then creates them if not
        required_tags = { #tag dictionary with colours for each tag
            "curation:relevance=high":         "#721c24",  # red
            "curation:relevance=medium":       "#856404",  # amber
            "curation:relevance=low":          "#1a7a3e",  # green
            "curation:relevance=not-relevant": "#6c757d",  # grey
            "tlp:white":                       "#ffffff",
            "feed:curated":                    "#0d6efd",
        }
        if self.dry_run:
            logger.info("[dry-run] Would create tags if missing: %s", list(required_tags.keys())) #logs the tags that would be assigned, doesnt actually assign
            return
        try:
            existing = {t.name for t in self.client.tags(pythonify=True)} #fetches all tags from misp
        except Exception as exc:
            logger.error("Couldn't fetch existing tags from MISP: %s", exc)
            return
        for tag_name, colour in required_tags.items():
            if tag_name not in existing: #if tag is missing
                new_tag = MISPTag() #creats tag object
                new_tag.from_dict(name=tag_name, colour=colour, exportable=False)
                self.client.add_tag(new_tag)#send to misp
                logger.info("Created missing tag in MISP: %s", tag_name)
                #creates the tag in misp and then logs it was created
    def process(self, event: CurationEvent) -> CurationEvent: #main function, all events go through
        if event.confidence is None: #if there is no confidence score
            logger.warning("Event %s has no confidence score, skipping tagger", event.misp_id)
            return event

        tag = get_relevance_tag(event.confidence) #gets the tag based on the score
        is_relevant = tag != "curation:relevance=not-relevant" #relevance check

        if self.dry_run: #if dry run is true then it only logs not applies tags
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
            uuid = event.misp_uuid #gets the misp uuid
            misp_event = self.client.get_event(uuid, pythonify=True) #downloads the event from misp

            self._remove_old_curation_tags(uuid) #suppose the event already has a relevance tag, score changes so 
            self.client.tag(uuid, tag) #applies the new tag
            if is_relevant: #only for tags low,med,high not for irrelevant
                self.client.tag(uuid, "tlp:white")
                self.client.tag(uuid, "feed:curated")

            self._upsert_score_attribute(misp_event, uuid, event) #stores the score and brekadown in the event
            self._upsert_analyst_summary_attribute(misp_event, uuid, event)#stores the llm summary

            logger.info("Tagged event %s → %s (confidence=%.4f)", event.misp_id, tag, event.confidence)
        except Exception as exc:
            logger.error("Failed to tag event %s: %s", event.misp_id, exc)

        return event

    def _remove_old_curation_tags(self, uuid: str) -> None: #loops through
        """brute-force remove all curation tags by UUID — avoids stale event object issues."""
        for tag_name in _CURATION_TAGS: #removes all curation tags
            try:
                self.client.untag(uuid, tag_name)
                logger.debug("Removed tag '%s' from event %s", tag_name, uuid) #incase there is a medium but gets changed to a high, cant have both tags
            except Exception:
                pass  # tag wasn't present, that's fine

    def _upsert_score_attribute(self, misp_event: MISPEvent, uuid: str, event: CurationEvent) -> None:
        breakdown   = event.score_breakdown
        score_lines = [f"curation-confidence: {event.confidence:.4f}"] #builds score line
        if breakdown: #keywords,sbom,actor etc hits
            score_lines.append("breakdown: " + ", ".join(f"{k}={v:.3f}" for k, v in breakdown.items()))
        if event.matched_sbom_components: #named sbom hits
            score_lines.append(f"sbom-hits: {', '.join(event.matched_sbom_components)}")
        if event.matched_profile_terms: #named keyword hits
            score_lines.append(f"keyword-hits: {', '.join(event.matched_profile_terms[:8])}")

        try:
            for attr in misp_event.attributes:
                if getattr(attr, "comment", "") == "curation-score": #finds old score if there
                    self.client.delete_attribute(attr.id) #deletes old score
            attr = MISPAttribute() #creates new score attribute
            attr.from_dict(type="text", category="External analysis",
                           value="\n".join(score_lines), comment="curation-score",
                           to_ids=False, distribution=0)
                        #creates type, category,comment etc for the attribute
            self.client.add_attribute(uuid, attr) #writes to misp
            logger.debug("Added curation score attribute to event %s", uuid)
        except Exception as exc:
            logger.error("Failed to write score attribute to event %s: %s", uuid, exc)

    def _upsert_analyst_summary_attribute(self, misp_event: MISPEvent, uuid: str, event: CurationEvent) -> None:
        if not event.analyst_summary: #no summary to write
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
