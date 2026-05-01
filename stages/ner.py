"""Stage 2 — Named Entity Recognition over event text."""

import logging
from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)

# spaCy entity types relevant to threat intelligence
THREAT_ENTITY_TYPES = {
    "ORG",      # organisations, threat actor groups, vendors
    "PERSON",   # named individuals
    "GPE",      # geopolitical entities (countries, cities)
    "LOC",      # non-GPE locations
    "PRODUCT",  # software, hardware, platform names
    "LAW",      # CVEs referenced as law/regulation names occasionally
    "NORP",     # nationalities, political groups (nation-state actors)
    "EVENT",    # named campaigns or operations
}

# Fields pulled from a MISP event dict to build the NER input text
_TEXT_FIELDS = ("info", "description")
_TEXT_ATTR_TYPES = {"text", "comment", "vulnerability"}


def _event_to_text(raw: dict) -> str:
    parts = [raw.get(f, "") for f in _TEXT_FIELDS]
    parts += [
        a.get("value", "")
        for a in raw.get("Attribute", [])
        if a.get("type") in _TEXT_ATTR_TYPES
    ]
    parts += [t.get("name", "") for t in raw.get("Tag", [])]
    parts += [
        f"{gc.get('value', '')} {gc.get('description', '')}"
        for g in raw.get("Galaxy", [])
        for gc in g.get("GalaxyCluster", [])
    ]
    return " ".join(filter(None, parts))


class NERStage(Stage):
    """Extracts named entities from MISP event text using spaCy."""

    name = "ner"

    def __init__(self, nlp=None, entity_types: set[str] = THREAT_ENTITY_TYPES) -> None:
        self._nlp = nlp
        self._entity_types = entity_types

    def process(self, event: CurationEvent) -> CurationEvent:
        if self._nlp is None:
            event.entities = {}
            return event

        text = _event_to_text(event.raw)
        doc = self._nlp(text)

        entities: dict[str, list[str]] = {}
        seen: set[str] = set()
        for ent in doc.ents:
            if ent.label_ not in self._entity_types:
                continue
            key = (ent.label_, ent.text.lower())
            if key in seen:
                continue
            seen.add(key)
            entities.setdefault(ent.label_, []).append(ent.text)

        event.entities = entities
        logger.debug("Event %s entities: %s", event.misp_id, entities)
        return event
