"""Stage 3 — BERTopic topic modelling over event text."""

import logging
from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)


def _event_to_text(raw: dict) -> str:
    """Concatenate all useful text fields from a raw MISP event dict."""
    parts = [
        raw.get("info", ""),
        raw.get("description", ""),
        " ".join(t.get("name", "") for t in raw.get("Tag", [])),
        " ".join(
            f"{gc.get('value', '')} {gc.get('description', '')}"
            for g in raw.get("Galaxy", [])
            for gc in g.get("GalaxyCluster", [])
        ),
        " ".join(
            a.get("value", "") for a in raw.get("Attribute", [])
            if a.get("type") in {"text", "comment", "vulnerability"}
        ),
    ]
    return " ".join(filter(None, parts))


class TopicModelStage(Stage):
    """Assigns a topic distribution to each event using a fitted BERTopic model."""

    name = "topic_model"

    def __init__(self, model=None) -> None:
        # model: a fitted BERTopic instance (None = stub passthrough)
        self._model = model

    def process_batch(self, events: list[CurationEvent]) -> list[CurationEvent]:
        if self._model is None:
            for e in events:
                e.topics = []
            return events

        texts = [_event_to_text(e.raw) for e in events]
        topic_ids, probs = self._model.transform(texts)

        for event, topic_id, prob in zip(events, topic_ids, probs):
            topic_id = int(topic_id)
            prob = float(prob)
            if topic_id == -1:
                event.topics = [("outlier", round(prob, 4))]
            else:
                words = self._model.get_topic(topic_id) or []
                event.topics = [(w, round(score, 4)) for w, score in words[:8]]
            logger.debug("Event %s → topic_id=%d words=%s", event.misp_id, topic_id, [t for t, _ in event.topics[:3]])

        return events

    def process(self, event: CurationEvent) -> CurationEvent:
        if self._model is None:
            event.topics = []
            return event

        text = _event_to_text(event.raw)
        topic_ids, probs = self._model.transform([text])
        topic_id = int(topic_ids[0])
        prob = float(probs[0])

        if topic_id == -1:
            event.topics = [("outlier", round(prob, 4))]
        else:
            # Store all top keywords for the topic so they flow into scoring
            words = self._model.get_topic(topic_id) or []
            event.topics = [(w, round(score, 4)) for w, score in words[:8]]

        logger.debug("Event %s → topic_id=%d top_words=%s", event.misp_id, topic_id, [t for t, _ in event.topics[:3]])
        return event
