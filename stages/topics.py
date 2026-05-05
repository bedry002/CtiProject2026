"""Stage 3 — BERTopic topic modelling over event text."""

import logging
from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Topic relevance map
#
# After retraining, inspect the discovered topics printed by train_topics.py
# and add an entry here for each topic that has a known relevance to the
# business profile.  Key = the topic label (first 3 words joined by "_").
# Value = relevance score 0.0–1.0.
#
# Topics not listed here default to 0.0 — they contribute nothing to scoring
# but still enrich the haystack text for the keyword/tech sub-scores.
#
# Guidance on scoring:
#   1.0  Directly targets your SBOM components or environment (linux/ssh/ubuntu)
#   0.8  Strong relevance — attack type you care about (supply chain, exploit)
#   0.6  Moderate — general malware/RAT family active in your sector
#   0.3  Weak — generic botnet noise, unlikely to affect your stack
#   0.0  Unrelated or feed metadata artifact
# ---------------------------------------------------------------------------
TOPIC_RELEVANCE_MAP: dict[str, float] = {
    # Generated from retrained model — labels are first-3-words of each topic.
    # Scores reflect relevance to an Ubuntu 24.04 / VirtualBox / Windows 11 test-bed.

    # RAT family with RMM/ScreenConnect abuse — targets Windows endpoints
    "rat_drb-ra rat_ghost":             0.5,
    # SOCKS5 proxy botnet — network-level threat, lower direct relevance
    "socks5__":                         0.3,
    # Mirai botnet — targets Linux SSH, directly relevant to Ubuntu/OpenSSH
    "mirai_malware_":                   0.7,
    # DarkComet/Fynloski RAT family — Windows-targeted
    "drb-ra_darkcomet_darkcomet fynloski": 0.4,
    # ClickFix social engineering + RMM abuse — targets Windows users
    "clickfix_compromised_rmm-abuse":   0.5,
    # Lumma credential stealer + ClickFix delivery — credential theft, high relevance
    "stealer_lumma_clickfix":           0.7,
    # GhostSocks proxy infrastructure — network-level C2
    "infrastructure_ghostsocks_encryption": 0.3,
    # DRB-RA C2 framework — sparse topic, moderate relevance
    "drb-ra__":                         0.4,
    # General attack/deployment techniques mentioning credentials
    "attack_deploying_affected":        0.6,
    # GhostSocks specific — sparse, low signal
    "ghostsocks__":                     0.3,
    # Empty/sparse topics
    "__":                               0.0,
}


def _resolve_relevance(topic_label: str) -> float:
    """Look up a topic label in the relevance map; return 0.0 if unmapped."""
    return TOPIC_RELEVANCE_MAP.get(topic_label, 0.0)


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


def _apply_topic(event: CurationEvent, topic_id: int, model) -> None:
    """Populate event.topics, event.topic_label, and event.topic_relevance_score."""
    if topic_id == -1:
        event.topics = [("outlier", 0.0)]
        event.topic_label = "outlier"
        event.topic_relevance_score = 0.0
        return

    words = model.get_topic(topic_id) or []
    event.topics = [(w, round(score, 4)) for w, score in words[:8]]
    label = "_".join(w for w, _ in words[:3])
    event.topic_label = label
    event.topic_relevance_score = _resolve_relevance(label)
    logger.debug(
        "Event %s → topic_id=%d label=%s relevance=%.2f",
        event.misp_id, topic_id, label, event.topic_relevance_score,
    )


class TopicModelStage(Stage):
    """Assigns a topic to each event and looks up its profile relevance."""

    name = "topic_model"

    def __init__(self, model=None) -> None:
        self._model = model

    def process_batch(self, events: list[CurationEvent]) -> list[CurationEvent]:
        if self._model is None:
            for e in events:
                e.topics = []
                e.topic_label = ""
                e.topic_relevance_score = 0.0
            return events

        texts = [_event_to_text(e.raw) for e in events]
        topic_ids, _ = self._model.transform(texts)

        for event, topic_id in zip(events, topic_ids):
            _apply_topic(event, int(topic_id), self._model)

        return events

    def process(self, event: CurationEvent) -> CurationEvent:
        if self._model is None:
            event.topics = []
            event.topic_label = ""
            event.topic_relevance_score = 0.0
            return event

        topic_ids, _ = self._model.transform([_event_to_text(event.raw)])
        _apply_topic(event, int(topic_ids[0]), self._model)
        return event
