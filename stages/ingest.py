"""Stage 1 — Pull events from a MISP instance."""

import logging
from pymisp import PyMISP, MISPEvent
from typing import cast
from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)


class MISPIngestStage(Stage):
    """Fetches raw events from MISP and wraps them in CurationEvent objects."""

    @property
    def name(self) -> str:
        return "misp_ingest"

    def __init__(self, url: str, key: str, verifycert: bool = True) -> None:
        self._client = PyMISP(url, key, verifycert)

    def fetch(self, limit: int = 100) -> list[CurationEvent]:
        """Pull the latest events from MISP and return CurationEvent objects."""
        logger.info("Fetching up to %d events from MISP", limit)
        raw_events = cast(list[MISPEvent], self._client.search(limit=limit, pythonify=True))
        events = [
            CurationEvent(misp_id=str(e.id), raw=e.to_dict())
            for e in raw_events
        ]
        logger.info("Fetched %d events", len(events))
        return events

    def process(self, event: CurationEvent) -> CurationEvent:
        return event
