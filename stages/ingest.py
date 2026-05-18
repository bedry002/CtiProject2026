"""Stage 1 — Pull events from a MISP instance."""

import logging
from pymisp import PyMISP, MISPEvent
from typing import cast
from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)

# Events with more attributes than this are almost certainly bulk IOC feeds
# (e.g. PhishTank with 60k attributes, MalwareBazaar hash dumps).
# They produce misleading high ioc_s scores and are not narrative CTI.
_MAX_ATTRIBUTE_COUNT = 200


class MISPIngestStage(Stage):
    """Fetches raw events from MISP and wraps them in CurationEvent objects.

    Uses a two-phase approach to avoid pulling large feed events:
      Phase 1 — metadata-only search: retrieve event stubs with attribute counts.
      Phase 2 — full fetch: only pull complete event data for events that pass
                the attribute-count filter.

    This prevents 84MB+ payloads from bulk IOC aggregator events causing
    IncompleteRead errors and polluting the scoring pipeline.
    """

    @property
    def name(self) -> str:
        return "misp_ingest"

    def __init__(self, url: str, key: str, verifycert: bool = True) -> None:
        self._client = PyMISP(url, key, verifycert)

    def fetch(self, limit: int = 100) -> list[CurationEvent]:
        """Pull narrative CTI events from MISP, skipping bulk IOC feeds."""
        logger.info("Fetching metadata for up to %d events from MISP", limit)

        # Phase 1: metadata only — fast, small payload
        stubs = self._client.search(
            limit=limit,
            metadata=True,
            pythonify=True,
        )
        if not stubs:
            logger.info("No events returned from MISP")
            return []

        # Filter: skip events with too many attributes (bulk IOC feeds)
        candidate_ids = []
        skipped = 0
        for stub in cast(list[MISPEvent], stubs):
            attr_count = int(getattr(stub, "attribute_count", 0) or 0)
            if attr_count <= _MAX_ATTRIBUTE_COUNT:
                candidate_ids.append((str(stub.id), str(stub.uuid)))
            else:
                skipped += 1
                logger.debug(
                    "Skipping event %s — %d attributes (bulk IOC feed)",
                    stub.id, attr_count,
                )

        logger.info(
            "Metadata filter: %d/%d events pass (skipped %d bulk feed events)",
            len(candidate_ids), len(stubs), skipped,
        )

        # Phase 2: full fetch for each candidate
        events: list[CurationEvent] = []
        for misp_id, misp_uuid in candidate_ids:
            try:
                full = self._client.get_event(misp_id, pythonify=True)
                events.append(
                    CurationEvent(
                        misp_id=misp_id,
                        misp_uuid=misp_uuid,
                        raw=full.to_dict(),
                    )
                )
            except Exception as exc:
                logger.warning("Failed to fetch event %s: %s", misp_id, exc)

        logger.info("Fetched %d full events", len(events))
        return events

    def process(self, event: CurationEvent) -> CurationEvent:
        return event
