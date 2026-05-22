"""Stage 1 — Pull events from a MISP instance."""

from __future__ import annotations

import logging
from typing import cast

from pymisp import MISPEvent, PyMISP

from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)

# Events with more attributes than this are almost certainly bulk IOC feeds
# (e.g. PhishTank with 60k attributes, MalwareBazaar hash dumps).
_MAX_ATTRIBUTE_COUNT = 200
_PAGE_SIZE = 500


class MISPIngestStage(Stage):
    """Fetches raw events from MISP and wraps them in CurationEvent objects.

    Uses a two-phase approach to avoid pulling large feed events:
      Phase 1 — metadata-only search: retrieve event stubs with attribute counts.
      Phase 2 — full fetch: only pull complete event data for events that pass
                the attribute-count filter.
    """

    @property
    def name(self) -> str:
        return "misp_ingest"

    def __init__(self, url: str, key: str, verifycert: bool = True) -> None:
        self._client = PyMISP(url, key, verifycert)

    def fetch(self, since_timestamp: int) -> list[CurationEvent]:
        """Pull narrative CTI events from MISP, skipping bulk IOC feeds."""
        logger.info("Polling for events since timestamp=%d", since_timestamp)

        stubs: list[MISPEvent] = []
        page = 1
        search_kwargs = {
            "metadata": True, "pythonify": True,
            "limit": _PAGE_SIZE, "timestamp": since_timestamp,
        }
        while True:
            batch = self._client.search(page=page, **search_kwargs)
            if not batch:
                break
            stubs.extend(cast(list[MISPEvent], batch))
            if len(batch) < _PAGE_SIZE:
                break
            page += 1

        if not stubs:
            logger.info("No events returned from MISP")
            return []

        candidate_ids: list[tuple[str, str]] = []
        skipped = 0
        for stub in stubs:
            attr_count = int(getattr(stub, "attribute_count", 0) or 0)
            if attr_count <= _MAX_ATTRIBUTE_COUNT:
                candidate_ids.append((str(stub.id), str(stub.uuid)))
            else:
                skipped += 1
                logger.debug("Skipping event %s — %d attributes (bulk IOC feed)", stub.id, attr_count)

        logger.info(
            "Metadata filter: %d/%d events pass (skipped %d bulk feed events)",
            len(candidate_ids), len(stubs), skipped,
        )

        events: list[CurationEvent] = []
        for misp_id, misp_uuid in candidate_ids:
            try:
                full = self._client.get_event(misp_id, pythonify=True)
                events.append(CurationEvent(misp_id=misp_id, misp_uuid=misp_uuid, raw=full.to_dict()))
            except Exception as exc:
                logger.warning("Failed to fetch event %s: %s", misp_id, exc)

        logger.info("Fetched %d full events", len(events))
        return events

    def process(self, event: CurationEvent) -> CurationEvent:
        return event
