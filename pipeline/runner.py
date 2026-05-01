"""Orchestrates stages and drives events through the pipeline."""

import logging
from .base import Stage
from .event import CurationEvent

logger = logging.getLogger(__name__)


class Pipeline:
    def __init__(self, stages: list[Stage]) -> None:
        self.stages = stages

    def run(self, events: list[CurationEvent]) -> list[CurationEvent]:
        active = list(events)
        for stage in self.stages:
            try:
                active = stage.process_batch(active)
            except Exception:
                logger.exception("Stage %s failed — aborting pipeline", stage.name)
                return []
        return active
