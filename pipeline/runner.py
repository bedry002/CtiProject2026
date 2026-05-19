"""Orchestrates stages and drives events through the pipeline."""

import logging
from .base import Stage
from .event import CurationEvent

logger = logging.getLogger(__name__)


class Pipeline:
    def __init__(self, stages: list[Stage], continue_on_stage_error: bool = False) -> None:
        self.stages = stages
        self.continue_on_stage_error = continue_on_stage_error

    def run(self, events: list[CurationEvent]) -> list[CurationEvent]:
        active = list(events)
        for stage in self.stages:
            try:
                active = stage.process_batch(active)
            except Exception:
                logger.exception("Stage %s failed during batch processing", stage.name)
                if not self.continue_on_stage_error:
                    logger.error("Stage %s failed — aborting pipeline", stage.name)
                    return []

                recovered: list[CurationEvent] = []
                for event in active:
                    try:
                        recovered.append(stage.process(event))
                    except Exception:
                        logger.exception(
                            "Stage %s failed for event %s — dropping event",
                            stage.name,
                            event.misp_id,
                        )
                logger.warning(
                    "Stage %s recovered with %d/%d events",
                    stage.name,
                    len(recovered),
                    len(active),
                )
                active = recovered
        return active
