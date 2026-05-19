import unittest

from pipeline.base import Stage
from pipeline.event import CurationEvent
from pipeline.runner import Pipeline


class FailsBatchStage(Stage):
    @property
    def name(self) -> str:
        return "fails_batch"

    def process(self, event: CurationEvent) -> CurationEvent:
        if event.misp_id == "bad":
            raise RuntimeError("event-level failure")
        event.topic_label = "processed"
        return event

    def process_batch(self, events: list[CurationEvent]) -> list[CurationEvent]:
        raise RuntimeError("batch failure")


class PassThroughStage(Stage):
    @property
    def name(self) -> str:
        return "pass"

    def process(self, event: CurationEvent) -> CurationEvent:
        return event


class TestRunnerFaultMode(unittest.TestCase):
    def _events(self) -> list[CurationEvent]:
        return [
            CurationEvent(misp_id="ok", misp_uuid="u1", raw={}),
            CurationEvent(misp_id="bad", misp_uuid="u2", raw={}),
        ]

    def test_fail_fast_returns_empty_on_stage_batch_error(self) -> None:
        pipeline = Pipeline([FailsBatchStage(), PassThroughStage()])
        result = pipeline.run(self._events())
        self.assertEqual(result, [])

    def test_continue_mode_recovers_and_drops_failing_event(self) -> None:
        pipeline = Pipeline([FailsBatchStage(), PassThroughStage()], continue_on_stage_error=True)
        result = pipeline.run(self._events())

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].misp_id, "ok")
        self.assertEqual(result[0].topic_label, "processed")


if __name__ == "__main__":
    unittest.main()
