"""Abstract base class for all pipeline stages."""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .event import CurationEvent


class Stage(ABC):
    """A single processing step in the curation pipeline."""

    @property
    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def process(self, event: "CurationEvent") -> "CurationEvent":
        """Transform a single event in-place and return it."""
        ...

    def process_batch(self, events: list["CurationEvent"]) -> list["CurationEvent"]:
        """Process a batch of events. Override for stages that benefit from batching."""
        return [self.process(e) for e in events]

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}()"
