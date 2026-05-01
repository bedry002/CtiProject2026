"""Core data model passed between pipeline stages."""

from dataclasses import dataclass, field
from typing import Any


@dataclass
class CurationEvent:
    """Represents a single MISP event as it flows through the pipeline."""

    misp_id: str
    raw: dict[str, Any]

    # Populated by NER stage
    entities: dict[str, list[str]] = field(default_factory=dict)

    # Populated by topic modelling stage
    topics: list[tuple[str, float]] = field(default_factory=list)

    # Populated by scoring stage
    confidence: float | None = None
    matched_profile_terms: list[str] = field(default_factory=list)
    matched_sbom_components: list[str] = field(default_factory=list)  # bom-refs of matched components
    score_breakdown: dict[str, float] = field(default_factory=dict)   # per-category scores

    def __repr__(self) -> str:
        return (
            f"CurationEvent(id={self.misp_id!r}, "
            f"confidence={self.confidence}, "
            f"topics={[t for t, _ in self.topics]})"
        )
