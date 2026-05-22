"""Core data model passed between pipeline stages."""

from dataclasses import dataclass, field
from typing import Any, TypeAlias, TypedDict


class EntityRecord(TypedDict, total=False):
    text: str
    confidence: float
    type: str
    bom_ref: str


EntityBucket: TypeAlias = list[EntityRecord]
EntityMap: TypeAlias = dict[str, EntityBucket | str]


@dataclass
class CurationEvent:
    """Represents a single MISP event as it flows through the pipeline."""

    misp_id: str          # numeric database ID (e.g. "1574")
    misp_uuid: str        # MISP UUID — required by tag/untag API calls
    raw: dict[str, Any]

    # Populated by NER stage
    entities: EntityMap = field(default_factory=dict)

    # Populated by scoring stage
    confidence: float | None = None
    matched_profile_terms: list[str] = field(default_factory=list)
    matched_sbom_components: list[str] = field(default_factory=list)
    score_breakdown: dict[str, float] = field(default_factory=dict)
    ioc_summary: dict[str, int] = field(default_factory=dict)   # attr_type → count

    # Populated by LLM enricher stage
    analyst_summary: str | None = None
    implicit_relevance_flags: list[str] = field(default_factory=list)

    def __repr__(self) -> str:
        return (
            f"CurationEvent(id={self.misp_id!r}, "
            f"confidence={self.confidence})"
        )
