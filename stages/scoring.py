"""Stage 4 — Weighted relevance scoring against business profile and SBOM."""

import logging
from dataclasses import dataclass, field
from pipeline.base import Stage
from pipeline.event import CurationEvent
from pipeline.sbom import SBOMProfile

logger = logging.getLogger(__name__)


@dataclass
class BusinessProfile:
    name: str
    sectors: list[str]       # e.g. ["security research", "system administration"]
    technologies: list[str]  # general OS/software terms
    geographies: list[str]   # e.g. ["Australia", "Adelaide"]
    keywords: list[str]      # threat-type terms: ransomware, exploit, brute-force …


@dataclass
class ScoringWeights:
    sbom:       float = 0.40   # direct SBOM component hits — most precise signal
    keyword:    float = 0.30   # threat-type terms
    technology: float = 0.20   # general tech terms from profile
    context:    float = 0.10   # sector + geography

    def __post_init__(self) -> None:
        total = self.sbom + self.keyword + self.technology + self.context
        assert abs(total - 1.0) < 1e-6, f"Weights must sum to 1.0, got {total}"


# Confidence bands for tagging and reporting (0–1 scale)
BAND_HIGH   = 0.50
BAND_MEDIUM = 0.25
BAND_LOW    = 0.10


def _haystack(event: CurationEvent) -> str:
    raw = event.raw
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
        " ".join(v for vals in event.entities.values() for v in vals),
        " ".join(t for t, _ in event.topics),
    ]
    return " ".join(filter(None, parts)).lower()


def _category_score(terms: list[str], haystack: str) -> tuple[float, list[str]]:
    """Simple presence score: matched / total, plus the list of matched terms."""
    if not terms:
        return 0.0, []
    matched = [t for t in terms if t.lower() in haystack]
    return len(matched) / len(terms), matched


def _sbom_score(
    sbom: SBOMProfile, haystack: str
) -> tuple[float, list[str]]:
    """
    Weighted component match score.
    Each component contributes (its weight / total_weight) when any of its
    match terms appear in the haystack.
    Returns (score 0-1, list of matched bom-refs).
    """
    if not sbom.components or sbom.total_weight == 0:
        return 0.0, []

    matched_weight = 0.0
    matched_refs: list[str] = []

    for component in sbom.components:
        terms = component.match_terms()
        if any(t in haystack for t in terms):
            matched_weight += component.weight
            matched_refs.append(component.bom_ref)

    score = matched_weight / sbom.total_weight
    return round(score, 4), matched_refs


class ScoringStage(Stage):
    """Computes a weighted [0, 1] confidence score for each event."""

    name = "scoring"

    def __init__(
        self,
        profile: BusinessProfile,
        sbom: SBOMProfile | None = None,
        weights: ScoringWeights | None = None,
    ) -> None:
        self._profile = profile
        self._sbom = sbom or SBOMProfile()
        self._weights = weights or ScoringWeights()

    def process(self, event: CurationEvent) -> CurationEvent:
        hay = _haystack(event)

        # --- SBOM score ---
        sbom_s, sbom_refs = _sbom_score(self._sbom, hay)

        # --- Keyword score (threat types) ---
        kw_s, kw_matched = _category_score(
            [t.lower() for t in self._profile.keywords], hay
        )

        # --- Technology score ---
        tech_s, tech_matched = _category_score(
            [t.lower() for t in self._profile.technologies], hay
        )

        # --- Context score (sector + geography) ---
        context_terms = (
            [t.lower() for t in self._profile.sectors]
            + [t.lower() for t in self._profile.geographies]
        )
        ctx_s, ctx_matched = _category_score(context_terms, hay)

        w = self._weights
        confidence = round(
            sbom_s   * w.sbom
            + kw_s   * w.keyword
            + tech_s * w.technology
            + ctx_s  * w.context,
            4,
        )

        event.confidence = confidence
        event.matched_sbom_components = sbom_refs
        event.matched_profile_terms = kw_matched + tech_matched + ctx_matched
        event.score_breakdown = {
            "sbom":       round(sbom_s, 4),
            "keyword":    round(kw_s, 4),
            "technology": round(tech_s, 4),
            "context":    round(ctx_s, 4),
        }

        logger.debug(
            "Event %s → %.4f  sbom=%.3f kw=%.3f tech=%.3f ctx=%.3f",
            event.misp_id, confidence, sbom_s, kw_s, tech_s, ctx_s,
        )
        return event
