"""Stage 3 — Weighted relevance scoring against business profile, SBOM, and IOC analysis."""

from __future__ import annotations

import logging
import os
import re
from collections import Counter
from dataclasses import dataclass, field

from pipeline.base import Stage
from pipeline.event import CurationEvent
from pipeline.sbom import SBOMComponent, SBOMProfile
from pipeline.text import event_to_text

logger = logging.getLogger(__name__)

# Word-boundary matching toggle.  Default ON.
# Set SCORING_WORD_BOUNDARY=false to reproduce the original substring behaviour
_WORD_BOUNDARY = os.getenv("SCORING_WORD_BOUNDARY", "true").strip().lower() == "true"

# Asset-normalisation mode.  Default ON (saturation).
# Set SCORING_ASSET_SATURATION=false to restore the original matched_weight/total_weight
_ASSET_SATURATION = os.getenv("SCORING_ASSET_SATURATION", "false").strip().lower() == "true"
# Weighted matched points at which the asset sub-score saturates to 1.0.
# 1.0 == one high-criticality component (weight 1.0), or ~two medium (0.6) components.
_ASSET_SAT_CAP = float(os.getenv("SCORING_ASSET_SAT_CAP", "1.0"))

# When an event CVE matches a documented risk affecting a component in the org's
# SBOM, that is a near-certain relevance signal: a known-exploitable flaw on kit
# the organisation actually runs. In the weighted average that signal is diluted
# by total SBOM weight, so genuinely critical CVE hits scored below the drop
# threshold in evaluation. This floor guarantees a confirmed CVE-to-SBOM match
# lands at least in this band, independent of the other dimensions.
_CVE_MATCH_FLOOR = float(os.getenv("SCORING_CVE_MATCH_FLOOR", "0.50"))

def _normalise_asset(matched_weight: float, total_weight: float) -> float:
    """Convert matched component weight into a [0, 1] asset sub-score.

    Saturation mode (default): matched_weight / cap, capped at 1.0.
    Does NOT depend on total SBOM size — enriching the SBOM never lowers
    an existing match's contribution.

    Legacy mode: matched_weight / total_weight (original behaviour, for the ablation).
    """
    if _ASSET_SATURATION:
        return round(min(1.0, matched_weight / _ASSET_SAT_CAP), 4) if _ASSET_SAT_CAP > 0 else 0.0
    return round(matched_weight / total_weight, 4) if total_weight else 0.0


def _compile_term(term: str) -> re.Pattern[str]:
    """Compile a term into a pattern that requires non-word-character boundaries.

    Uses (?<!\\w) / (?!\\w) lookarounds rather than \\b so that terms whose edges
    are NOT word characters (e.g. 'point-of-sale', '.net', 'c++') still anchor
    correctly.  A boundary lookaround is only inserted on a side when that side
    is itself a word character — otherwise it is omitted for that side.
    """
    t = term.lower().strip()
    if not t:
        return re.compile(r"(?!x)x")  # never-matches sentinel
    left  = r"(?<!\w)" if (t[0].isalnum()  or t[0]  == "_") else r""
    right = r"(?!\w)"  if (t[-1].isalnum() or t[-1] == "_") else r""
    return re.compile(left + re.escape(t) + right)


class _TermMatcher:
    """Precompiles a list of terms once and tests matches against a haystack.

    When _WORD_BOUNDARY is True (default) each term is compiled with lookaround
    anchors so short terms like 'us', 'ca', 'pos', 'rce' cannot match inside
    longer words ('because', 'virus', 'exposed', 'source').

    When _WORD_BOUNDARY is False the original plain-substring behaviour is
    preserved exactly — useful for ablation runs.
    """

    __slots__ = ("_terms", "_patterns", "_wb")

    def __init__(self, terms: list[str], word_boundary: bool = _WORD_BOUNDARY) -> None:
        self._terms    = [t.lower() for t in terms]
        self._wb       = word_boundary
        self._patterns = [(t, _compile_term(t)) for t in self._terms] if word_boundary else []

    def matched(self, haystack: str) -> list[str]:
        if self._wb:
            return [t for t, pat in self._patterns if pat.search(haystack)]
        return [t for t in self._terms if t in haystack]

    def any_match(self, haystack: str) -> bool:
        if self._wb:
            return any(pat.search(haystack) for _, pat in self._patterns)
        return any(t in haystack for t in self._terms)


def _scored(
    matcher: _TermMatcher,
    n_terms: int,
    haystack: str,
    saturation: float,
) -> tuple[float, list[str]]:
    """Apply a precompiled _TermMatcher and return (score, matched_terms)."""
    if n_terms == 0:
        return 0.0, []
    matched = matcher.matched(haystack)
    return round(min(1.0, len(matched) / n_terms / saturation), 4), matched


@dataclass
class BusinessProfile:
    name: str
    sectors: list[str]
    technologies: list[str]
    geographies: list[str]
    keywords: list[str] = field(default_factory=list)
    specific_keywords: list[str] = field(default_factory=list)


@dataclass
class ScoringWeights:
    asset:      float = 0.30
    technology: float = 0.30
    sector:     float = 0.30
    geography:  float = 0.10

    def __post_init__(self) -> None:
        total = self.asset + self.technology + self.sector + self.geography
        assert abs(total - 1.0) < 1e-6, f"Weights must sum to 1.0, got {total}"


_VULN_TYPES    = frozenset({"vulnerability"})
_NETWORK_TYPES = frozenset({"hostname", "domain", "domain|ip", "url", "uri",
                             "ip-src", "ip-dst", "ip-src|port", "ip-dst|port"})
_FILE_TYPES    = frozenset({"md5", "sha1", "sha256", "sha512", "filename",
                             "filename|md5", "filename|sha256", "malware-sample"})


def _haystack(event: CurationEvent) -> str:
    # Reuse _raw_text stored by NERStage to avoid rebuilding the text string
    raw_text = event.entities.get("_raw_text") or event_to_text(event.raw)
    entity_text = " ".join(
        item["text"]
        for vals in event.entities.values()
        if isinstance(vals, list)
        for item in vals
        if isinstance(item, dict) and "text" in item
    )
    return f"{raw_text} {entity_text}".lower() if entity_text else raw_text.lower()


def _category_score(terms: list[str], haystack: str, saturation: float = 0.25) -> tuple[float, list[str]]:
    """Saturation-based score: reaching `saturation` match-ratio → score of 1.0."""
    if not terms:
        return 0.0, []
    matched = _TermMatcher(terms).matched(haystack)
    return round(min(1.0, len(matched) / len(terms) / saturation), 4), matched


def _ioc_score(raw: dict) -> tuple[float, dict[str, int]]:
    attrs = raw.get("Attribute", [])
    if not attrs:
        return 0.0, {}
    type_counts: dict[str, int] = Counter(a["type"] for a in attrs)
    vuln_count    = sum(type_counts.get(t, 0) for t in _VULN_TYPES)
    network_count = sum(type_counts.get(t, 0) for t in _NETWORK_TYPES)
    file_count    = sum(type_counts.get(t, 0) for t in _FILE_TYPES)
    score = round(
        (1.0 if vuln_count > 0 else 0.0) * 0.50
        + min(1.0, network_count / 5) * 0.30
        + min(1.0, file_count / 10)   * 0.20,
        4,
    )
    return score, dict(type_counts)


class ScoringStage(Stage):
    """Computes a weighted [0, 1] confidence score for each event.

    Events scoring below ``threshold`` are dropped before the next stage runs.
    """

    @property
    def name(self) -> str:
        return "scoring"

    def __init__(
        self,
        profile: BusinessProfile,
        sbom: SBOMProfile | None = None,
        weights: ScoringWeights | None = None,
        threshold: float = 0.0,
    ) -> None:
        self._profile   = profile
        self._sbom      = sbom or SBOMProfile()
        self._weights   = weights or ScoringWeights()
        self._threshold = threshold

        # Precompute per-component match terms — avoids recomputing for every event
        self._component_terms: list[tuple[SBOMComponent, list[str]]] = [
            (c, c.match_terms()) for c in self._sbom.components
        ]
        # Precompiled per-component matchers — compiled ONCE, reused on every event
        self._component_matchers: list[tuple[SBOMComponent, _TermMatcher]] = [
            (c, _TermMatcher(terms)) for c, terms in self._component_terms
        ]
        # Precompiled profile-category matchers
        self._m_tech    = _TermMatcher([t.lower() for t in self._profile.technologies])
        self._m_sector  = _TermMatcher([t.lower() for t in self._profile.sectors])
        self._m_geo     = _TermMatcher([t.lower() for t in self._profile.geographies])
        self._m_keyword = _TermMatcher([t.lower() for t in self._profile.specific_keywords])
        # Precompute per-risk CVE sets — avoids recomputing for every event
        self._risk_cve_sets = [
            (risk, frozenset(c.upper() for c in risk.known_cves))
            for risk in self._sbom.risks
            if risk.known_cves
        ]

    def process_batch(self, events: list[CurationEvent]) -> list[CurationEvent]:
        scored = super().process_batch(events)
        if self._threshold <= 0:
            return scored
        passed  = [e for e in scored if (e.confidence or 0) >= self._threshold]
        dropped = len(scored) - len(passed)
        if dropped:
            logger.info(
                "scoring_filter: dropped %d/%d events below threshold=%.2f",
                dropped, len(scored), self._threshold,
            )
        return passed

    def process(self, event: CurationEvent) -> CurationEvent:
        hay = _haystack(event)
        w   = self._weights

        # SBOM component text match
        sbom_s, sbom_refs = self._sbom_score(hay)

        # CVE cross-reference against SBOM risk entries
        event_cves = {
            item["text"].upper()
            for item in event.entities.get("cves", [])
            if isinstance(item, dict) and "text" in item
        }
        cve_s, cve_refs = self._cve_sbom_score(event_cves)
        if cve_refs:
            all_refs = list(dict.fromkeys(sbom_refs + cve_refs))
            ref_set  = set(all_refs)
            matched_weight = sum(c.weight for c, _ in self._component_terms if c.bom_ref in ref_set)
            sbom_s    = _normalise_asset(matched_weight, self._sbom.total_weight)
            sbom_refs = all_refs

        # NER-confirmed SBOM hits provide a small additional boost
        ner_sbom_hits = [
            ref.strip()
            for item in event.entities.get("sbom_assets", [])
            if isinstance(item, dict) and "bom_ref" in item
            for ref in item["bom_ref"].split(",")
            if ref.strip()
        ]
        if ner_sbom_hits:
            sbom_s    = round(min(1.0, sbom_s + min(0.2, len(set(ner_sbom_hits)) * 0.07)), 4)
            sbom_refs = list(dict.fromkeys(sbom_refs + ner_sbom_hits))

        kw_s, kw_matched = (
            _scored(self._m_keyword, len(self._profile.specific_keywords), hay, 0.006)
            if self._profile.specific_keywords else (0.0, [])
        )
        asset_s = min(1.0, sbom_s + kw_s)

        tech_s,   tech_matched   = _scored(self._m_tech,   len(self._profile.technologies), hay, 0.30)
        sector_s, sector_matched = _scored(self._m_sector, len(self._profile.sectors),      hay, 0.50)
        geo_s,    geo_matched    = _scored(self._m_geo,    len(self._profile.geographies),  hay, 0.50)

        _, ioc_counts = _ioc_score(event.raw)

        confidence = round(
            asset_s   * w.asset
            + tech_s  * w.technology
            + sector_s * w.sector
            + geo_s   * w.geography,
            4,
        )

        # CVE-match floor: a confirmed event-CVE-to-SBOM-risk match is a
        # near-certain relevance signal that the weighted average dilutes.
        # Guarantee it clears the band, without disturbing the weight maths.
        cve_floor_applied = False
        if cve_refs and _CVE_MATCH_FLOOR > 0.0 and confidence < _CVE_MATCH_FLOOR:
            confidence = _CVE_MATCH_FLOOR
            cve_floor_applied = True

        event.confidence              = confidence
        event.matched_sbom_components = sbom_refs
        event.matched_profile_terms   = kw_matched + tech_matched + sector_matched + geo_matched
        event.ioc_summary             = ioc_counts
        event.score_breakdown         = {
            "asset":     round(asset_s,  4),
            "sbom_cve":  round(cve_s,    4),
            "tech":      round(tech_s,   4),
            "sector":    round(sector_s, 4),
            "geography": round(geo_s,    4),
            "cve_floor_applied": 1.0 if cve_floor_applied else 0.0,
        }
        logger.debug(
            "Event %s → %.4f  asset=%.3f tech=%.3f sector=%.3f geo=%.3f",
            event.misp_id, confidence, asset_s, tech_s, sector_s, geo_s,
        )
        return event

    def _sbom_score(self, haystack: str) -> tuple[float, list[str]]:
        if not self._component_matchers or self._sbom.total_weight == 0:
            return 0.0, []
        matched_weight = 0.0
        matched_refs: list[str] = []
        for component, matcher in self._component_matchers:
            if matcher.any_match(haystack):
                matched_weight += component.weight
                matched_refs.append(component.bom_ref)
        return _normalise_asset(matched_weight, self._sbom.total_weight), matched_refs

    def _cve_sbom_score(self, event_cves: set[str]) -> tuple[float, list[str]]:
        if not event_cves or not self._risk_cve_sets:
            return 0.0, []
        comp_weights  = {c.bom_ref: c.weight for c, _ in self._component_terms}
        matched_refs: list[str] = []
        matched_weight = 0.0
        for risk, cve_set in self._risk_cve_sets:
            if event_cves & cve_set:
                for ref in risk.affected_refs:
                    if ref not in matched_refs:
                        matched_refs.append(ref)
                        matched_weight += comp_weights.get(ref, 0.0)
        return _normalise_asset(matched_weight, self._sbom.total_weight), matched_refs
