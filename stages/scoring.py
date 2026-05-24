"""Stage 3 — Weighted relevance scoring against business profile, SBOM, and IOC analysis."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field

from pipeline.base import Stage
from pipeline.event import CurationEvent
from pipeline.sbom import SBOMComponent, SBOMProfile
from pipeline.text import event_to_text

logger = logging.getLogger(__name__)


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
    stack:  float = 0.50   # combined SBOM + keywords + tech stack
    sector: float = 0.25
    ttp:    float = 0.25

    def __post_init__(self) -> None:
        total = self.stack + self.sector + self.ttp
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
    matched = [t for t in terms if t.lower() in haystack]
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
        attack_lookup: dict | None = None,
        org_attack_platforms: set[str] | None = None,
    ) -> None:
        self._profile      = profile
        self._sbom         = sbom or SBOMProfile()
        self._weights      = weights or ScoringWeights()
        self._threshold    = threshold
        self._attack_lookup   = attack_lookup or {}
        self._org_platforms   = org_attack_platforms or set()

        # Precompute per-component match terms — avoids recomputing for every event
        self._component_terms: list[tuple[SBOMComponent, list[str]]] = [
            (c, c.match_terms()) for c in self._sbom.components
        ]
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
            sbom_s    = round(min(1.0, matched_weight / self._sbom.total_weight), 4) if self._sbom.total_weight else 0.0
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
            _category_score([t.lower() for t in self._profile.specific_keywords], hay, saturation=0.006)
            if self._profile.specific_keywords else (0.0, [])
        )
        asset_s = min(1.0, sbom_s + kw_s)

        tech_s,   tech_matched   = _category_score([t.lower() for t in self._profile.technologies],  hay, saturation=0.30)
        sector_s, sector_matched = _category_score([t.lower() for t in self._profile.sectors],        hay, saturation=0.50)

        _, ioc_counts = _ioc_score(event.raw)

        from pipeline.attack import ttp_relevance_score
        ttp_s = ttp_relevance_score(
            event.entities.get("ttps", []),
            self._attack_lookup,
            self._org_platforms,
        )

        # Geography excluded from scoring — displayed per-event in the report via NER entities
        stack_s = min(1.0, asset_s + tech_s)

        confidence = round(
            stack_s    * w.stack
            + sector_s * w.sector
            + ttp_s    * w.ttp,
            4,
        )

        # NVD CVEs for matched SBOM components — for report display only
        matched_ref_set = set(sbom_refs)
        nvd_cves: list[str] = []
        for risk, cve_set in self._risk_cve_sets:
            if any(ref in matched_ref_set for ref in risk.affected_refs):
                nvd_cves.extend(sorted(cve_set)[:6])
        event.entities["nvd_cves"] = list(dict.fromkeys(nvd_cves))[:15]

        # Enrich TTP entries with ATT&CK metadata for report display
        if self._attack_lookup:
            for ttp in event.entities.get("ttps", []):
                if not isinstance(ttp, dict):
                    continue
                info = self._attack_lookup.get(ttp.get("text", ""), {})
                ttp["name"]         = info.get("name", "")
                ttp["tactics"]      = info.get("tactics", [])
                ttp["org_relevant"] = bool(info.get("platforms", set()) & self._org_platforms)

        event.confidence              = confidence
        event.matched_sbom_components = sbom_refs
        event.matched_profile_terms   = kw_matched + tech_matched + sector_matched
        event.ioc_summary             = ioc_counts
        event.score_breakdown         = {
            "stack":          round(stack_s,            4),
            "stack_contrib":  round(stack_s  * w.stack,  4),
            "sbom_cve":       round(cve_s,              4),
            "sector":         round(sector_s,            4),
            "sector_contrib": round(sector_s * w.sector, 4),
            "ttp":            round(ttp_s,               4),
            "ttp_contrib":    round(ttp_s    * w.ttp,     4),
        }
        logger.debug(
            "Event %s → %.4f  stack=%.3f sector=%.3f ttp=%.3f",
            event.misp_id, confidence, stack_s, sector_s, ttp_s,
        )
        return event

    def _sbom_score(self, haystack: str) -> tuple[float, list[str]]:
        if not self._component_terms or self._sbom.total_weight == 0:
            return 0.0, []
        matched_weight = 0.0
        matched_refs: list[str] = []
        for component, terms in self._component_terms:
            if any(t in haystack for t in terms):
                matched_weight += component.weight
                matched_refs.append(component.bom_ref)
        return round(matched_weight / self._sbom.total_weight, 4), matched_refs

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
        return round(min(1.0, matched_weight / self._sbom.total_weight), 4) if self._sbom.total_weight else 0.0, matched_refs
