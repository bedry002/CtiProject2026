"""Stage 4 — Weighted relevance scoring against business profile, SBOM, and IOC analysis."""

import logging
from collections import Counter
from dataclasses import dataclass, field
from pipeline.base import Stage
from pipeline.event import CurationEvent
from pipeline.sbom import SBOMProfile
from pipeline.text import event_to_text

logger = logging.getLogger(__name__)


@dataclass
class BusinessProfile:
    name: str
    sectors: list[str]
    technologies: list[str]
    geographies: list[str]
    keywords: list[str]                              # generic threat keywords
    specific_keywords: list[str] = field(default_factory=list)  # SBOM-derived compound phrases


@dataclass
class ScoringWeights:
    sbom:       float = 0.35  # SBOM component hits — most precise signal
    keyword:    float = 0.25  # SBOM-derived compound phrase matches
    ioc:        float = 0.10  # IOC type analysis (profile-blind — kept low)
    topic:      float = 0.20  # topic cluster relevance (from TOPIC_RELEVANCE_MAP)
    technology: float = 0.07  # general tech terms
    context:    float = 0.03  # sector + geography

    def __post_init__(self) -> None:
        total = self.sbom + self.keyword + self.ioc + self.topic + self.technology + self.context
        assert abs(total - 1.0) < 1e-6, f"Weights must sum to 1.0, got {total}"


# Confidence bands (0–1 scale)
BAND_HIGH   = 0.50
BAND_MEDIUM = 0.25
BAND_LOW    = 0.10

# IOC attribute type groups
_VULN_TYPES    = {"vulnerability"}
_NETWORK_TYPES = {"hostname", "domain", "domain|ip", "url", "uri",
                  "ip-src", "ip-dst", "ip-src|port", "ip-dst|port"}
_FILE_TYPES    = {"md5", "sha1", "sha256", "sha512", "filename",
                  "filename|md5", "filename|sha256", "malware-sample"}


def _haystack(event: CurationEvent) -> str:
    raw_text = event_to_text(event.raw)
    parts = [
        raw_text,
        " ".join(
            item["text"] for vals in event.entities.values()
            if isinstance(vals, list)
            for item in vals
            if isinstance(item, dict) and "text" in item
        ),
        " ".join(t for t, _ in event.topics),
    ]
    return " ".join(filter(None, parts)).lower()


def _category_score(
    terms: list[str], haystack: str, saturation: float = 0.25
) -> tuple[float, list[str]]:
    """
    Saturation-based score: reaching `saturation` match-ratio = score of 1.0.
    Prevents large term lists from diluting scores when a few strong hits are present.
    e.g. with saturation=0.25: matching any 4 of 16 terms → score 1.0
    """
    if not terms:
        return 0.0, []
    matched = [t for t in terms if t.lower() in haystack]
    raw_ratio = len(matched) / len(terms)
    score = min(1.0, raw_ratio / saturation)
    return round(score, 4), matched


def _sbom_score(sbom: SBOMProfile, haystack: str) -> tuple[float, list[str]]:
    """Weighted component match: each component contributes weight/total_weight when matched."""
    if not sbom.components or sbom.total_weight == 0:
        return 0.0, []
    matched_weight = 0.0
    matched_refs: list[str] = []
    for component in sbom.components:
        if any(t in haystack for t in component.match_terms()):
            matched_weight += component.weight
            matched_refs.append(component.bom_ref)
    score = matched_weight / sbom.total_weight
    return round(score, 4), matched_refs


def _cve_sbom_score(
    sbom: SBOMProfile, event_cves: set[str]
) -> tuple[float, list[str]]:
    """
    Cross-reference event CVEs against SBOM risk entries.

    Each risk entry carries a known_cves list.  When an event CVE matches,
    the affected component weights are added to the matched pool — using the
    same weight/total_weight formula as the text-based SBOM score so the two
    signals are directly comparable and can be cleanly combined.

    Returns (score, matched_component_refs).
    """
    if not event_cves or not sbom.risks or sbom.total_weight == 0:
        return 0.0, []

    comp_weights = {c.bom_ref: c.weight for c in sbom.components}
    matched_refs: list[str] = []
    matched_weight = 0.0

    for risk in sbom.risks:
        if not risk.known_cves:
            continue
        if event_cves & {c.upper() for c in risk.known_cves}:
            for ref in risk.affected_refs:
                if ref not in matched_refs:
                    matched_refs.append(ref)
                    matched_weight += comp_weights.get(ref, 0.0)

    score = round(min(1.0, matched_weight / sbom.total_weight), 4)
    return score, matched_refs


def _ioc_score(raw: dict) -> tuple[float, dict[str, int]]:
    """
    Score based on IOC attribute type distribution.

    Sub-signals:
      vulnerability  — CVE/vuln attributes signal direct exploitability (weight 0.50)
      network IOCs   — hostnames, IPs, domains, URLs — actionable for detection (weight 0.30)
      file IOCs      — hashes, filenames — actionable for endpoint detection (weight 0.20)

    Network and file scores saturate at 5 and 10 attributes respectively,
    so a handful of indicators already yields a meaningful score.
    """
    attrs = raw.get("Attribute", [])
    if not attrs:
        return 0.0, {}

    type_counts: dict[str, int] = Counter(a["type"] for a in attrs)

    vuln_count    = sum(type_counts.get(t, 0) for t in _VULN_TYPES)
    network_count = sum(type_counts.get(t, 0) for t in _NETWORK_TYPES)
    file_count    = sum(type_counts.get(t, 0) for t in _FILE_TYPES)

    vuln_score    = 1.0 if vuln_count > 0 else 0.0
    network_score = min(1.0, network_count / 5)
    file_score    = min(1.0, file_count / 10)

    score = round(
        vuln_score    * 0.50
        + network_score * 0.30
        + file_score    * 0.20,
        4,
    )
    return score, dict(type_counts)


class ScoringStage(Stage):
    """Computes a weighted [0, 1] confidence score for each event."""

    @property
    def name(self) -> str:
        return "scoring"

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
        w   = self._weights

        sbom_s, sbom_refs = _sbom_score(self._sbom, hay)

        # CVE cross-reference: union any components whose known CVEs appear in the event
        event_cves = {
            item["text"].upper()
            for item in event.entities.get("cves", [])
            if isinstance(item, dict) and "text" in item
        }
        cve_s, cve_refs = _cve_sbom_score(self._sbom, event_cves)
        if cve_refs:
            # Recompute from the union of text-matched and CVE-matched components
            # so both signals share the same weight/total_weight formula.
            all_refs = list(dict.fromkeys(sbom_refs + cve_refs))
            matched_weight = sum(
                c.weight for c in self._sbom.components if c.bom_ref in set(all_refs)
            )
            sbom_s = round(
                min(1.0, matched_weight / self._sbom.total_weight), 4
            ) if self._sbom.total_weight > 0 else 0.0
            sbom_refs = all_refs

        # NER sbom_assets boost — confirmed entity matches raise sbom score.
        # bom_ref may be a comma-joined string when a shared term maps to multiple
        # components (e.g. "windows" -> "pos-windows11, server-windows2022").
        # Split here so dict.fromkeys can deduplicate properly against sbom_refs.
        ner_sbom_hits = []
        for item in event.entities.get("sbom_assets", []):
            if isinstance(item, dict) and "bom_ref" in item:
                for ref in item["bom_ref"].split(","):
                    ref = ref.strip()
                    if ref:
                        ner_sbom_hits.append(ref)
        if ner_sbom_hits:
            ner_boost = min(0.2, len(set(ner_sbom_hits)) * 0.07)
            sbom_s = round(min(1.0, sbom_s + ner_boost), 4)
            sbom_refs = list(dict.fromkeys(sbom_refs + ner_sbom_hits))

        # Keyword scoring — SBOM-derived compound phrases only.
        # Phrases like "esxi ransomware", "pos malware windows", "nginx exploit"
        # are far more discriminating than single generic terms.
        # Saturation: ~3 exact compound phrase matches → score 1.0.
        if self._profile.specific_keywords:
            kw_s, kw_matched = _category_score(
                [t.lower() for t in self._profile.specific_keywords], hay, saturation=0.006
            )
        else:
            kw_s, kw_matched = 0.0, []

        tech_s,  tech_matched = _category_score(
            [t.lower() for t in self._profile.technologies], hay, saturation=0.30
        )
        ctx_terms = (
            [t.lower() for t in self._profile.sectors]
            + [t.lower() for t in self._profile.geographies]
        )
        ctx_s, ctx_matched = _category_score(ctx_terms, hay, saturation=0.50)

        ioc_s, ioc_counts = _ioc_score(event.raw)
        topic_s = event.topic_relevance_score  # set by TopicModelStage

        confidence = round(
            sbom_s  * w.sbom
            + kw_s  * w.keyword
            + ioc_s * w.ioc
            + topic_s * w.topic
            + tech_s * w.technology
            + ctx_s * w.context,
            4,
        )

        event.confidence              = confidence
        event.matched_sbom_components = sbom_refs
        event.matched_profile_terms   = kw_matched + tech_matched + ctx_matched
        event.ioc_summary             = ioc_counts
        event.score_breakdown         = {
            "sbom":        round(sbom_s,  4),
            "sbom_cve":    round(cve_s,   4),  # CVE→component cross-reference contribution
            "keyword":     round(kw_s,    4),
            "ioc":         round(ioc_s,   4),
            "topic":       round(topic_s, 4),
            "tech":        round(tech_s,  4),
            "context":     round(ctx_s,   4),
        }

        logger.debug(
            "Event %s → %.4f  sbom=%.3f kw=%.3f ioc=%.3f topic=%.3f tech=%.3f ctx=%.3f",
            event.misp_id, confidence, sbom_s, kw_s, ioc_s, topic_s, tech_s, ctx_s,
        )
        return event
