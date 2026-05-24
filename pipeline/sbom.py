"""SBOM parser — loads a CycloneDX JSON SBOM into a structured model."""

from __future__ import annotations

import json
import pathlib
import re
from dataclasses import dataclass, field


_CRITICALITY_WEIGHT = {"high": 1.0, "medium": 0.6, "low": 0.3}
_DEFAULT_WEIGHT = 0.4

_STRIP = re.compile(r"[_\-]")

_BIGRAM_STOP_WORDS = frozenset({
    "a", "an", "the", "and", "or", "in", "of", "to", "at", "by",
    "for", "from", "on", "with", "is", "are", "was", "were", "be",
    "been", "being", "have", "has", "had", "do", "does", "did",
    "will", "would", "could", "should", "may", "might", "can",
    "it", "its", "this", "that", "not", "no", "as", "if", "so",
    "but", "also", "into", "than", "more", "less", "any", "all",
})

_THREAT_VERBS = (
    "exploit", "vulnerability", "cve", "attack", "compromise",
    "brute force", "privilege escalation", "remote code execution",
    "backdoor", "malware", "ransomware", "rce", "bypass",
)


def parse_cpe_product(cpe: str) -> str | None:
    """Extract and normalise the product field from a CPE 2.3 URI. Returns None for wildcards."""
    parts = cpe.split(":")
    if len(parts) >= 5:
        product = _STRIP.sub(" ", parts[4]).lower().strip()
        return product if product and product != "*" else None
    return None


@dataclass
class SBOMComponent:
    bom_ref: str
    name: str
    version: str
    supplier: str
    cpe: str | None
    criticality: str
    weight: float
    aliases: list[str] = field(default_factory=list)

    def match_terms(self) -> list[str]:
        """Discriminating strings that could plausibly appear in a MISP event for this component.

        Intentionally excluded to prevent false-positive score inflation:
          - Supplier names ("microsoft", "canonical") — map to many components and fire on
            any event that mentions the vendor even if the specific product isn't affected.
          - Version strings ("current", "8.0", "23h2") — too generic.
          - Very short first words (<7 chars) — "active" (Active Directory) matches "actively".

        Short-form aliases that are genuinely useful (e.g. "ubuntu", "aks", "sentinel")
        should be specified explicitly in the SBOM component's match_alias properties.
        """
        seen: set[str] = set()
        terms: list[str] = []

        def _add(t: str) -> None:
            t = t.lower().strip()
            if t and t not in seen:
                seen.add(t)
                terms.append(t)

        _add(self.name)

        if self.cpe:
            prod = parse_cpe_product(self.cpe)
            if prod:
                _add(prod)

        words = self.name.split()
        if len(words) >= 2:
            first = words[0].lower()
            if len(first) >= 7 and first != (self.supplier or "").lower():
                _add(first)

        for alias in self.aliases:
            _add(alias)

        return terms


@dataclass
class SBOMRisk:
    """A documented risk entry from the SBOM vulnerabilities section."""
    risk_id: str
    description: str
    affected_refs: list[str]
    severity: str
    known_cves: list[str] = field(default_factory=list)


@dataclass
class SBOMProfile:
    components: list[SBOMComponent] = field(default_factory=list)
    risks: list[SBOMRisk] = field(default_factory=list)

    @property
    def total_weight(self) -> float:
        return sum(c.weight for c in self.components)

    def high_criticality(self) -> list[SBOMComponent]:
        return [c for c in self.components if c.criticality == "high"]

    def all_match_terms(self) -> set[str]:
        """Flat set of all component match terms — used for fast NER lookup."""
        return {term for c in self.components for term in c.match_terms()}

    def specific_threat_phrases(self) -> list[str]:
        """Generate asset-specific compound threat phrases for high-signal keyword matching.

        Combines each component's match terms with threat verbs to produce phrases like
        'openssh exploit', 'ubuntu vulnerability'. Also includes bigrams from SBOM risks.
        """
        seen: set[str] = set()
        phrases: list[str] = []

        for component in self.components:
            for term in component.match_terms()[:2]:
                if len(term) < 4:
                    continue
                for verb in _THREAT_VERBS:
                    phrase = f"{term} {verb}"
                    if phrase not in seen:
                        seen.add(phrase)
                        phrases.append(phrase)

        for risk in self.risks:
            words = re.findall(r"\b[a-z][a-z0-9\-]{2,}\b", risk.description.lower())
            for i in range(len(words) - 1):
                bigram = f"{words[i]} {words[i + 1]}"
                if bigram not in seen and not all(w in _BIGRAM_STOP_WORDS for w in bigram.split()):
                    seen.add(bigram)
                    phrases.append(bigram)

        return phrases


def _cpe_queryable(cpe: str) -> bool:
    """True if the CPE has at least vendor and product specified (not wildcards)."""
    parts = cpe.split(":")
    return (len(parts) >= 5
            and parts[3] not in ("", "*")
            and parts[4] not in ("", "*"))


def inject_profile_cpes(profile: SBOMProfile, cpe_list: list[str]) -> None:
    """Add synthetic SBOM components for org-profile CPEs not already in the SBOM.

    Profile CPEs cover non-software technology assets (firewalls, middleware, etc.)
    that tools like Syft do not discover. Injecting them lets NVD enrichment and
    CVE cross-reference scoring cover the full technology estate.
    """
    existing_cpes = {c.cpe for c in profile.components if c.cpe}
    for cpe in cpe_list:
        if cpe in existing_cpes:
            continue
        parts   = cpe.split(":")
        vendor  = parts[3] if len(parts) > 3 and parts[3] != "*" else "unknown"
        product = parts[4] if len(parts) > 4 and parts[4] != "*" else "unknown"
        version = parts[5] if len(parts) > 5 and parts[5] != "*" else ""
        name    = f"{vendor} {product}".replace("_", " ").title()
        bom_ref = f"profile-{product.replace('_', '-')}"
        profile.components.append(SBOMComponent(
            bom_ref=bom_ref,
            name=name,
            version=version,
            supplier=vendor,
            cpe=cpe,
            criticality="medium",
            weight=_CRITICALITY_WEIGHT.get("medium", 0.6),
            aliases=[],
        ))


def enrich_with_nvd(
    profile: SBOMProfile,
    cache_path: pathlib.Path,
    api_key: str | None = None,
) -> None:
    """Append NVD-sourced CVEs to risk entries for every queryable component CPE.

    A CPE is queryable when vendor and product are both specified. Trailing
    version/edition wildcards are fine — NVD returns all CVEs for that product.
    """
    from pipeline.nvd import enrich_cpe_list

    cpe_list = [c.cpe for c in profile.components if c.cpe and _cpe_queryable(c.cpe)]
    if not cpe_list:
        return

    nvd_data = enrich_cpe_list(cpe_list, cache_path, api_key)

    for component in profile.components:
        if not component.cpe or component.cpe not in nvd_data:
            continue
        new_cves = [c.upper() for c in nvd_data[component.cpe]]
        if not new_cves:
            continue
        existing = next(
            (r for r in profile.risks if component.bom_ref in r.affected_refs), None
        )
        if existing:
            existing.known_cves = list(dict.fromkeys(existing.known_cves + new_cves))
        else:
            profile.risks.append(SBOMRisk(
                risk_id=f"NVD-{component.bom_ref}",
                description=f"NVD CVEs for {component.name} ({component.cpe})",
                affected_refs=[component.bom_ref],
                severity="unknown",
                known_cves=new_cves,
            ))


def load_sbom(path: pathlib.Path) -> SBOMProfile:
    data = json.loads(path.read_text(encoding="utf-8"))
    components = []
    for raw in data.get("components", []):
        props_list = raw.get("properties", [])
        props = {p["name"]: p["value"] for p in props_list}
        criticality = props.get("criticality", "unknown")
        aliases = [p["value"] for p in props_list if p.get("name") == "match_alias"]
        components.append(SBOMComponent(
            bom_ref=raw.get("bom-ref", ""),
            name=raw.get("name", ""),
            version=raw.get("version", ""),
            supplier=raw.get("supplier", {}).get("name", ""),
            cpe=raw.get("cpe"),
            criticality=criticality,
            weight=_CRITICALITY_WEIGHT.get(criticality, _DEFAULT_WEIGHT),
            aliases=aliases,
        ))

    risks = []
    for raw in data.get("vulnerabilities", []):
        severity = next(
            (r.get("severity", "unknown") for r in raw.get("ratings", [])),
            "unknown",
        )
        risks.append(SBOMRisk(
            risk_id=raw.get("id", ""),
            description=raw.get("description", ""),
            affected_refs=[a.get("ref", "") for a in raw.get("affects", [])],
            severity=severity,
            known_cves=[c.upper() for c in raw.get("known_cves", [])],
        ))

    return SBOMProfile(components=components, risks=risks)
