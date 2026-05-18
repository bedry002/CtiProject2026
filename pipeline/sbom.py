"""SBOM parser — loads a CycloneDX JSON SBOM into a structured model."""

import json
import pathlib
import re
from dataclasses import dataclass, field


_CRITICALITY_WEIGHT = {"high": 1.0, "medium": 0.6, "low": 0.3}
_DEFAULT_WEIGHT = 0.4

_STRIP = re.compile(r"[_\-]")


def _cpe_product(cpe: str) -> str | None:
    """Extract the product field from a CPE 2.3 URI and normalise it."""
    parts = cpe.split(":")
    if len(parts) >= 5:
        return _STRIP.sub(" ", parts[4]).lower().strip()
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
    aliases: list[str] = field(default_factory=list)  # explicit short-forms from SBOM properties

    def match_terms(self) -> list[str]:
        """Discriminating strings that could plausibly appear in a MISP event for this component.

        Intentionally excluded to prevent false-positive score inflation:
          - Supplier names ("microsoft", "canonical") — map to many components and fire on
            any event that mentions the vendor even if the specific product isn't affected.
          - Version strings ("current", "8.0", "23h2") — too generic; "current" matches 3+
            components, "8.0" matches in IP addresses and unrelated software versions.
          - Very short first words (<7 chars) — "active" (Active Directory) matches "actively",
            "azure" matches in unrelated product names.

        Short-form aliases that are genuinely useful (e.g. "ubuntu", "aks", "sentinel")
        should be specified explicitly in the SBOM component's match_alias properties.
        """
        terms: list[str] = []

        # Full component name — primary signal
        terms.append(self.name.lower())

        # CPE product field — often the canonical short form
        # e.g. cpe:…:vmware:esxi → "esxi", cpe:…:nginx:nginx → "nginx"
        if self.cpe:
            prod = _cpe_product(self.cpe)
            if prod and prod not in terms:
                terms.append(prod)

        # First significant word — only if it's long enough to be a proper identifier
        # and is not the supplier name (which would re-introduce the generic-vendor problem).
        words = self.name.split()
        if len(words) >= 2:
            first = words[0].lower()
            supplier_lower = self.supplier.lower() if self.supplier else ""
            if len(first) >= 7 and first != supplier_lower and first not in terms:
                terms.append(first)

        # Explicit aliases from SBOM properties (e.g. "ubuntu", "aks", "sentinel")
        for alias in self.aliases:
            a = alias.lower().strip()
            if a and a not in terms:
                terms.append(a)

        return list(dict.fromkeys(t for t in terms if t))


@dataclass
class SBOMRisk:
    """A documented risk entry from the SBOM vulnerabilities section."""
    risk_id: str
    description: str
    affected_refs: list[str]
    severity: str
    known_cves: list[str] = field(default_factory=list)  # CVE IDs that map to this risk


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
        terms: set[str] = set()
        for c in self.components:
            terms.update(c.match_terms())
        return terms

    def specific_threat_phrases(self) -> list[str]:
        """Generate asset-specific compound threat phrases for high-signal keyword matching.

        Combines each component's match terms with threat verbs to produce
        phrases like 'openssh exploit', 'ubuntu vulnerability', 'virtualbox escape'.
        These are far more discriminating than generic single-word keywords.
        Also includes phrases derived from documented SBOM risk entries.
        """
        _THREAT_VERBS = [
            "exploit", "vulnerability", "cve", "attack", "compromise",
            "brute force", "privilege escalation", "remote code execution",
            "backdoor", "malware", "ransomware", "rce", "bypass",
        ]
        phrases: list[str] = []

        for component in self.components:
            # Use the two most distinctive terms per component (name + first word/alias).
            # Noun-first form only ("esxi ransomware", not "ransomware esxi") — this
            # matches how product names appear in CTI headlines and event descriptions,
            # and halves the phrase list without reducing match quality.
            key_terms = component.match_terms()[:2]
            for term in key_terms:
                if len(term) < 4:
                    continue
                for verb in _THREAT_VERBS:
                    phrases.append(f"{term} {verb}")

        # Add phrases derived from documented SBOM risks
        for risk in self.risks:
            # Description already contains specific risk language —
            # extract meaningful 2-3 word phrases from it
            words = re.findall(r"\b[a-z][a-z0-9\-]{2,}\b", risk.description.lower())
            for i in range(len(words) - 1):
                bigram = f"{words[i]} {words[i+1]}"
                if bigram not in phrases:
                    phrases.append(bigram)

        return list(dict.fromkeys(phrases))  # deduplicate, preserve order


def load_sbom(path: pathlib.Path) -> SBOMProfile:
    data = json.loads(path.read_text(encoding="utf-8"))
    components = []
    for raw in data.get("components", []):
        props_list = raw.get("properties", [])
        props = {p["name"]: p["value"] for p in props_list}
        criticality = props.get("criticality", "unknown")
        weight = _CRITICALITY_WEIGHT.get(criticality, _DEFAULT_WEIGHT)
        # Collect all match_alias entries (multiple properties with the same key allowed)
        aliases = [p["value"] for p in props_list if p.get("name") == "match_alias"]
        components.append(SBOMComponent(
            bom_ref=raw.get("bom-ref", ""),
            name=raw.get("name", ""),
            version=raw.get("version", ""),
            supplier=raw.get("supplier", {}).get("name", ""),
            cpe=raw.get("cpe"),
            criticality=criticality,
            weight=weight,
            aliases=aliases,
        ))

    risks = []
    for raw in data.get("vulnerabilities", []):
        severity = "unknown"
        for rating in raw.get("ratings", []):
            severity = rating.get("severity", "unknown")
            break
        # known_cves may be stored as a top-level array or inside a "references" list
        known_cves = [c.upper() for c in raw.get("known_cves", [])]
        risks.append(SBOMRisk(
            risk_id=raw.get("id", ""),
            description=raw.get("description", ""),
            affected_refs=[a.get("ref", "") for a in raw.get("affects", [])],
            severity=severity,
            known_cves=known_cves,
        ))

    return SBOMProfile(components=components, risks=risks)
