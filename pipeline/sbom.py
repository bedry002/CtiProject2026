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

    def match_terms(self) -> list[str]:
        """All strings that could plausibly appear in a MISP event for this component."""
        terms: list[str] = []

        # Full name and lowercased short forms
        terms.append(self.name.lower())
        # First significant word (e.g. "ubuntu" from "Ubuntu Linux")
        first = self.name.split()[0].lower()
        if len(first) > 3:
            terms.append(first)

        # Supplier name (e.g. "canonical", "microsoft", "oracle")
        if self.supplier:
            terms.append(self.supplier.lower())

        # CPE product field (e.g. "ubuntu linux", "vm virtualbox", "windows 11")
        if self.cpe:
            prod = _cpe_product(self.cpe)
            if prod and prod not in terms:
                terms.append(prod)

        # Version string for precise matching (e.g. "24.04", "9.6p1")
        if self.version and self.version not in {"*", "built-in"}:
            terms.append(self.version.lower())

        return list(dict.fromkeys(t for t in terms if t))  # deduplicate, preserve order


@dataclass
class SBOMProfile:
    components: list[SBOMComponent] = field(default_factory=list)

    @property
    def total_weight(self) -> float:
        return sum(c.weight for c in self.components)

    def high_criticality(self) -> list[SBOMComponent]:
        return [c for c in self.components if c.criticality == "high"]


def load_sbom(path: pathlib.Path) -> SBOMProfile:
    data = json.loads(path.read_text(encoding="utf-8"))
    components = []
    for raw in data.get("components", []):
        props = {p["name"]: p["value"] for p in raw.get("properties", [])}
        criticality = props.get("criticality", "unknown")
        weight = _CRITICALITY_WEIGHT.get(criticality, _DEFAULT_WEIGHT)
        components.append(SBOMComponent(
            bom_ref=raw.get("bom-ref", ""),
            name=raw.get("name", ""),
            version=raw.get("version", ""),
            supplier=raw.get("supplier", {}).get("name", ""),
            cpe=raw.get("cpe"),
            criticality=criticality,
            weight=weight,
        ))
    return SBOMProfile(components=components)
