"""
Shared SBOM merge utilities — used by both form_api.py (web upload)
and tools/orchestrator.py (testbed DT pipeline).

Handles deduplication, criticality assignment, and CycloneDX envelope building.
"""

from __future__ import annotations

import json
import pathlib
import uuid
from datetime import datetime, timezone


# CycloneDX type → criticality mapping for components that don't already have one
_TYPE_CRITICALITY = {
    "operating-system": "high",
    "container": "high",
    "framework": "medium",
    "library": "medium",
    "application": "medium",
    "device": "high",
    "firmware": "high",
    "file": "low",
}


def get_component_criticality(component: dict) -> str:
    """
    Get the criticality of a CycloneDX component.

    If the component already has a criticality property, return it as-is.
    Otherwise assign one based on the component type.
    """
    # Check if criticality already exists in properties
    for prop in component.get("properties", []):
        if prop.get("name") == "criticality":
            return prop["value"]

    # Assign based on component type
    comp_type = (component.get("type") or "library").lower()
    return _TYPE_CRITICALITY.get(comp_type, "low")


def ensure_criticality(component: dict) -> dict:
    """
    Ensure a component has a criticality property. If it already has one,
    return unchanged. If not, add one based on the component type.

    Returns the component (mutated in place for efficiency).
    """
    props = component.get("properties", [])
    has_criticality = any(p.get("name") == "criticality" for p in props)

    if not has_criticality:
        criticality = get_component_criticality(component)
        props.append({"name": "criticality", "value": criticality})
        component["properties"] = props

    return component


def dedupe_components(components: list[dict]) -> list[dict]:
    """
    Deduplicate components by (cpe, version) or (name, version).
    First occurrence wins — later duplicates are dropped.
    """
    seen: set[tuple] = set()
    unique: list[dict] = []

    for c in components:
        key = (c.get("cpe") or c.get("name"), c.get("version"))
        if key not in seen:
            seen.add(key)
            unique.append(c)

    return unique


def merge_components(existing: list[dict], incoming: list[dict]) -> list[dict]:
    """
    Merge incoming components into existing ones, deduplicating and
    ensuring every component has a criticality property.
    """
    combined = existing + incoming
    deduped = dedupe_components(combined)

    for comp in deduped:
        ensure_criticality(comp)

    return deduped


def build_merged_sbom(
    components: list[dict],
    description: str = "Merged CycloneDX SBOM for organisational CTI curation.",
    org_name: str = "Organisation",
) -> dict:
    """
    Wrap a list of components in a valid CycloneDX 1.6 envelope.
    """
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "authors": [{"name": "CTI Curation Engine"}],
            "component": {
                "type": "application",
                "bom-ref": "merged-sbom",
                "name": f"{org_name} — Merged SBOM",
                "version": datetime.now(timezone.utc).strftime("%Y.%m"),
                "description": description,
            },
        },
        "components": components,
    }


def load_existing_components(sbom_path: pathlib.Path) -> list[dict]:
    """
    Load components from an existing CycloneDX SBOM file.
    Returns an empty list if the file doesn't exist or is invalid.
    """
    if not sbom_path.exists():
        return []

    try:
        data = json.loads(sbom_path.read_text(encoding="utf-8"))
        return data.get("components", [])
    except (json.JSONDecodeError, KeyError):
        return []


def extract_components_from_upload(raw_json: dict) -> list[dict]:
    """
    Extract the components array from an uploaded CycloneDX JSON.
    Also preserves any vulnerabilities section for pass-through.
    """
    return raw_json.get("components", [])


def extract_vulnerabilities_from_upload(raw_json: dict) -> list[dict]:
    """Extract vulnerabilities from an uploaded CycloneDX JSON."""
    return raw_json.get("vulnerabilities", [])


def dedupe_vulnerabilities(vulns: list[dict]) -> list[dict]:
    """Deduplicate vulnerabilities by their id field."""
    seen: set[str] = set()
    unique: list[dict] = []

    for v in vulns:
        vid = v.get("id", "")
        if vid and vid not in seen:
            seen.add(vid)
            unique.append(v)
        elif not vid:
            unique.append(v)

    return unique
