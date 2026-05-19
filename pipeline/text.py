"""Shared MISP event text assembly helpers."""

from __future__ import annotations

from typing import Any

_TEXT_FIELDS = ("info", "description")
_TEXT_ATTR_TYPES = {"text", "comment", "vulnerability"}


def event_to_text(raw: dict[str, Any]) -> str:
    """Build a single text string from all relevant fields of a MISP event dict."""
    parts = [raw.get(field, "") for field in _TEXT_FIELDS]
    parts += [
        attr.get("value", "")
        for attr in raw.get("Attribute", [])
        if attr.get("type") in _TEXT_ATTR_TYPES
    ]
    parts += [tag.get("name", "") for tag in raw.get("Tag", [])]
    parts += [
        f"{cluster.get('value', '')} {cluster.get('description', '')}"
        for galaxy in raw.get("Galaxy", [])
        for cluster in galaxy.get("GalaxyCluster", [])
    ]
    return " ".join(filter(None, parts))