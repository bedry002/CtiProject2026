"""Shared MISP event text assembly helpers."""

from __future__ import annotations

from itertools import chain
from typing import Any

_TEXT_FIELDS = ("info", "description")
_TEXT_ATTR_TYPES = frozenset({"text", "comment", "vulnerability"})


def event_to_text(raw: dict[str, Any]) -> str:
    """Build a single text string from all relevant fields of a MISP event dict."""
    return " ".join(filter(None, chain(
        (raw.get(f, "") for f in _TEXT_FIELDS),
        (a.get("value", "") for a in raw.get("Attribute", []) if a.get("type") in _TEXT_ATTR_TYPES),
        (t.get("name", "") for t in raw.get("Tag", [])),
        (
            f"{c.get('value', '')} {c.get('description', '')}"
            for g in raw.get("Galaxy", [])
            for c in g.get("GalaxyCluster", [])
        ),
    )))
