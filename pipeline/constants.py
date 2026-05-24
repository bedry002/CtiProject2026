"""Shared constants used across pipeline stages — single source of truth."""

from __future__ import annotations

BAND_HIGH   = 0.50
BAND_MEDIUM = 0.25
BAND_LOW    = 0.10

# Merged from config.py and stages/ner.py — all low-signal strings that appear in
# profile JSON fields but are not product or technology names.
SKIP_TECH_VALUES: frozenset[str] = frozenset({
    "n/a", "none", "true", "false", "hybrid", "basic",
    "intermediate", "advanced", "co-managed", "in-house",
    "on-prem", "public", "private", "current", "offline",
    "partial", "significant", "minimal", "internal_only",
    "production", "staging", "development",
})
