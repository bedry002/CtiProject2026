"""NAICS 2-digit sector hierarchy → sector terms for scoring."""

from __future__ import annotations

# 2-digit NAICS code → terms to add to BusinessProfile.sectors
NAICS_SECTORS: dict[str, list[str]] = {
    "11": ["agriculture", "farming", "forestry", "fishing"],
    "21": ["mining", "oil and gas", "energy extraction"],
    "22": ["utilities", "electricity", "water treatment", "energy"],
    "23": ["construction", "building", "infrastructure"],
    "31": ["manufacturing", "production", "factory"],
    "32": ["manufacturing", "chemical", "plastics"],
    "33": ["manufacturing", "machinery", "electronics"],
    "42": ["wholesale", "distribution", "wholesale trade"],
    "44": ["retail", "retail trade", "e-commerce", "stores"],
    "45": ["retail", "retail trade", "e-commerce", "stores"],
    "48": ["logistics", "transportation", "shipping", "freight"],
    "49": ["logistics", "warehousing", "postal", "courier"],
    "51": ["technology", "software", "media", "telecommunications", "information technology"],
    "52": ["finance", "insurance", "financial services", "banking", "fintech"],
    "53": ["real estate", "property management", "leasing"],
    "54": ["consulting", "legal", "professional services", "research"],
    "55": ["corporate", "management", "holding company"],
    "56": ["administrative", "support services", "staffing"],
    "61": ["education", "university", "academic", "training"],
    "62": ["healthcare", "medical", "clinical", "health", "hospital"],
    "71": ["entertainment", "arts", "recreation", "gaming"],
    "72": ["hospitality", "restaurant", "hotel", "food service"],
    "81": ["repair", "religious", "social services"],
    "92": ["government", "public sector", "federal", "defence", "defense"],
}


def expand_naics(naics_code: str) -> list[str]:
    """Return sector terms for the 2-digit parent of the given NAICS code."""
    if not naics_code or len(naics_code) < 2:
        return []
    prefix = naics_code[:2]
    return NAICS_SECTORS.get(prefix, [])
