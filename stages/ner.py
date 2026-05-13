#Stage 2 — Named Entity Recognition over event text.

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
from pathlib import Path
from typing import Any

from pipeline.base import Stage
from pipeline.event import CurationEvent
from pipeline.sbom import SBOMProfile

logger = logging.getLogger(__name__)

# Configuration

PROFILE_PATH = os.environ.get("ORG_PROFILE_PATH", "Assets/Test-bed Profile.json")
SBOM_PATH = os.environ.get("ORG_SBOM_PATH", "Assets/SBOM.json")
MITRE_ACTOR_CACHE_PATH = os.environ.get("MITRE_ACTOR_CACHE_PATH", "data/mitre_actor_cache.json")
SPACY_AUTO_DOWNLOAD = os.environ.get("SPACY_AUTO_DOWNLOAD", "true").strip().lower() == "true"
SPACY_BOOTSTRAP_MODEL = os.environ.get("SPACY_BOOTSTRAP_MODEL", "en_core_web_lg")

_SPACY_FALLBACK_MODELS = ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"]

# Pre-compiled patterns

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TTP_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
IOC_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|xyz|top)\b", re.IGNORECASE)
IOC_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
IOC_HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
IOC_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

EXPLOIT_CONTEXT_PATTERN = re.compile(
    r"\b(?:vulnerabilit(?:y|ies)|exploit(?:ed|ing|ation|s)?|patch(?:ed|ing)?"
    r"|zero.?day|remote.?code.?execution|rce|arbitrary.?code"
    r"|privilege.?escalation|injection|buffer.?overflow|use.?after.?free)\b",
    re.IGNORECASE,)

# Module-level state for organization-specific assets

_org_software_terms: set[str] = set()
_org_technologies: set[str] = set()
_org_sectors: set[str] = set()
_org_geographies: set[str] = set()
_org_cpe_products: set[str] = set()
_org_asset_lock = threading.Lock()
_known_actors_lock = threading.Lock()


def _load_organization_assets() -> None:
    global _org_software_terms, _org_technologies, _org_sectors, _org_geographies, _org_cpe_products

    with _org_asset_lock:
        # Load SBOM components
        sbom_path = Path(SBOM_PATH)
        if sbom_path.exists():
            try:
                from pipeline.sbom import load_sbom
                sbom = load_sbom(sbom_path)

                # Extract all match terms from SBOM components
                for component in sbom.components:
                    for term in component.match_terms():
                        _org_software_terms.add(term.lower())

                logger.info("sbom_loaded components=%d unique_terms=%d", 
                           len(sbom.components), len(_org_software_terms))
            except Exception as exc:
                logger.error("sbom_load_failed: %s", exc)

        # Load organization profile
        profile_path = Path(PROFILE_PATH)
        if profile_path.exists():
            try:
                data = json.loads(profile_path.read_text(encoding="utf-8"))

                # Extract sectors/business functions
                org = data.get("organisation", {})
                for func in org.get("critical_business_functions", []):
                    _org_sectors.add(func.lower())

                # Extract geographies
                hq = org.get("primary_headquarters", "")
                for part in hq.split(","):
                    part = part.strip()
                    if part:
                        _org_geographies.add(part.lower())

                for jurisdiction in org.get("jurisdiction", []):
                    _org_geographies.add(jurisdiction.lower())

                # Extract technology stack from profile
                tech_stack = data.get("technology_stack", {})

                def _extract_tech_list(obj):
                    """Recursively extract technology names from nested structures."""
                    if isinstance(obj, dict):
                        for value in obj.values():
                            _extract_tech_list(value)
                    elif isinstance(obj, list):
                        for item in obj:
                            if isinstance(item, str) and item.strip() and item not in ["N/A", "None", "none", ""]:
                                for tech in item.split(","):
                                    tech = tech.strip().lower()
                                    if tech and len(tech) > 2:
                                        _org_technologies.add(tech)
                            else:
                                _extract_tech_list(item)
                    elif isinstance(obj, str) and obj.strip() and obj not in ["N/A", "None", "none", ""]:
                        tech = obj.strip().lower()
                        if tech and len(tech) > 2:
                            _org_technologies.add(tech)

                _extract_tech_list(tech_stack)

                # Extract CPE list
                for cpe in data.get("cpe_list", []):
                    parts = cpe.split(":")
                    if len(parts) >= 5:
                        product = re.sub(r"[_\-]", " ", parts[4]).strip().lower()
                        if product and product != "*":
                            _org_cpe_products.add(product)

                logger.info("org_profile_loaded sectors=%d geographies=%d technologies=%d cpes=%d",
                           len(_org_sectors), len(_org_geographies), len(_org_technologies), len(_org_cpe_products))
            except Exception as exc:
                logger.error("org_profile_load_failed: %s", exc)


# Load organization assets on module import
_load_organization_assets()

# MISP text assembly

_TEXT_FIELDS = ("info", "description")
_TEXT_ATTR_TYPES = {"text", "comment", "vulnerability"}


def _event_to_text(raw: dict[str, Any]) -> str:
#Build a single text string from all relevant fields of a MISP event dict.
    parts = [raw.get(f, "") for f in _TEXT_FIELDS]
    parts += [
        a.get("value", "")
        for a in raw.get("Attribute", [])
        if a.get("type") in _TEXT_ATTR_TYPES
    ]
    parts += [t.get("name", "") for t in raw.get("Tag", [])]
    parts += [
        f"{gc.get('value', '')} {gc.get('description', '')}"
        for g in raw.get("Galaxy", [])
        for gc in g.get("GalaxyCluster", [])
    ]
    return " ".join(filter(None, parts))

# Shared helpers

def _download_spacy_model(model: str) -> bool:
    import subprocess as _sp
    try:
        result = _sp.run(
            [sys.executable, "-m", "spacy", "download", model],
            capture_output=True,
            timeout=120,
        )
        return result.returncode == 0
    except Exception as exc:
        logger.warning("spacy_download_failed model=%s error=%s", model, exc)
        return False


def _clean_entity_text(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip(" \t\r\n.,;:()[]{}\"'"))


def _append_unique(entities: dict, key: str, entry: dict) -> None:
    bucket = entities.setdefault(key, [])
    existing = {item.get("text", "").lower() for item in bucket}
    if entry.get("text", "").lower() not in existing:
        bucket.append(entry)


def _context_boost(text: str, start: int, end: int, window: int = 150) -> float:
    context = text[max(0, start - window): end + window]
    return 0.15 if EXPLOIT_CONTEXT_PATTERN.search(context) else 0.0


def _is_private_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    if a == 10:
        return True
    if a == 172 and 16 <= b <= 31:
        return True
    if a == 192 and b == 168:
        return True
    if a == 127:
        return True
    return False


# NERStage — Stage interface

class NERStage(Stage):
    #Extracts named entities from events text focusing on organization-specific assets.

    @property
    def name(self) -> str:
        return "ner"

    def __init__(
        self,
        spacy_auto_download: bool = True,
        spacy_bootstrap_model: str = "en_core_web_lg",) -> None:
        self._auto_download = spacy_auto_download
        self._bootstrap_model = spacy_bootstrap_model

        self._nlp_instance = None
        self._nlp_unavailable_flag = False
        self._bootstrap_attempted = False
        self._nlp_lock = threading.Lock()

        # Use organization-specific asset sets
        self._org_software = _org_software_terms.copy()
        self._org_technologies = _org_technologies.copy()
        self._org_sectors = _org_sectors.copy()
        self._org_geographies = _org_geographies.copy()
        self._org_cpe_products = _org_cpe_products.copy()

    # public helpers

    @property
    def nlp_unavailable(self) -> bool:
        return self._nlp_unavailable_flag

    def ensure_model(self) -> bool:
        return self._get_nlp() is not None

    # Stage entry point 

    def process(self, event: CurationEvent) -> CurationEvent:
        text = _event_to_text(event.raw)
        entities = self._regex_entities(text)

        try:
            nlp = self._get_nlp()
            if nlp is not None:
                # Extract only text chunks that mention our inventory terms
                relevant_chunks = self._extract_relevant_chunks(text)

                if relevant_chunks:
                    # Only run spaCy on text that mentions our assets
                    combined_text = " ... ".join(relevant_chunks)
                    doc = nlp(combined_text[:5000])

                    for ent in doc.ents:
                        label = ent.label_
                        value = _clean_entity_text(ent.text)
                        if not value or len(value) < 2:
                            continue

                        # Check if this entity matches organization software/tech
                        value_lower = value.lower()
                        if label in ("ORG", "PRODUCT"):
                            if self._is_org_software_strict(value_lower):
                                boost = _context_boost(text, 0, len(text))
                                _append_unique(
                                    entities,
                                    "software",
                                    {"text": value, "confidence": min(0.95, 0.85 + boost)},
                                )
                        elif label == "GPE":
                            if self._is_org_geography_strict(value_lower):
                                _append_unique(
                                    entities,
                                    "geographies",
                                    {"text": value, "confidence": 0.9},
                                )
                else:
                    logger.debug("Event %s: No inventory terms found in text, skipping spaCy", 
                                event.misp_id)
        except Exception as exc:
            logger.warning("spacy_ner_failed: %s", exc)

        entities.setdefault("malware", [])
        entities.setdefault("geographies", [])

        entities["_raw_text"] = text
        event.entities = entities
        logger.debug(
            "Event %s entities: %s",
            event.misp_id,
            {k: len(v) for k, v in entities.items() if isinstance(v, list)},
        )
        return event

    # Internal NLP

    def _get_nlp(self):
        with self._nlp_lock:
            if self._nlp_instance is not None:
                return self._nlp_instance
            if self._nlp_unavailable_flag:
                return None
            try:
                import spacy
            except BaseException as exc:
                if isinstance(exc, SystemExit):
                    raise
                self._nlp_unavailable_flag = True
                logger.warning(
                    "spacy_import_failed %s: %s ; falling back to regex only",
                    type(exc).__name__, str(exc)[:200],
                )
                return None

            resolved = self._try_models(spacy, _SPACY_FALLBACK_MODELS)
            if resolved is not None:
                self._nlp_instance = resolved
                return resolved

            if self._auto_download and not self._bootstrap_attempted:
                self._bootstrap_attempted = True
                logger.info("spacy_bootstrapping_model=%s", self._bootstrap_model)
                if _download_spacy_model(self._bootstrap_model):
                    resolved = self._try_models(
                        spacy, ["en_core_web_lg", self._bootstrap_model]
                    )
                    if resolved is not None:
                        self._nlp_instance = resolved
                        return resolved

            self._nlp_unavailable_flag = True
            logger.warning("spacy_model_unavailable — falling back to regex only")
            return None

    @staticmethod
    def _try_models(spacy, models: list):
        for model in models:
            try:
                loaded = spacy.load(model)
                logger.info("spacy_model_loaded=%s", model)
                return loaded
            except OSError:
                continue
            except Exception as exc:
                logger.warning("spacy_model_unavailable: %s", exc)
                return None
        return None

    def _regex_entities(self, text: str) -> dict:
        """Extract entities using regex patterns, focusing on org-specific software."""
        entities: dict = {
            "cves": [], "ttps": [], "iocs": [],
            "threat_actors": [], "sectors": [], "software": [],
            "geographies": [], "malware": []
        }
        seen: set = set()

        # CVEs - always relevant
        for match in CVE_PATTERN.finditer(text):
            value = match.group().upper()
            if value not in seen:
                seen.add(value)
                entities["cves"].append({"text": value, "confidence": 1.0})

        # TTPs - always relevant
        for match in TTP_PATTERN.finditer(text):
            value = match.group().upper()
            if value not in seen:
                seen.add(value)
                entities["ttps"].append({"text": value, "confidence": 0.95})

        # IOCs - Hashes
        for match in IOC_HASH_SHA256.finditer(text):
            value = match.group()
            if value not in seen:
                seen.add(value)
                entities["iocs"].append({"text": value, "type": "sha256", "confidence": 0.99})

        for match in IOC_HASH_SHA1.finditer(text):
            value = match.group()
            if value not in seen:
                seen.add(value)
                entities["iocs"].append({"text": value, "type": "sha1", "confidence": 0.99})

        for match in IOC_HASH_MD5.finditer(text):
            value = match.group()
            if value not in seen:
                seen.add(value)
                entities["iocs"].append({"text": value, "type": "md5", "confidence": 0.95})

        # IOCs - IPs (filter private)
        for match in IOC_IP.finditer(text):
            value = match.group()
            if not _is_private_ip(value) and value not in seen:
                seen.add(value)
                entities["iocs"].append({"text": value, "type": "ipv4", "confidence": 0.9})

        # IOCs - Domains
        for match in IOC_DOMAIN.finditer(text):
            value = match.group().lower()
            if value not in seen:
                seen.add(value)
                entities["iocs"].append({"text": value, "type": "domain", "confidence": 0.85})

        # Organization-specific software and technologies
        text_lower = text.lower()

        # Check for SBOM components and technologies
        all_org_terms = self._org_software | self._org_technologies | self._org_cpe_products
        for term in all_org_terms:
            if term in text_lower and term not in seen:
                seen.add(term)
                idx = text_lower.index(term)
                boost = _context_boost(text, idx, idx + len(term))
                entities["software"].append(
                    {"text": term, "confidence": min(0.95, 0.85 + boost)}
                )

        # Organization sectors
        for sector in self._org_sectors:
            if sector in text_lower and sector not in seen:
                seen.add(sector)
                entities["sectors"].append({"text": sector, "confidence": 0.9})

        # Organization geographies
        for geo in self._org_geographies:
            if geo in text_lower and geo not in seen:
                seen.add(geo)
                entities["geographies"].append({"text": geo, "confidence": 0.9})

        return entities

    def _is_org_software(self, value_lower: str) -> bool:
        """Check if a value matches organization's software or technologies."""
        # Direct match
        if value_lower in self._org_software:
            return True
        if value_lower in self._org_technologies:
            return True
        if value_lower in self._org_cpe_products:
            return True

        # Partial match (contains)
        for term in self._org_software | self._org_technologies | self._org_cpe_products:
            if term in value_lower or value_lower in term:
                return True

        return False

    def _is_org_software_strict(self, value_lower: str) -> bool:
        # Exact match
        if value_lower in self._org_software:
            return True
        if value_lower in self._org_technologies:
            return True
        if value_lower in self._org_cpe_products:
            return True

        for term in self._org_software | self._org_technologies | self._org_cpe_products:
            if len(term) > 3 and term in value_lower:
                return True

        return False

    def _is_org_geography(self, value_lower: str) -> bool:
        """Check if a value matches organization's geographies."""
        for geo in self._org_geographies:
            if geo in value_lower or value_lower in geo:
                return True
        return False

    def _is_org_geography_strict(self, value_lower: str) -> bool:
        #Strict geography matching.
        # Exact match
        if value_lower in self._org_geographies:
            return True

        # Only if detected entity contains our geography
        for geo in self._org_geographies:
            if len(geo) > 2 and geo in value_lower:
                return True

        return False

    def _extract_relevant_chunks(self, text: str, context_window: int = 200) -> list[str]:
        text_lower = text.lower()
        chunks = []
        seen_positions = set()

        # Combine all organization terms
        all_terms = (self._org_software | self._org_technologies | 
                     self._org_cpe_products | self._org_geographies)

        # Sort by length (longest first) to avoid substring issues
        sorted_terms = sorted(all_terms, key=len, reverse=True)

        for term in sorted_terms:
            # Skip very short terms to avoid false positives
            if len(term) < 4:
                continue

            # Find all occurrences of this term
            start_pos = 0
            while True:
                pos = text_lower.find(term, start_pos)
                if pos == -1:
                    break

                # Check if we've already captured this region
                if any(abs(pos - seen_pos) < context_window for seen_pos in seen_positions):
                    start_pos = pos + len(term)
                    continue

                # Extract context around the term
                chunk_start = max(0, pos - context_window)
                chunk_end = min(len(text), pos + len(term) + context_window)
                chunk = text[chunk_start:chunk_end]

                chunks.append(chunk)
                seen_positions.add(pos)
                start_pos = pos + len(term)

        logger.debug("Extracted %d relevant chunks from text (inventory terms found)", len(chunks))
        return chunks
