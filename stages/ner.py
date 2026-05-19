#Stage 2 — Named Entity Recognition over event text.

from __future__ import annotations

import json
import logging
import os
import re
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pipeline.base import Stage
from pipeline.event import CurationEvent
from pipeline.text import event_to_text

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
IOC_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
    r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
IOC_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b",
    re.IGNORECASE,
)
IOC_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
IOC_HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
IOC_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

EXPLOIT_CONTEXT_PATTERN = re.compile(
    r"\b(?:vulnerabilit(?:y|ies)|exploit(?:ed|ing|ation|s)?|patch(?:ed|ing)?"
    r"|zero.?day|remote.?code.?execution|rce|arbitrary.?code"
    r"|privilege.?escalation|injection|buffer.?overflow|use.?after.?free)\b",
    re.IGNORECASE,)

@dataclass(frozen=True)
class OrgAssets:
    software_terms: frozenset[str]
    technologies: frozenset[str]
    sectors: frozenset[str]
    geographies: frozenset[str]
    cpe_products: frozenset[str]
    sbom_term_map: dict[str, str]


_org_asset_lock = threading.Lock()
_org_asset_cache: dict[tuple[str, str], OrgAssets] = {}


def _build_org_assets(profile_path: Path, sbom_path: Path) -> OrgAssets:
    software_terms: set[str] = set()
    technologies: set[str] = set()
    sectors: set[str] = set()
    geographies: set[str] = set()
    cpe_products: set[str] = set()
    sbom_term_map: dict[str, str] = {}

    if sbom_path.exists():
        try:
            from pipeline.sbom import load_sbom

            sbom = load_sbom(sbom_path)
            multi_ref_map: dict[str, list[str]] = {}
            for component in sbom.components:
                for term in component.match_terms():
                    t = term.lower()
                    if len(t) >= 4:
                        software_terms.add(t)
                        multi_ref_map.setdefault(t, [])
                        if component.bom_ref not in multi_ref_map[t]:
                            multi_ref_map[t].append(component.bom_ref)

            for term, refs in multi_ref_map.items():
                sbom_term_map[term] = refs[0] if len(refs) == 1 else ", ".join(refs)

            logger.info("sbom_loaded components=%d unique_terms=%d", len(sbom.components), len(software_terms))
        except Exception as exc:
            logger.error("sbom_load_failed: %s", exc)

    if profile_path.exists():
        try:
            data = json.loads(profile_path.read_text(encoding="utf-8"))
            org = data.get("organisation", {})

            for func in org.get("critical_business_functions", []):
                sectors.add(func.lower())

            hq = org.get("primary_headquarters", "")
            for part in hq.split(","):
                part = part.strip()
                if len(part) >= 4:
                    geographies.add(part.lower())

            tech_stack = data.get("technology_stack", {})

            def extract_tech_list(obj: object) -> None:
                skip_values = {
                    "n/a", "none", "true", "false", "hybrid", "basic", "intermediate",
                    "advanced", "co-managed", "in-house", "on-prem", "public", "private",
                }
                if isinstance(obj, dict):
                    for value in obj.values():
                        extract_tech_list(value)
                elif isinstance(obj, list):
                    for item in obj:
                        extract_tech_list(item)
                elif isinstance(obj, str):
                    s = obj.strip()
                    s_lower = s.lower()
                    if (
                        s
                        and len(s) > 2
                        and len(s.split()) <= 4
                        and s_lower not in skip_values
                        and not s[0].isdigit()
                    ):
                        technologies.add(s_lower)

            extract_tech_list(tech_stack)

            for cpe in data.get("cpe_list", []):
                parts = cpe.split(":")
                if len(parts) >= 5:
                    product = re.sub(r"[_\-]", " ", parts[4]).strip().lower()
                    if product and product != "*":
                        cpe_products.add(product)

            logger.info(
                "org_profile_loaded sectors=%d geographies=%d technologies=%d cpes=%d",
                len(sectors), len(geographies), len(technologies), len(cpe_products),
            )
        except Exception as exc:
            logger.error("org_profile_load_failed: %s", exc)

    return OrgAssets(
        software_terms=frozenset(software_terms),
        technologies=frozenset(technologies),
        sectors=frozenset(sectors),
        geographies=frozenset(geographies),
        cpe_products=frozenset(cpe_products),
        sbom_term_map=sbom_term_map,
    )


def _get_org_assets(profile_path: Path, sbom_path: Path) -> OrgAssets:
    cache_key = (str(profile_path.resolve()), str(sbom_path.resolve()))
    with _org_asset_lock:
        cached = _org_asset_cache.get(cache_key)
        if cached is not None:
            return cached
        assets = _build_org_assets(profile_path=profile_path, sbom_path=sbom_path)
        _org_asset_cache[cache_key] = assets
        return assets

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


def _contains_term(text_lower: str, term: str) -> bool:
    if not term:
        return False
    if re.search(r"[a-z0-9]", term, re.IGNORECASE):
        return re.search(r"\b" + re.escape(term) + r"\b", text_lower) is not None
    return term in text_lower


def _first_term_span(text: str, term: str) -> tuple[int, int] | None:
    text_lower = text.lower()
    term_lower = term.lower()
    if re.search(r"[a-z0-9]", term_lower, re.IGNORECASE):
        match = re.search(r"\b" + re.escape(term_lower) + r"\b", text_lower)
        if match:
            return match.start(), match.end()
    idx = text_lower.find(term_lower)
    if idx == -1:
        return None
    return idx, idx + len(term)


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
        spacy_bootstrap_model: str = "en_core_web_lg",
        profile_path: str | Path | None = None,
        sbom_path: str | Path | None = None,
    ) -> None:
        self._auto_download = spacy_auto_download
        self._bootstrap_model = spacy_bootstrap_model
        self._profile_path = Path(profile_path) if profile_path else Path(PROFILE_PATH)
        self._sbom_path = Path(sbom_path) if sbom_path else Path(SBOM_PATH)

        self._nlp_instance = None
        self._nlp_unavailable_flag = False
        self._bootstrap_attempted = False
        self._nlp_lock = threading.Lock()

        assets = _get_org_assets(self._profile_path, self._sbom_path)
        self._org_software = set(assets.software_terms)
        self._org_technologies = set(assets.technologies)
        self._org_sectors = set(assets.sectors)
        self._org_geographies = set(assets.geographies)
        self._org_cpe_products = set(assets.cpe_products)
        self._org_sbom_term_map = dict(assets.sbom_term_map)

    # public helpers

    @property
    def nlp_unavailable(self) -> bool:
        return self._nlp_unavailable_flag

    def ensure_model(self) -> bool:
        return self._get_nlp() is not None

    # Stage entry point 

    def process(self, event: CurationEvent) -> CurationEvent:
        text = event_to_text(event.raw)
        entities = self._regex_entities(text)

        try:
            nlp = self._get_nlp()
            if nlp is not None:
                # Extract only text chunks that mention our inventory terms
                relevant_chunks = self._extract_relevant_chunks(text)

                if relevant_chunks:
                    # Process chunks independently so long events do not truncate away entities.
                    for chunk_text, chunk_start in relevant_chunks:
                        doc = nlp(chunk_text)
                        for ent in doc.ents:
                            label = ent.label_
                            value = _clean_entity_text(ent.text)
                            if not value or len(value) < 2:
                                continue

                            value_lower = value.lower()
                            original_start = chunk_start + ent.start_char
                            original_end = chunk_start + ent.end_char

                            if label in ("ORG", "PRODUCT"):
                                if self._is_org_software_strict(value_lower):
                                    boost = _context_boost(text, original_start, original_end)
                                    _append_unique(
                                        entities,
                                        "software",
                                        {"text": value, "confidence": min(0.95, 0.85 + boost)},
                                    )
                            elif label == "GPE":
                                if self._is_org_geography_strict(value_lower):
                                    boost = _context_boost(text, original_start, original_end)
                                    _append_unique(
                                        entities,
                                        "geographies",
                                        {"text": value, "confidence": min(0.95, 0.80 + boost)},
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
            "geographies": [], "malware": [], "sbom_assets": [],
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

        # SBOM-confirmed asset mentions — highest confidence, separate bucket
        # so scoring can weight them independently of generic software mentions.
        for term, bom_ref in self._org_sbom_term_map.items():
            if _contains_term(text_lower, term) and term not in seen:
                seen.add(term)
                span = _first_term_span(text, term)
                if span is None:
                    continue
                boost = _context_boost(text, span[0], span[1])
                _append_unique(
                    entities,
                    "sbom_assets",
                    {"text": term, "bom_ref": bom_ref, "confidence": min(0.97, 0.90 + boost)},
                )

        # Remaining org technology terms not already captured as SBOM assets
        remaining_terms = (self._org_technologies | self._org_cpe_products) - self._org_sbom_term_map.keys()
        for term in remaining_terms:
            if _contains_term(text_lower, term) and term not in seen:
                seen.add(term)
                span = _first_term_span(text, term)
                if span is None:
                    continue
                boost = _context_boost(text, span[0], span[1])
                entities["software"].append(
                    {"text": term, "confidence": min(0.95, 0.85 + boost)}
                )

        # Organization sectors
        for sector in self._org_sectors:
            if _contains_term(text_lower, sector) and sector not in seen:
                seen.add(sector)
                entities["sectors"].append({"text": sector, "confidence": 0.9})

        # Organization geographies — word-boundary match to avoid substring noise
        # e.g. "illinois" should not match inside "illinoisville"; "chicago" is fine
        for geo in self._org_geographies:
            if re.search(r"\b" + re.escape(geo) + r"\b", text_lower) and geo not in seen:
                seen.add(geo)
                entities["geographies"].append({"text": geo, "confidence": 0.9})

        return entities

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

    def _is_org_geography_strict(self, value_lower: str) -> bool:
        """Strict geography matching — exact or contained, minimum 4 chars."""
        if value_lower in self._org_geographies:
            return True
        for geo in self._org_geographies:
            if len(geo) >= 4 and geo in value_lower:
                return True
        return False

    def _extract_relevant_chunks(self, text: str, context_window: int = 200) -> list[tuple[str, int]]:
        text_lower = text.lower()
        chunks: list[tuple[str, int]] = []
        seen_positions: set[int] = set()

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
            for match in re.finditer(r"\b" + re.escape(term) + r"\b", text_lower):
                pos = match.start()

                # Check if we've already captured this region
                if any(abs(pos - seen_pos) < context_window for seen_pos in seen_positions):
                    continue

                # Extract context around the term
                chunk_start = max(0, pos - context_window)
                chunk_end = min(len(text), pos + len(term) + context_window)
                chunk = text[chunk_start:chunk_end]

                chunks.append((chunk, chunk_start))
                seen_positions.add(pos)

        logger.debug("Extracted %d relevant chunks from text (inventory terms found)", len(chunks))
        return chunks
