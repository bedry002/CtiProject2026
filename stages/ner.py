#  Stage 2, Named Entity Recognition over event text.

from __future__ import annotations

import bisect
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
from pipeline.sbom import parse_cpe_product
from pipeline.text import event_to_text

logger = logging.getLogger(__name__)

#  Configuration

PROFILE_PATH = os.environ.get("ORG_PROFILE_PATH", "Assets/Test-bed Profile.json")
SBOM_PATH = os.environ.get("ORG_SBOM_PATH", "Assets/SBOM.json")
MITRE_ACTOR_CACHE_PATH = os.environ.get(
    "MITRE_ACTOR_CACHE_PATH", "data/mitre_actor_cache.json"
)
SPACY_AUTO_DOWNLOAD = (
    os.environ.get("SPACY_AUTO_DOWNLOAD", "true").strip().lower() == "true"
)
SPACY_BOOTSTRAP_MODEL = os.environ.get("SPACY_BOOTSTRAP_MODEL", "en_core_web_lg")
NER_DOC_SCOPED_ONLY = (
    os.environ.get("NER_DOC_SCOPED_ONLY", "false").strip().lower() == "true"
)  # skip raw IOC/CVE regex when upstream already handles structured extraction

_SPACY_FALLBACK_MODELS = ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"]

#  Pre-compiled patterns

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TTP_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
IOC_IP = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"
)
IOC_DOMAIN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", re.IGNORECASE
)
IOC_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
IOC_HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
IOC_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

# boosts confidence on any match found near active-exploitation language rather than passive mentions
EXPLOIT_CONTEXT_PATTERN = re.compile(
    r"\b(?:vulnerabilit(?:y|ies)|exploit(?:ed|ing|ation|s)?|patch(?:ed|ing)?"
    r"|zero.?day|remote.?code.?execution|rce|arbitrary.?code"
    r"|privilege.?escalation|injection|buffer.?overflow|use.?after.?free)\b",
    re.IGNORECASE,
)

#  Org asset model


@dataclass(
    frozen=True
)  # frozen so the module-level cache can't be mutated after initial load
class OrgAssets:
    software_terms: frozenset[str]
    technologies: frozenset[str]
    sectors: frozenset[str]
    geographies: frozenset[str]
    cpe_products: frozenset[str]
    threat_actors: frozenset[str]
    sbom_term_map: dict[str, str]


# shared across pipeline workers, lock prevents two threads from building the same profile simultaneously
_org_asset_lock: threading.Lock = threading.Lock()
_org_asset_cache: dict[tuple[str, str], OrgAssets] = {}


def _build_org_assets(profile_path: Path, sbom_path: Path) -> OrgAssets:
    software_terms: set[str] = set()
    technologies: set[str] = set()
    sectors: set[str] = set()
    geographies: set[str] = set()
    cpe_products: set[str] = set()
    threat_actors: set[str] = set()
    sbom_term_map: dict[str, str] = {}

    if sbom_path.exists():
        try:
            from pipeline.sbom import load_sbom

            sbom = load_sbom(sbom_path)
            multi_ref_map: dict[str, list[str]] = {}
            for component in sbom.components:
                for term in component.match_terms():
                    t = term.lower()
                    if (
                        len(t) >= 4
                    ):  # short tokens produce too many false-positive substring matches
                        software_terms.add(t)
                        refs = multi_ref_map.setdefault(t, [])
                        if component.bom_ref not in refs:
                            refs.append(component.bom_ref)
            for term, refs in multi_ref_map.items():
                sbom_term_map[term] = (
                    refs[0] if len(refs) == 1 else ", ".join(refs)
                )  # preserve ambiguity when a name matches multiple SBOM components
            logger.info(
                "sbom_loaded components=%d unique_terms=%d",
                len(sbom.components),
                len(software_terms),
            )
        except Exception as exc:
            logger.error("sbom_load_failed: %s", exc)

    if profile_path.exists():
        try:
            data = json.loads(profile_path.read_text(encoding="utf-8"))

            for s in data.get("sectors", []):
                v = s.strip().lower()
                if v:
                    sectors.add(v)

            for t in data.get("technologies", []):
                v = t.strip().lower()
                if len(v) >= 3:
                    technologies.add(v)

            for g in data.get("geographies", []):
                v = g.strip().lower()
                if len(v) >= 3:
                    geographies.add(v)

            for actor in data.get("threat_actors", []):
                v = actor.strip().lower()
                if len(v) >= 3:
                    threat_actors.add(v)

            for cpe in data.get("cpe_list", []):
                product = parse_cpe_product(cpe)
                if product:
                    cpe_products.add(product)

            logger.info(
                "org_profile_loaded sectors=%d geographies=%d technologies=%d cpes=%d threat_actors=%d",
                len(sectors),
                len(geographies),
                len(technologies),
                len(cpe_products),
                len(threat_actors),
            )
        except Exception as exc:
            logger.error("org_profile_load_failed: %s", exc)

    return OrgAssets(
        software_terms=frozenset(software_terms),
        technologies=frozenset(technologies),
        sectors=frozenset(sectors),
        geographies=frozenset(geographies),
        cpe_products=frozenset(cpe_products),
        threat_actors=frozenset(threat_actors),
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


#  Shared helpers


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
    # spaCy frequently includes trailing punctuation and brackets inside entity spans
    return re.sub(r"\s+", " ", str(value or "").strip(" \t\r\n.,;:()[]{}\"'"))


def _append_unique(entities: dict[str, Any], key: str, entry: dict[str, Any]) -> None:
    # case-insensitive dedup so 'Apache' from spaCy and 'apache' from regex don't both appear
    bucket = entities.setdefault(key, [])
    text_lower = entry.get("text", "").lower()
    if not any(item.get("text", "").lower() == text_lower for item in bucket):
        bucket.append(entry)


def _context_boost(text: str, start: int, end: int, window: int = 150) -> float:
    # 0.15 pushes borderline matches over the reporting threshold when active exploitation is nearby
    context = text[max(0, start - window) : end + window]
    return 0.15 if EXPLOIT_CONTEXT_PATTERN.search(context) else 0.0


def _first_term_span(text: str, term: str) -> tuple[int, int] | None:
    text_lower = text.lower()
    term_lower = term.lower()
    # word boundaries don't apply to symbol only terms like "C++", fall back to plain index search
    if re.search(r"[a-z0-9]", term_lower, re.IGNORECASE):
        match = re.search(r"\b" + re.escape(term_lower) + r"\b", text_lower)
        return (match.start(), match.end()) if match else None
    idx = text_lower.find(term_lower)
    return (idx, idx + len(term)) if idx != -1 else None


def _is_term_match(value_lower: str, terms: frozenset[str], min_len: int) -> bool:
    # accepts exact match OR an inventory term embedded in a longer spaCy entity (e.g. "Microsoft Windows" contains "windows")
    return value_lower in terms or any(
        len(t) >= min_len and t in value_lower for t in terms
    )


_ATTR_NETWORK_TYPES = frozenset({"ip-src", "ip-dst", "domain", "hostname", "url"})
_ATTR_FILE_TYPES = frozenset({"md5", "sha256", "sha1"})


def _is_private_ip(ip: str) -> bool:
    # RFC 1918 + loopback, internal addresses are never meaningful external threat indicators
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
    except ValueError:
        return False
    return (
        (a == 10)
        or (a == 172 and 16 <= b <= 31)
        or (a == 192 and b == 168)
        or (a == 127)
    )


# NERStage


class NERStage(Stage):
    # Extracts named entities from event text focusing on organisation-specific assets.

    @property
    def name(self) -> str:
        return "ner"

    def __init__(
        self,
        spacy_auto_download: bool = SPACY_AUTO_DOWNLOAD,
        spacy_bootstrap_model: str = SPACY_BOOTSTRAP_MODEL,
        profile_path: str | Path | None = None,
        sbom_path: str | Path | None = None,
        doc_scoped_only: bool = NER_DOC_SCOPED_ONLY,
    ) -> None:
        self._auto_download = spacy_auto_download
        self._bootstrap_model = spacy_bootstrap_model
        self._profile_path = Path(profile_path) if profile_path else Path(PROFILE_PATH)
        self._sbom_path = Path(sbom_path) if sbom_path else Path(SBOM_PATH)
        self._doc_scoped_only = doc_scoped_only
        self._nlp_instance = None
        self._nlp_unavailable_flag = (
            False  # once set, all future model load attempts are skipped immediately
        )
        self._bootstrap_attempted = (
            False  # prevents re-triggering the pip download if the first attempt fails
        )
        self._nlp_lock = threading.Lock()

        assets = _get_org_assets(self._profile_path, self._sbom_path)
        self._org_software = assets.software_terms
        self._org_technologies = assets.technologies
        self._org_sectors = assets.sectors
        self._org_geographies = assets.geographies
        self._org_cpe_products = assets.cpe_products
        self._org_threat_actors = assets.threat_actors
        self._org_sbom_term_map = dict(assets.sbom_term_map)

        # Precomputed combined sets, avoid recomputing on every process() call
        self._all_tech_terms = (
            assets.software_terms | assets.technologies | assets.cpe_products
        )
        self._remaining_terms = (
            assets.technologies | assets.cpe_products
        ) - assets.sbom_term_map.keys()
        # Sorted longest-first for chunk extraction, computed once, reused per event
        self._sorted_extract_terms: list[str] = sorted(
            self._all_tech_terms | assets.geographies | assets.threat_actors,
            key=len,
            reverse=True,
        )

    @property
    def nlp_unavailable(self) -> bool:
        return self._nlp_unavailable_flag

    def ensure_model(self) -> bool:
        return self._get_nlp() is not None

    def process(self, event: CurationEvent) -> CurationEvent:
        # fast regex pass first; spaCy only runs over inventory-term neighbourhoods to limit CPU cost
        text = event_to_text(event.raw)
        entities = self._regex_entities(text)

        try:
            nlp = self._get_nlp()
            if nlp is not None:
                relevant_chunks = self._extract_relevant_chunks(text)
                if relevant_chunks:
                    for chunk_text, chunk_start in relevant_chunks:
                        doc = nlp(chunk_text)
                        for ent in doc.ents:
                            label = ent.label_
                            value = _clean_entity_text(ent.text)
                            if not value or len(value) < 2:
                                continue
                            value_lower = value.lower()
                            orig_start = chunk_start + ent.start_char
                            orig_end = chunk_start + ent.end_char

                            # spaCy labels software as ORG or PRODUCT depending on phrasing; both need checking
                            if label in (
                                "ORG",
                                "PRODUCT",
                            ) and self._is_org_software_match(value_lower):
                                boost = _context_boost(text, orig_start, orig_end)
                                _append_unique(
                                    entities,
                                    "software",
                                    {
                                        "text": value,
                                        "confidence": min(0.95, 0.85 + boost),
                                    },
                                )

                            if label == "GPE" and self._is_org_geography_match(
                                value_lower
                            ):
                                boost = _context_boost(text, orig_start, orig_end)
                                _append_unique(
                                    entities,
                                    "geographies",
                                    {
                                        "text": value,
                                        "confidence": min(0.95, 0.80 + boost),
                                    },
                                )

                            # NORP covers nationality/group labels; some APT names appear as demonyms in spaCy
                            if label in (
                                "ORG",
                                "PERSON",
                                "NORP",
                            ) and self._is_org_threat_actor_match(value_lower):
                                _append_unique(
                                    entities,
                                    "threat_actors",
                                    {"text": value, "confidence": 0.9},
                                )
                else:
                    logger.debug(
                        "Event %s: no inventory terms found, skipping spaCy",
                        event.misp_id,
                    )
        except Exception as exc:
            logger.warning("spacy_ner_failed: %s", exc)

        # guarantee keys exist even when nothing was found so downstream stages don't need to guard
        entities.setdefault("geographies", [])
        entities.setdefault("threat_actors", [])
        entities["_raw_text"] = text
        event.entities = entities
        self._extract_attribute_iocs(event)
        logger.debug(
            "Event %s entities: %s",
            event.misp_id,
            {k: len(v) for k, v in entities.items() if isinstance(v, list)},
        )
        return event

    def _extract_attribute_iocs(self, event: CurationEvent) -> None:
        # Populate entities from MISP attribute IOCs — catches indicators stored as attributes, not in text.
        ioc_count = len(event.entities.get("iocs", []))
        cve_count = len(event.entities.get("cves", []))
        for attr in event.raw.get("Attribute", []):
            attr_type = attr.get("type", "")
            value = str(attr.get("value", "")).strip()
            if not value:
                continue
            # cap at 10 per category, attribute-heavy events shouldn't drown out text-derived entities
            if (
                attr_type == "vulnerability"
                and CVE_PATTERN.match(value)
                and cve_count < 10
            ):
                _append_unique(
                    event.entities, "cves", {"text": value, "source": "attribute"}
                )
                cve_count += 1
            elif attr_type in _ATTR_NETWORK_TYPES and ioc_count < 10:
                _append_unique(
                    event.entities,
                    "iocs",
                    {"text": value, "type": attr_type, "confidence": 1.0},
                )
                ioc_count += 1
            elif attr_type in _ATTR_FILE_TYPES and ioc_count < 10:
                _append_unique(
                    event.entities,
                    "iocs",
                    {"text": value, "type": attr_type, "confidence": 1.0},
                )
                ioc_count += 1

    #  Internal NLP

    def _get_nlp(self) -> Any:
        with self._nlp_lock:
            # re-check under lock; another thread may have loaded the model while we were waiting
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
                    "spacy_import_failed %s: %s — falling back to regex only",
                    type(exc).__name__,
                    str(exc)[:200],
                )
                return None

            resolved = self._try_models(spacy, _SPACY_FALLBACK_MODELS)
            if resolved is not None:
                self._nlp_instance = resolved
                return resolved

            # only attempt the download once; repeated failures would stall the pipeline on every event
            if self._auto_download and not self._bootstrap_attempted:
                self._bootstrap_attempted = True
                logger.info("spacy_bootstrapping_model=%s", self._bootstrap_model)
                if _download_spacy_model(self._bootstrap_model):
                    resolved = self._try_models(spacy, [self._bootstrap_model])
                    if resolved is not None:
                        self._nlp_instance = resolved
                        return resolved

            self._nlp_unavailable_flag = True
            logger.warning("spacy_model_unavailable — falling back to regex only")
            return None

    @staticmethod
    def _try_models(spacy: Any, models: list[str]) -> Any:
        for model in models:
            try:
                loaded = spacy.load(model)
                logger.info("spacy_model_loaded=%s", model)
                return loaded
            except OSError:  # model package not installed, try the next fallback
                continue
            except Exception as exc:
                logger.warning("spacy_model_unavailable: %s", exc)
        return None

    def _regex_entities(self, text: str) -> dict[str, Any]:
        entities: dict[str, Any] = {
            "cves": [],
            "ttps": [],
            "iocs": [],
            "threat_actors": [],
            "sectors": [],
            "software": [],
            "geographies": [],
            "sbom_assets": [],
        }
        seen_ioc: set[str] = set()
        seen_terms: set[str] = set()

        # raw IOC/TTP extraction is skipped in doc_scoped_only mode, org asset matching still runs
        if not self._doc_scoped_only:
            for match in CVE_PATTERN.finditer(text):
                v = match.group().upper()
                if v not in seen_ioc:
                    seen_ioc.add(v)
                    entities["cves"].append({"text": v, "confidence": 1.0})

            for match in TTP_PATTERN.finditer(text):
                v = match.group().upper()
                if v not in seen_ioc:
                    seen_ioc.add(v)
                    entities["ttps"].append({"text": v, "confidence": 0.95})

            for match in IOC_HASH_SHA256.finditer(text):
                v = match.group()
                if v not in seen_ioc:
                    seen_ioc.add(v)
                    entities["iocs"].append(
                        {"text": v, "type": "sha256", "confidence": 0.99}
                    )

            for match in IOC_HASH_SHA1.finditer(text):
                v = match.group()
                if v not in seen_ioc:
                    seen_ioc.add(v)
                    entities["iocs"].append(
                        {"text": v, "type": "sha1", "confidence": 0.99}
                    )

            for match in IOC_HASH_MD5.finditer(text):
                v = match.group()
                if v not in seen_ioc:
                    seen_ioc.add(v)
                    entities["iocs"].append(
                        {"text": v, "type": "md5", "confidence": 0.95}
                    )

            for match in IOC_IP.finditer(text):
                v = match.group()
                if not _is_private_ip(v) and v not in seen_ioc:
                    seen_ioc.add(v)
                    entities["iocs"].append(
                        {"text": v, "type": "ipv4", "confidence": 0.9}
                    )

            for match in IOC_DOMAIN.finditer(text):
                v = match.group().lower()
                if v not in seen_ioc:
                    seen_ioc.add(v)
                    entities["iocs"].append(
                        {"text": v, "type": "domain", "confidence": 0.85}
                    )

        # SBOM-confirmed asset mentions, highest confidence, links back to a known inventory component
        for term, bom_ref in self._org_sbom_term_map.items():
            if term in seen_terms:
                continue
            span = _first_term_span(text, term)
            if span is None:
                continue
            seen_terms.add(term)
            boost = _context_boost(text, span[0], span[1])
            _append_unique(
                entities,
                "sbom_assets",
                {
                    "text": term,
                    "bom_ref": bom_ref,
                    "confidence": min(0.97, 0.90 + boost),
                },
            )

        # Remaining org technology terms not captured as SBOM assets, precomputed in __init__
        for term in self._remaining_terms:
            if term in seen_terms:
                continue
            span = _first_term_span(text, term)
            if span is None:
                continue
            seen_terms.add(term)
            boost = _context_boost(text, span[0], span[1])
            entities["software"].append(
                {"text": term, "confidence": min(0.95, 0.85 + boost)}
            )

        for actor in self._org_threat_actors:
            if actor not in seen_terms and _first_term_span(text, actor) is not None:
                seen_terms.add(actor)
                entities["threat_actors"].append({"text": actor, "confidence": 0.95})

        for sector in self._org_sectors:
            if sector not in seen_terms and _first_term_span(text, sector) is not None:
                seen_terms.add(sector)
                entities["sectors"].append({"text": sector, "confidence": 0.9})

        # geographies use word-boundary regex rather than plain find, so lowercase the full text once here
        text_lower = text.lower()
        for geo in self._org_geographies:
            if geo not in seen_terms and re.search(
                r"\b" + re.escape(geo) + r"\b", text_lower
            ):
                seen_terms.add(geo)
                entities["geographies"].append({"text": geo, "confidence": 0.9})

        return entities

    def _is_org_software_match(self, value_lower: str) -> bool:
        return _is_term_match(value_lower, self._all_tech_terms, 4)

    def _is_org_geography_match(self, value_lower: str) -> bool:
        return _is_term_match(value_lower, self._org_geographies, 4)

    def _is_org_threat_actor_match(self, value_lower: str) -> bool:
        return _is_term_match(value_lower, self._org_threat_actors, 3)

    def _extract_relevant_chunks(
        self, text: str, context_window: int = 200
    ) -> list[tuple[str, int]]:
        text_lower = text.lower()
        chunks: list[tuple[str, int]] = []
        seen_positions: list[int] = []  # sorted; bisect gives O(log n) overlap checks

        for term in self._sorted_extract_terms:  # precomputed, longest-first
            if len(term) < 4:
                break  # sorted descending, once too short, all remaining are too
            for match in re.finditer(r"\b" + re.escape(term) + r"\b", text_lower):
                pos = match.start()
                idx = bisect.bisect_left(seen_positions, pos)
                # skip positions already covered by an existing chunk to avoid feeding spaCy the same text twice
                too_close = (
                    idx > 0 and abs(seen_positions[idx - 1] - pos) < context_window
                ) or (
                    idx < len(seen_positions)
                    and abs(seen_positions[idx] - pos) < context_window
                )
                if too_close:
                    continue
                # 200-char window on each side gives spaCy enough sentence context to resolve entity types
                chunk_start = max(0, pos - context_window)
                chunk_end = min(len(text), pos + len(term) + context_window)
                chunks.append((text[chunk_start:chunk_end], chunk_start))
                bisect.insort(seen_positions, pos)

        logger.debug("Extracted %d relevant chunks from text", len(chunks))
        return chunks
