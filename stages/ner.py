"""Stage 2 — Named Entity Recognition over event text."""

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

logger = logging.getLogger(__name__)

# Configuration

MITRE_ACTOR_CACHE_PATH = os.environ.get("MITRE_ACTOR_CACHE_PATH", "data/mitre_actor_cache.json")
SPACY_AUTO_DOWNLOAD = os.environ.get("SPACY_AUTO_DOWNLOAD", "true").strip().lower() == "true"
SPACY_BOOTSTRAP_MODEL = os.environ.get("SPACY_BOOTSTRAP_MODEL", "en_core_web_lg")

_SPACY_FALLBACK_MODELS = ["en_core_web_lg", "en_core_web_md", "en_core_web_sm"]

# Pre-compiled patterns

CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
TTP_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?")
IOC_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IOC_DOMAIN = re.compile(
    r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|ru|cn|info|xyz|top)\b", re.IGNORECASE
)
IOC_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
IOC_HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
IOC_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")

SOFTWARE_VERSION_PATTERN = re.compile(r"\b(?:[A-Za-z][\w.+-]*\s+){0,3}[A-Za-z][\w.+-]*\s+(?:\d+(?:\.\d+){0,3}|[A-Z]{2,}\d{0,4})\b")
SOFTWARE_NOUN_PATTERN = re.compile(
    r"\b(?:server|client|agent|gateway|firewall|browser|plugin|library|framework|platform|suite"
    r"|hypervisor|directory|database|kernel|vpn|appliance"
    r"|firmware|driver|bootloader|bios|uefi|baseband"
    r"|router|switch|controller|balancer|proxy|middleware|runtime|container"
    r"|orchestrator|endpoint|waf)\b", 
    re.IGNORECASE,)
UPPERCASE_PRODUCT_PATTERN = re.compile(r"\b[A-Z]{2,}(?:\s+[A-Z0-9]{2,})*\b")
EXPLOIT_CONTEXT_PATTERN = re.compile(
    r"\b(?:vulnerabilit(?:y|ies)|exploit(?:ed|ing|ation|s)?|patch(?:ed|ing)?"
    r"|zero.?day|remote.?code.?execution|rce|arbitrary.?code"
    r"|privilege.?escalation|injection|buffer.?overflow|use.?after.?free)\b",
    re.IGNORECASE,)

# Lookup sets

KNOWN_ACTORS = {
    "fin7", "carbanak", "lazarus group", "apt38", "hidden cobra",
    "apt29", "cozy bear", "midnight blizzard", "apt28", "fancy bear",
    "forest blizzard", "apt41", "double dragon", "sandworm", "voodoo bear",
    "volt typhoon", "scattered spider", "unc3944", "wizard spider",
    "unc1878", "blackcat", "alphv", "hive", "lockbit", "vice society",
    "apt10", "stone panda", "apt40", "kimsuky", "dragonfly",
    "energetic bear", "hexane", "lyceum", "ta505", "ta407",
    "silent librarian", "revil", "darkside", "conti", "ryuk",
    "nobelium", "phosphorus", "charming kitten",
}

KNOWN_SECTORS = {
    "financial services", "banking", "finance", "healthcare", "health care",
    "education", "energy", "utilities", "government", "public sector",
    "manufacturing", "retail", "technology", "telecom", "defence",
    "defense", "transportation", "logistics", "pharmaceutical",
    "oil and gas", "critical infrastructure",
}

GENERIC_SOFTWARE_EXCLUSIONS = {
    "microsoft", "google", "amazon", "meta", "bank",
    "financial institutions", "insurance firms", "australia",
    "united states", "us", "it help desks", "bulletproof hosting providers",
    "government", "public sector",
}

COMMON_ACRONYM_EXCLUSIONS = {
    "it", "us", "uk", "eu", "un", "iot", "rdp", "smb", "dns",
    "http", "https", "ftp", "ssh", "tcp", "udp", "ip", "api",
    "sdk", "atm", "pos", "ids", "ips", "vlan", "wan", "lan",
    "pdf", "docx", "json", "xml", "html", "xss", "sql", "rce",
    "poc", "ttp", "apt", "cti", "ioc", "ioa", "mfa", "sso",
    "pii", "cve", "nvd", "cisa", "nist", "iso", "gdpr", "pci",
    "c2", "md5", "sha1", "sha256", "sha384", "sha512",
}

KNOWN_EXPLOITED_PRODUCTS = frozenset({
    "log4j", "log4shell",
    "openssl", "heartbleed",
    "exchange server", "exchange",
    "spring4shell", "springshell",
    "log4net",
    "apache struts", "struts",
    "citrix adc", "citrix gateway",
    "pulse secure",
    "fortinet", "fortigate", "fortios",
    "solarwinds",
    "kaseya",
    "vmware vcenter", "vcenter",
    "confluence", "jira",
    "jenkins",
    "apache httpd", "apache http server",
    "weblogic", "oracle weblogic",
    "coldfusion",
    "sharepoint",
    "ivanti",
    "MOVEit", "moveit",
    "barracuda",
})

# Module-level actor cache and lock for thread safety

_known_actors_lock = threading.Lock()

# Module-level flags for the functional extract_entities shim
_nlp = None
_nlp_unavailable = False
_bootstrap_attempted = False


def _refresh_known_actors() -> None:
    global KNOWN_ACTORS
    cache_path = Path(MITRE_ACTOR_CACHE_PATH)
    if not cache_path.exists():
        return
    try:
        cached = json.loads(cache_path.read_text(encoding="utf-8"))
        with _known_actors_lock:
            KNOWN_ACTORS = KNOWN_ACTORS | {a.lower() for a in cached if a}
        logger.info("mitre_actor_cache_loaded count=%d", len(cached))
    except Exception as exc:
        logger.error("mitre_actor_cache_read_failed: %s", exc)


_refresh_known_actors()

# MISP text assembly

_TEXT_FIELDS = ("info", "description")
_TEXT_ATTR_TYPES = {"text", "comment", "vulnerability"}


def _event_to_text(raw: dict[str, Any]) -> str:
    """Build a single text string from all relevant fields of a MISP event dict."""
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


def _looks_like_software_candidate(
    value: str,
    label: str,
    software_exclusions: frozenset = frozenset(GENERIC_SOFTWARE_EXCLUSIONS),
    known_sectors: frozenset = frozenset(KNOWN_SECTORS),
    acronym_exclusions: frozenset = frozenset(COMMON_ACRONYM_EXCLUSIONS),
) -> bool:
    cleaned = _clean_entity_text(value)
    if len(cleaned) < 2:
        return False
    lowered = cleaned.lower()
    if lowered in software_exclusions or lowered in known_sectors:
        return False
    if label == "PRODUCT":
        return True
    if SOFTWARE_VERSION_PATTERN.search(cleaned):
        return True
    if SOFTWARE_NOUN_PATTERN.search(cleaned):
        return True
    if any(c.isdigit() for c in cleaned) and any(c.isalpha() for c in cleaned):
        return True
    if UPPERCASE_PRODUCT_PATTERN.search(cleaned) and len(cleaned.split()) <= 4:
        tokens = cleaned.lower().split()
        if not any(t in acronym_exclusions for t in tokens):
            return True
    return False

# NERStage — Stage interface

class NERStage(Stage):
    """Extracts named entities from events text using spaCy + regex."""

    @property
    def name(self) -> str:
        return "ner"

    def __init__(
        self,
        actor_cache_path: Path | None = None,
        spacy_auto_download: bool = True,
        spacy_bootstrap_model: str = "en_core_web_lg",) -> None:
        self._actor_cache_path = actor_cache_path or Path(MITRE_ACTOR_CACHE_PATH)
        self._auto_download = spacy_auto_download
        self._bootstrap_model = spacy_bootstrap_model

        self._nlp_instance = None
        self._nlp_unavailable_flag = False
        self._bootstrap_attempted = False
        self._nlp_lock = threading.Lock()

        self._known_actors: set = set(KNOWN_ACTORS)
        self._known_sectors: frozenset = frozenset(KNOWN_SECTORS)
        self._acronym_exclusions: frozenset = frozenset(COMMON_ACRONYM_EXCLUSIONS)
        self._software_exclusions: frozenset = frozenset(GENERIC_SOFTWARE_EXCLUSIONS)

        self._load_actor_cache()

    # public helpers

    @property
    def nlp_unavailable(self) -> bool:
        return self._nlp_unavailable_flag

    def ensure_model(self) -> bool:
        return self._get_nlp() is not None

    def load_actor_cache(self, cache_path: Path | None = None) -> None:
        self._load_actor_cache(cache_path)

    # Stage entry point 

    def process(self, event: CurationEvent) -> CurationEvent:
        text = _event_to_text(event.raw)
        entities = self._regex_entities(text)

        try:
            nlp = self._get_nlp()
            if nlp is not None:
                doc = nlp(text[:5000])
                for ent in doc.ents:
                    label = ent.label_
                    value = _clean_entity_text(ent.text)
                    if not value or len(value) < 2:
                        continue
                    if label in ("ORG", "PRODUCT") and self._looks_like_software(value, label):
                        boost = _context_boost(text, ent.start_char, ent.end_char)
                        _append_unique(
                            entities,
                            "software",
                            {"text": value, "confidence": min(0.95, 0.75 + boost)},
                        )
                    elif label == "GPE":
                        _append_unique(
                            entities,
                            "geographies",
                            {"text": value, "confidence": 0.8},
                        )
        except Exception as exc:
            logger.warning("spacy_ner_failed: %s", exc)

        # Only malware and geographies are not pre-initialised by _regex_entities
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
                    "spacy_import_failed %s: %s — falling back to regex only",
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

    def _load_actor_cache(self, cache_path: Path | None = None) -> None:
        path = cache_path or self._actor_cache_path
        if not path.exists():
            return
        try:
            cached = json.loads(path.read_text(encoding="utf-8"))
            self._known_actors.update(a.lower() for a in cached if a)
            logger.info("mitre_actor_cache_loaded count=%d", len(cached))
        except Exception as exc:
            logger.error("mitre_actor_cache_read_failed: %s", exc)

    def _regex_entities(self, text: str) -> dict:
        entities: dict = {
            "cves": [], "ttps": [], "iocs": [],
            "threat_actors": [], "sectors": [], "software": [],
        }
        seen: set = set()

        for match in CVE_PATTERN.finditer(text):
            value = match.group().upper()
            if value not in seen:
                seen.add(value)
                entities["cves"].append({"text": value, "confidence": 1.0})

        for match in TTP_PATTERN.finditer(text):
            value = match.group().upper()
            if value not in seen:
                seen.add(value)
                entities["ttps"].append({"text": value, "confidence": 0.95})

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

        for match in IOC_IP.finditer(text):
            value = match.group()
            if not _is_private_ip(value) and value not in seen:
                seen.add(value)
                entities["iocs"].append({"text": value, "type": "ipv4", "confidence": 0.9})

        for match in IOC_DOMAIN.finditer(text):
            value = match.group().lower()
            if value not in seen:
                seen.add(value)
                entities["iocs"].append({"text": value, "type": "domain", "confidence": 0.85})

        text_lower = text.lower()
        for actor in self._known_actors:
            if actor in text_lower and actor not in seen:
                seen.add(actor)
                entities["threat_actors"].append({"text": actor, "confidence": 0.9})

        for sector in self._known_sectors:
            if sector in text_lower and sector not in seen:
                seen.add(sector)
                entities["sectors"].append({"text": sector, "confidence": 0.85})

        for product in KNOWN_EXPLOITED_PRODUCTS:
            key = product.lower()
            if key in text_lower and key not in seen:
                seen.add(key)
                idx = text_lower.index(key)
                boost = _context_boost(text, idx, idx + len(key))
                entities["software"].append(
                    {"text": product, "confidence": min(0.95, 0.85 + boost)}
                )

        return entities

    def _looks_like_software(self, value: str, label: str) -> bool:
        cleaned = _clean_entity_text(value)
        if len(cleaned) < 2:
            return False
        lowered = cleaned.lower()
        if lowered in self._software_exclusions or lowered in self._known_sectors:
            return False
        if label == "PRODUCT":
            return True
        if SOFTWARE_VERSION_PATTERN.search(cleaned):
            return True
        if SOFTWARE_NOUN_PATTERN.search(cleaned):
            return True
        if any(c.isdigit() for c in cleaned) and any(c.isalpha() for c in cleaned):
            return True
        if UPPERCASE_PRODUCT_PATTERN.search(cleaned) and len(cleaned.split()) <= 4:
            tokens = cleaned.lower().split()
            if not any(t in self._acronym_exclusions for t in tokens):
                return True
        return False
