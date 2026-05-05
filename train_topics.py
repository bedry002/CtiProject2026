"""Fit a BERTopic model on MISP events and save it for use in the pipeline."""

import logging
import re
import urllib3
import pathlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

from bertopic import BERTopic
from sklearn.feature_extraction.text import CountVectorizer, ENGLISH_STOP_WORDS
from pymisp import PyMISP
from config import MISP_URL, MISP_KEY, MISP_VERIFYCERT
from stages.topics import _event_to_text

MODEL_PATH = pathlib.Path(__file__).parent / "models" / "bertopic_model"

# MISP-specific noise words merged with sklearn's English stopword list
_CUSTOM_STOP = {
    # TLP / classification markers
    "tlp", "white", "green", "amber", "red", "clear",
    # MISP feed and attribute type labels
    "threatfox", "urlhaus", "otx", "circl", "feed", "type", "ioc", "iocs",
    "botnet_cc", "malware_classification", "classification", "incident",
    "category", "osint", "alienvault",
    # Timestamps / years
    "2024", "2025", "2026", "2023", "2022", "2021", "2020", "2016", "2015",
    # URL fragments
    "http", "https", "www", "com", "org", "net", "html", "php",
    # Generic filler words not in sklearn defaults
    "also", "using", "used", "use", "via", "new", "known", "based",
    # MISP system / automation metadata fields
    "unknown", "event", "observation", "automation",
    "lifetime", "perpetual", "unsupervised", "supervised",
    "automation-level", "event-type", "event type",
    "payload", "payload_delivery", "payload delivery",
    # Network hosting noise (not informative as threat categories)
    "digitalocean", "digitalocean llc", "as45102",
}
_STOP_WORDS = list(_CUSTOM_STOP | set(ENGLISH_STOP_WORDS))

# MISP tag prefixes to exclude entirely when building training text
_TAG_NOISE = re.compile(
    r"^(tlp:|misp-galaxy:|admiralty-scale:|estimative-language:|"
    r"PAP:|ecsirt:|kill-chain:|course-of-action:)",
    re.IGNORECASE,
)


def _clean_tags(raw: dict) -> list[str]:
    """Return only informative tag name words, stripping taxonomy prefixes."""
    useful = []
    for tag in raw.get("Tag", []):
        name = tag.get("name", "")
        if _TAG_NOISE.match(name):
            continue
        # Strip prefix like "mitre-attack:" → keep the value after the colon
        if ":" in name:
            name = name.split(":", 1)[1]
        useful.append(name)
    return useful


def _build_training_text(raw: dict) -> str:
    """
    Extract only semantically meaningful text from a MISP event.
    Excludes raw IOC values (hashes, IPs) and feed metadata.
    """
    parts = [
        raw.get("info", ""),
        raw.get("description", ""),
        # Text/comment attributes only — not raw IOC values
        " ".join(
            a.get("value", "") for a in raw.get("Attribute", [])
            if a.get("type") in {"text", "comment", "vulnerability"}
        ),
        # Cleaned tags
        " ".join(_clean_tags(raw)),
        # Galaxy cluster names and descriptions (rich CTI context)
        " ".join(
            f"{gc.get('value', '')} {gc.get('description', '')}"
            for g in raw.get("Galaxy", [])
            for gc in g.get("GalaxyCluster", [])
        ),
    ]
    return " ".join(filter(None, parts)).strip()


def fetch_texts(limit: int = 500) -> tuple[list[str], list[str]]:
    logging.info("Fetching up to %d events from MISP...", limit)
    client = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    events = client.search(limit=limit, pythonify=True)
    ids, texts = [], []
    for e in events:
        text = _build_training_text(e.to_dict())
        # Skip documents that are too short to topic-model meaningfully
        if len(text.split()) >= 5:
            ids.append(str(e.id))
            texts.append(text)
    logging.info("Collected %d usable documents (skipped %d too-short)", len(texts), len(events) - len(texts))
    return ids, texts


def train(texts: list[str]) -> BERTopic:
    logging.info("Fitting BERTopic with cleaned corpus...")

    # Custom vectorizer: bigrams + merged stopwords + numeric token filter
    vectorizer = CountVectorizer(
        stop_words=_STOP_WORDS,
        ngram_range=(1, 2),        # capture "supply chain", "brute force", "remote access"
        min_df=2,                  # must appear in ≥2 docs
        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_\-]{2,}\b",  # no pure-numeric tokens
    )

    model = BERTopic(
        embedding_model="all-MiniLM-L6-v2",
        vectorizer_model=vectorizer,
        min_topic_size=5,     # require at least 5 docs per topic — avoids micro-clusters
        nr_topics="auto",
        verbose=True,
    )
    model.fit_transform(texts)
    return model


def save(model: BERTopic) -> None:
    MODEL_PATH.parent.mkdir(exist_ok=True)
    model.save(str(MODEL_PATH), serialization="pickle", save_ctfidf=True)
    logging.info("Model saved to %s", MODEL_PATH)


def show_topics(model: BERTopic) -> None:
    topics = {k: v for k, v in model.get_topics().items() if k != -1}
    outlier_count = sum(1 for t in model.topics_ if t == -1)

    print(f"\n--- Discovered Topics ({len(topics)} clusters, {outlier_count} outliers) ---")
    for topic_id, words in sorted(topics.items()):
        label = "_".join(w for w, _ in words[:3])
        scores = [(w, round(s, 3)) for w, s in words[:6]]
        print(f"  Topic {topic_id:>3}: [{label}]  {scores}")


if __name__ == "__main__":
    ids, texts = fetch_texts(limit=500)
    model = train(texts)
    show_topics(model)
    save(model)
