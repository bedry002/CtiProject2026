"""Fit a BERTopic model on MISP events and save it for use in the pipeline."""

import logging
import re
import urllib3
import pathlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

import json

from bertopic import BERTopic
from umap import UMAP
from hdbscan import HDBSCAN
from sklearn.feature_extraction.text import CountVectorizer, ENGLISH_STOP_WORDS
from pymisp import PyMISP
from config import MISP_URL, MISP_KEY, MISP_VERIFYCERT, BUSINESS_PROFILE, SBOM_PROFILE
from stages.topics import _event_to_text
from stages.scoring import BusinessProfile
from pipeline.sbom import SBOMProfile

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
    # Feed source names — these dominate topic vocabulary without adding signal
    "malwarebazaar", "maltrail", "krvtz", "krvtz-net",
    "samples", "sample",
    # Taxonomy metadata values that survive tag prefix stripping
    "source-type", "manual-collection", "medium-risk", "threat-level",
    "high-risk", "low-risk", "ids", "alerts",
    # Estimative-language taxonomy values
    "certainty", "likelihood", "probability", "confidence",
    # Tag type/taxonomy artefacts
    "malware-type", "malware type",
    # MITRE ATT&CK Galaxy description boilerplate
    # (prose like "Adversaries may... Citation: [ref]" is identical across events)
    "citation", "adversaries", "mitre", "techniques", "technique",
    "group", "groups", "actor", "actors",
}
_STOP_WORDS = list(_CUSTOM_STOP | set(ENGLISH_STOP_WORDS))

# MISP tag prefixes to exclude entirely when building training text
_TAG_NOISE = re.compile(
    r"^(tlp:|misp-galaxy:|admiralty-scale:|estimative-language:|"
    r"PAP:|ecsirt:|kill-chain:|course-of-action:|incident-classification:|"
    r"source-type:|threat-level:|maltrail:|ids:|feed:|mitre-attack:)",
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
        # Galaxy cluster names only — descriptions contain standardised MITRE
        # prose ("Adversaries may... Citation: ...") that dominates topic vocabulary
        # without adding distinguishing signal. Names/values carry the real CTI
        # content: threat actor names, technique IDs, malware family names.
        " ".join(
            gc.get("value", "")
            for g in raw.get("Galaxy", [])
            for gc in g.get("GalaxyCluster", [])
        ),
    ]
    return " ".join(filter(None, parts)).strip()


def fetch_texts(
    limit: int = 500,
    date_from: str = "2021-01-01",
    page_size: int = 200,
) -> tuple[list[str], list[str]]:
    """Fetch training documents from MISP using pagination to avoid gateway timeouts.

    Targets only events that contain text/comment/vulnerability attributes so that
    pure IOC feed events (hashes, IPs, domains) are excluded server-side — avoiding
    the need to pull the full event corpus, which can be several GB on active MISP
    instances.

    Args:
        limit:      Maximum total number of events to fetch.
        date_from:  Only include events published on or after this date.
                    Keeps the corpus focused on the current threat landscape.
                    Set to None to include all historical events.
        page_size:  Events per paginated request (keep ≤200 to avoid 504s).
    """
    client = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)

    # Fetch three passes — text, comment, vulnerability — then deduplicate.
    # MISP's type_attribute filter returns events that contain *at least one*
    # attribute of the given type, which eliminates pure-IOC feed events entirely
    # at the query level without pulling the full corpus.
    target_types = ["text", "comment", "vulnerability"]

    seen_ids: set[str] = set()
    all_events = []

    for attr_type in target_types:
        if len(all_events) >= limit:
            break

        logging.info(
            "Fetching events with type_attribute=%s (from %s, page_size=%d)...",
            attr_type, date_from or "all", page_size,
        )

        page = 1
        while len(all_events) < limit:
            batch_limit = min(page_size, limit - len(all_events))
            params: dict = {
                "limit": batch_limit,
                "page": page,
                "type_attribute": attr_type,
                "pythonify": True,
            }
            if date_from:
                params["date_from"] = date_from

            batch = client.search(**params)
            if not batch:
                break

            new = [e for e in batch if str(e.id) not in seen_ids]
            for e in new:
                seen_ids.add(str(e.id))
            all_events.extend(new)

            logging.info(
                "  [%s] page %d: %d returned, %d new (total: %d)",
                attr_type, page, len(batch), len(new), len(all_events),
            )

            if len(batch) < batch_limit:
                break  # Last page for this type
            page += 1

    logging.info("Fetched %d unique events total", len(all_events))

    ids, texts = [], []
    for e in all_events:
        text = _build_training_text(e.to_dict())
        # Skip documents that are too short to topic-model meaningfully.
        # Threshold of 20 words filters out near-empty feed events (MalwareBazaar
        # sample submissions, IDS alerts, etc.) that only repeat source metadata.
        if len(text.split()) >= 10:
            ids.append(str(e.id))
            texts.append(text)
    logging.info(
        "Collected %d usable documents (skipped %d too-short)",
        len(texts), len(all_events) - len(texts),
    )
    return ids, texts


def train(texts: list[str]) -> BERTopic:
    logging.info("Fitting BERTopic on %d documents...", len(texts))

    # Scale min_topic_size with corpus — avoids micro-clusters at larger scale
    min_topic_size = max(5, len(texts) // 150)
    logging.info("min_topic_size=%d (corpus=%d)", min_topic_size, len(texts))

    # Custom vectorizer: bigrams + merged stopwords + numeric token filter
    vectorizer = CountVectorizer(
        stop_words=_STOP_WORDS,
        ngram_range=(1, 2),        # capture "supply chain", "brute force", "remote access"
        min_df=2,                  # must appear in ≥2 docs
        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_\-]{2,}\b",  # no pure-numeric tokens
    )

    # Fixed random seeds → reproducible clusters across retrains.
    # Without this, UMAP's stochastic initialisation produces different cluster
    # counts on identical data (e.g. 3 topics one run, 5 the next).
    umap_model = UMAP(
        n_components=5,
        n_neighbors=15,
        min_dist=0.0,
        metric="cosine",
        random_state=42,
    )
    hdbscan_model = HDBSCAN(
        min_cluster_size=min_topic_size,
        metric="euclidean",
        cluster_selection_method="eom",
        prediction_data=True,
    )

    model = BERTopic(
        embedding_model="all-MiniLM-L6-v2",
        umap_model=umap_model,
        hdbscan_model=hdbscan_model,
        vectorizer_model=vectorizer,
        min_topic_size=min_topic_size,
        nr_topics=25,   # cap topic count — prevents fragmentation at larger corpus sizes
        verbose=True,
    )
    model.fit_transform(texts)
    return model


# ---------------------------------------------------------------------------
# Profile-driven relevance scoring
#
# Topic relevance is derived entirely from the BusinessProfile and
# SBOMProfile already used by ScoringStage — no separate signal dict
# to maintain.  Update your profile JSON or SBOM and relevance scores
# will automatically reflect those changes on the next retrain.
#
# Scoring logic (mirrors ScoringStage weight hierarchy):
#   SBOM  40% — topic mentions a known asset component (most precise)
#   KW    40% — topic mentions a threat keyword from the profile
#   Tech  20% — topic mentions a technology term from the profile
#
# Saturation: SBOM saturates at total_weight, KW at 3 hits, Tech at 2 hits.
# Topics with no signal at all default to 0.1 (unknown ≠ irrelevant).
# ---------------------------------------------------------------------------

def _auto_score(
    words: list[tuple[str, float]],
    profile: BusinessProfile,
    sbom: SBOMProfile,
) -> float:
    """Score a topic by matching its top words against the profile and SBOM."""
    top_text = " ".join(w for w, _ in words[:8]).lower()

    # SBOM — weighted match against asset inventory
    if sbom.total_weight > 0:
        sbom_matched = sum(
            c.weight for c in sbom.components
            if any(t.lower() in top_text for t in c.match_terms())
        )
        sbom_score = min(1.0, sbom_matched / sbom.total_weight)
    else:
        sbom_score = 0.0

    # Keywords — threat types the profile cares about (saturates at 2 hits)
    kw_hits = sum(1 for kw in profile.keywords if kw.lower() in top_text)
    kw_score = min(1.0, kw_hits / 2)

    # Technologies — known tech stack terms (saturates at 2 hits)
    tech_hits = sum(1 for t in profile.technologies if t.lower() in top_text)
    tech_score = min(1.0, tech_hits / 2)

    combined = (
        sbom_score * 0.40 +
        kw_score   * 0.40 +
        tech_score * 0.20
    )

    # Floor of 0.1 — unknown topics may still carry threat context
    return round(max(0.1, combined), 1)


def build_relevance_map(
    model: BERTopic,
    profile: BusinessProfile,
    sbom: SBOMProfile,
) -> dict[str, float]:
    """Generate a label → score map for every non-outlier topic."""
    relevance_map: dict[str, float] = {}
    for topic_id, words in model.get_topics().items():
        if topic_id == -1:
            continue
        label = "_".join(w for w, _ in words[:3])
        relevance_map[label] = _auto_score(words, profile, sbom)
    return relevance_map


def save(model: BERTopic, relevance_map: dict[str, float]) -> None:
    MODEL_PATH.parent.mkdir(exist_ok=True)
    model.save(str(MODEL_PATH), serialization="pickle", save_ctfidf=True)
    logging.info("Model saved to %s", MODEL_PATH)

    map_path = MODEL_PATH.parent / "topic_relevance_map.json"
    map_path.write_text(
        __import__("json").dumps(relevance_map, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logging.info("Relevance map saved to %s (%d topics)", map_path, len(relevance_map))


def show_topics(model: BERTopic, relevance_map: dict[str, float]) -> None:
    topics = {k: v for k, v in model.get_topics().items() if k != -1}
    outlier_count = sum(1 for t in model.topics_ if t == -1)
    total = len(model.topics_)

    print(f"\n--- Discovered Topics ({len(topics)} clusters, "
          f"{outlier_count}/{total} outliers {outlier_count/total*100:.1f}%) ---")
    print(f"    Scored against: {BUSINESS_PROFILE.name}")
    print(f"    SBOM components: {len(SBOM_PROFILE.components)}  "
          f"Keywords: {len(BUSINESS_PROFILE.keywords)}  "
          f"Technologies: {len(BUSINESS_PROFILE.technologies)}\n")

    for topic_id, words in sorted(topics.items(), key=lambda x: -relevance_map.get("_".join(w for w, _ in x[1][:3]), 0)):
        label = "_".join(w for w, _ in words[:3])
        score = relevance_map.get(label, 0.0)
        top_words = [(w, round(s, 3)) for w, s in words[:6]]
        doc_count = sum(1 for t in model.topics_ if t == topic_id)
        bar = "#" * int(score * 10)
        print(f"  Topic {topic_id:>3} ({doc_count:>3} docs)  [{bar:<10}] {score:.1f}  {label}")
        print(f"           {top_words}")


if __name__ == "__main__":
    ids, texts = fetch_texts()   # uses defaults: limit=2500, date_from="2021-01-01"
    model = train(texts)
    relevance_map = build_relevance_map(model, BUSINESS_PROFILE, SBOM_PROFILE)
    show_topics(model, relevance_map)
    save(model, relevance_map)
