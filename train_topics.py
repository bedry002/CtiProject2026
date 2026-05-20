"""Fit a BERTopic model on MISP events and save it for use in the pipeline."""

import logging
import re
import sys
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
from stages.scoring import BusinessProfile, _sbom_score, _category_score
from pipeline.sbom import SBOMProfile

MODEL_PATH = pathlib.Path(__file__).parent / "models" / "bertopic_model"
CACHE_PATH = pathlib.Path(__file__).parent / "models" / "train_texts_cache.json"

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
        # Strip prefix like "mitre-attack:" -> keep the value after the colon
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
    save_cache: bool = True,
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
        page_size:  Events per paginated request (keep <=200 to avoid 504s).
        save_cache: If True, persist ids+texts to CACHE_PATH so calibration can
                    be re-run without re-fetching from MISP.
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
        # Threshold of 10 words filters out near-empty feed events (MalwareBazaar
        # sample submissions, IDS alerts, etc.) that only repeat source metadata.
        if len(text.split()) >= 10:
            ids.append(str(e.id))
            texts.append(text)
    logging.info(
        "Collected %d usable documents (skipped %d too-short)",
        len(texts), len(all_events) - len(texts),
    )

    if save_cache:
        CACHE_PATH.parent.mkdir(exist_ok=True)
        CACHE_PATH.write_text(
            json.dumps({"ids": ids, "texts": texts}, indent=None, ensure_ascii=False),
            encoding="utf-8",
        )
        logging.info("Training corpus cached to %s (%d docs)", CACHE_PATH, len(texts))

    return ids, texts


def load_cached_texts() -> tuple[list[str], list[str]] | None:
    """Load the cached training corpus, or return None if no cache exists."""
    if not CACHE_PATH.exists():
        return None
    data = json.loads(CACHE_PATH.read_text(encoding="utf-8"))
    ids = data.get("ids", [])
    texts = data.get("texts", [])
    logging.info("Loaded %d cached training documents from %s", len(texts), CACHE_PATH)
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
        min_df=2,                  # must appear in >=2 docs
        token_pattern=r"(?u)\b[a-zA-Z][a-zA-Z0-9_\-]{2,}\b",  # no pure-numeric tokens
    )

    # Fixed random seeds -> reproducible clusters across retrains.
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
# Event-driven relevance calibration
#
# Instead of matching the cluster's top words against profile keywords
# (which misses semantic associations like "ESXi ransomware" -> vmware component),
# we score every training document that belongs to a cluster and aggregate.
#
# Per-document scoring (mirrors ScoringStage weight hierarchy, IOC/topic excluded):
#   SBOM  50% — document mentions a known SBOM component
#   KW    35% — document matches a SBOM-derived compound threat phrase
#   Tech  15% — document mentions a technology term from the profile
#
# Cluster score formula:
#   mean_s   = mean of per-document scores across the cluster
#   coverage = fraction of cluster docs with any non-zero signal (score > 0.05)
#   raw      = mean_s * 0.60 + coverage * 0.40
#   relevance = clamp(raw, 0.1, 0.9) — floor=0.1 so unknown != irrelevant
#
# The old top-word `_auto_score` is retained as a fallback for clusters that
# have no document texts available (e.g. when calibrating against a new profile
# without the training corpus loaded).
# ---------------------------------------------------------------------------

def _score_doc_for_calibration(
    text: str,
    profile: BusinessProfile,
    sbom: SBOMProfile,
) -> float:
    """Score a single training document against the SBOM and business profile.

    Uses the same scoring primitives as ScoringStage so calibration scores are
    on the same scale as live event scores.  IOC, topic, and context signals are
    excluded because they are not available from plain text.
    """
    hay = text.lower()

    sbom_s, _ = _sbom_score(sbom, hay)

    if profile.specific_keywords:
        kw_s, _ = _category_score(
            [t.lower() for t in profile.specific_keywords], hay, saturation=0.006
        )
    else:
        kw_s = 0.0

    tech_s, _ = _category_score(
        [t.lower() for t in profile.technologies], hay, saturation=0.30
    )

    # Weights mirror ScoringStage (sbom + keyword + tech), renormalised to 1.0.
    return round(sbom_s * 0.50 + kw_s * 0.35 + tech_s * 0.15, 4)


def _cluster_score(
    docs: list[str],
    profile: BusinessProfile,
    sbom: SBOMProfile,
) -> tuple[float, float, float]:
    """Score a topic cluster from its member documents.

    Returns:
        relevance  — calibrated [0.1, 0.9] score for the relevance map
        mean_s     — mean per-document score (diagnostic)
        coverage   — fraction of cluster docs with any signal (diagnostic)
    """
    if not docs:
        return 0.1, 0.0, 0.0

    doc_scores = [_score_doc_for_calibration(t, profile, sbom) for t in docs]
    mean_s = sum(doc_scores) / len(doc_scores)
    coverage = sum(1 for s in doc_scores if s > 0.05) / len(doc_scores)

    raw = mean_s * 0.60 + coverage * 0.40
    relevance = round(max(0.1, min(0.9, raw)), 2)
    return relevance, round(mean_s, 4), round(coverage, 4)


def _auto_score(
    words: list[tuple[str, float]],
    profile: BusinessProfile,
    sbom: SBOMProfile,
) -> float:
    """Fallback: score a topic from its top c-TF-IDF words (no documents available).

    Less accurate than _cluster_score because SBOM component names rarely appear
    verbatim in topic word representations — but useful when training texts are
    not cached and calibration is re-run from a new profile only.
    """
    top_text = " ".join(w for w, _ in words[:8]).lower()

    if sbom.total_weight > 0:
        sbom_matched = sum(
            c.weight for c in sbom.components
            if any(t.lower() in top_text for t in c.match_terms())
        )
        sbom_score = min(1.0, sbom_matched / sbom.total_weight)
    else:
        sbom_score = 0.0

    kw_hits = sum(1 for kw in profile.keywords if kw.lower() in top_text)
    kw_score = min(1.0, kw_hits / 2)

    tech_hits = sum(1 for t in profile.technologies if t.lower() in top_text)
    tech_score = min(1.0, tech_hits / 2)

    combined = sbom_score * 0.40 + kw_score * 0.40 + tech_score * 0.20
    return round(max(0.1, combined), 1)


def build_relevance_map(
    model: BERTopic,
    profile: BusinessProfile,
    sbom: SBOMProfile,
    texts: list[str] | None = None,
) -> tuple[dict[str, float], dict[str, tuple[float, float, int]]]:
    """Generate a label -> score map for every non-outlier topic.

    When `texts` is provided (same list used to train the model, in the same
    order), each cluster is scored by aggregating its member documents rather
    than by matching top-word labels — giving a far more accurate picture of
    cluster relevance to the business profile.

    When `texts` is None (e.g. calibrating from a new profile against a
    previously saved model without the training corpus), falls back to the
    word-matching heuristic via `_auto_score`.

    Returns:
        relevance_map  — {label: score} written to topic_relevance_map.json
        cluster_stats  — {label: (mean_s, coverage, doc_count)} for display
    """
    # Group training texts by cluster assignment when available
    topic_texts: dict[int, list[str]] = {}
    if texts is not None and hasattr(model, "topics_") and model.topics_ is not None:
        for topic_id, text in zip(model.topics_, texts):
            if topic_id == -1:
                continue
            topic_texts.setdefault(topic_id, []).append(text)

    relevance_map: dict[str, float] = {}
    cluster_stats: dict[str, tuple[float, float, int]] = {}

    for topic_id, words in model.get_topics().items():
        if topic_id == -1:
            continue
        label = "_".join(w for w, _ in words[:3])
        cluster_docs = topic_texts.get(topic_id, [])

        if cluster_docs:
            relevance, mean_s, coverage = _cluster_score(cluster_docs, profile, sbom)
            cluster_stats[label] = (mean_s, coverage, len(cluster_docs))
        else:
            # Fallback — no documents available for this cluster
            relevance = _auto_score(words, profile, sbom)
            cluster_stats[label] = (0.0, 0.0, 0)

        relevance_map[label] = relevance

    return relevance_map, cluster_stats


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


def show_topics(
    model: BERTopic,
    relevance_map: dict[str, float],
    cluster_stats: dict[str, tuple[float, float, int]] | None = None,
) -> None:
    topics = {k: v for k, v in model.get_topics().items() if k != -1}
    outlier_count = sum(1 for t in model.topics_ if t == -1)
    total = len(model.topics_)

    print(f"\n--- Discovered Topics ({len(topics)} clusters, "
          f"{outlier_count}/{total} outliers {outlier_count/total*100:.1f}%) ---")
    print(f"    Scored against: {BUSINESS_PROFILE.name}")
    print(f"    SBOM components: {len(SBOM_PROFILE.components)}  "
          f"Keywords: {len(BUSINESS_PROFILE.keywords)}  "
          f"Technologies: {len(BUSINESS_PROFILE.technologies)}\n")

    calibration_mode = cluster_stats and any(
        n > 0 for _, _, n in cluster_stats.values()
    )
    if calibration_mode:
        print("    Calibration: event-driven (document scoring)\n")
        header = f"  {'Topic':>5}  {'Docs':>4}  {'Score':>5}  {'Mean':>5}  {'Cover':>5}  Label"
        print(header)
        print("  " + "-" * (len(header) - 2))
    else:
        print("    Calibration: word-match fallback (no document cache)\n")

    sort_key = lambda x: -relevance_map.get("_".join(w for w, _ in x[1][:3]), 0)
    for topic_id, words in sorted(topics.items(), key=sort_key):
        label = "_".join(w for w, _ in words[:3])
        score = relevance_map.get(label, 0.0)
        top_words = [(w, round(s, 3)) for w, s in words[:6]]
        doc_count = sum(1 for t in model.topics_ if t == topic_id)
        bar = "#" * int(score * 10)

        if calibration_mode and cluster_stats and label in cluster_stats:
            mean_s, coverage, _ = cluster_stats[label]
            print(f"  {topic_id:>5}  {doc_count:>4}  [{bar:<10}] {score:.2f}"
                  f"  mean={mean_s:.3f}  cov={coverage:.2f}  {label}")
        else:
            print(f"  {topic_id:>5} ({doc_count:>3} docs)  [{bar:<10}] {score:.1f}  {label}")

        print(f"           {top_words}")


def recalibrate() -> None:
    """Re-score an existing model using the cached training corpus.

    Useful when the SBOM or business profile changes — avoids re-fetching
    from MISP and re-training the model when only the scoring weights change.
    """
    if not MODEL_PATH.exists():
        logging.error("No model found at %s — run a full train first", MODEL_PATH)
        sys.exit(1)

    cached = load_cached_texts()
    if cached is None:
        logging.error(
            "No training corpus cache found at %s.\n"
            "Run a full train (without --recalibrate) to build it.",
            CACHE_PATH,
        )
        sys.exit(1)

    ids, texts = cached
    logging.info("Loading model from %s...", MODEL_PATH)
    model = BERTopic.load(str(MODEL_PATH))

    relevance_map, cluster_stats = build_relevance_map(
        model, BUSINESS_PROFILE, SBOM_PROFILE, texts=texts
    )
    show_topics(model, relevance_map, cluster_stats)

    map_path = MODEL_PATH.parent / "topic_relevance_map.json"
    map_path.write_text(
        json.dumps(relevance_map, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    logging.info(
        "Relevance map recalibrated -> %s (%d topics)", map_path, len(relevance_map)
    )


if __name__ == "__main__":
    # --recalibrate: re-score existing model from cached texts (no MISP fetch/retrain)
    if "--recalibrate" in sys.argv:
        recalibrate()
        sys.exit(0)

    ids, texts = fetch_texts()   # uses defaults: limit=500, date_from="2021-01-01"
    model = train(texts)
    relevance_map, cluster_stats = build_relevance_map(
        model, BUSINESS_PROFILE, SBOM_PROFILE, texts=texts
    )
    show_topics(model, relevance_map, cluster_stats)
    save(model, relevance_map)
