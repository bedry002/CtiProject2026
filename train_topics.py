"""Fit a BERTopic model on MISP events and save it for use in the pipeline."""

import logging
import pickle
import urllib3
import pathlib

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

from bertopic import BERTopic
from pymisp import PyMISP
from config import MISP_URL, MISP_KEY, MISP_VERIFYCERT
from stages.topics import _event_to_text

MODEL_PATH = pathlib.Path(__file__).parent / "models" / "bertopic_model"


def fetch_texts(limit: int = 500) -> tuple[list[str], list[str]]:
    logging.info("Fetching up to %d events from MISP...", limit)
    client = PyMISP(MISP_URL, MISP_KEY, MISP_VERIFYCERT)
    events = client.search(limit=limit, pythonify=True)
    ids, texts = [], []
    for e in events:
        text = _event_to_text(e.to_dict()).strip()
        if text:
            ids.append(str(e.id))
            texts.append(text)
    logging.info("Collected %d documents for training", len(texts))
    return ids, texts


def train(texts: list[str]) -> BERTopic:
    logging.info("Fitting BERTopic (this may take a minute)...")
    model = BERTopic(
        embedding_model="all-MiniLM-L6-v2",
        min_topic_size=3,       # small corpus — lower threshold so topics form
        nr_topics="auto",       # merge similar topics automatically
        verbose=True,
    )
    model.fit_transform(texts)
    return model


def save(model: BERTopic) -> None:
    MODEL_PATH.parent.mkdir(exist_ok=True)
    model.save(str(MODEL_PATH), serialization="pickle", save_ctfidf=True)
    logging.info("Model saved to %s", MODEL_PATH)


def show_topics(model: BERTopic) -> None:
    print("\n--- Discovered Topics ---")
    for topic_id, words in model.get_topics().items():
        if topic_id == -1:
            continue
        label = "_".join(w for w, _ in words[:4])
        print(f"  Topic {topic_id:>3}: {label}")
        print(f"           {[w for w, _ in words[:8]]}")


if __name__ == "__main__":
    ids, texts = fetch_texts(limit=500)
    model = train(texts)
    show_topics(model)
    save(model)
