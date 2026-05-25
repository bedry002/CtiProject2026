"""
evaluate.py — the analytical core for Options A (silver labels) and C (synthetic).

Three sub-commands:

  assert-synthetic   Run the construct-by-design set through the scorer and check each event
                     lands in its expected band. Prints a pass/fail table + the substring-trap
                     audit. This is your fast regression harness (no LLM, no MISP).

  sweep              Given a scored corpus + gold labels, sweep CONFIDENCE_THRESHOLD and report
                     precision / recall / F1 / accuracy at each step + the best-F1 threshold and
                     a PR curve (CSV). This produces your scope's ">=80% relevance accuracy" number.

  kappa              Given two (or more) annotators' label columns, compute Cohen's / Fleiss'
                     kappa so the silver set's reliability is itself measured and reportable.

SCORING MODES
  --use-pipeline   import your real ScoringStage (run on the testbed; exact production scores)
  (default)        use the embedded faithful reimplementation of scoring.py + sbom.py, so this
                   script runs ANYWHERE for development. The embedded scorer also supports
                   --word-boundary to demonstrate the substring-fix before/after experiment.

Examples:
  python evaluate.py assert-synthetic --corpus synthetic_corpus.jsonl --labels synthetic_labels.csv \\
         --sbom SBOM.json --profile "Test-bed Profile.json"
  python evaluate.py assert-synthetic ... --word-boundary      # show the fix
  python evaluate.py sweep --scored corpus.scored.jsonl --labels silver_labels.csv
  python evaluate.py kappa --labels silver_labels.csv --cols annotator_a annotator_b
"""

from __future__ import annotations

import argparse
import csv
import json
import pathlib
import re
from collections import Counter
from dataclasses import dataclass, field

# ======================================================================================
# Embedded faithful reimplementation of your scoring (mirrors scoring.py + sbom.py).
# Kept deliberately close to the originals so dev-mode numbers track production closely.
# ======================================================================================

_STRIP = re.compile(r"[_\-]")
_CRITICALITY_WEIGHT = {"high": 1.0, "medium": 0.6, "low": 0.3}
_DEFAULT_WEIGHT = 0.4
_THREAT_VERBS = (
    "exploit", "vulnerability", "cve", "attack", "compromise", "brute force",
    "privilege escalation", "remote code execution", "backdoor", "malware",
    "ransomware", "rce", "bypass",
)


def parse_cpe_product(cpe: str) -> str | None:
    parts = cpe.split(":")
    if len(parts) >= 5:
        product = _STRIP.sub(" ", parts[4]).lower().strip()
        return product if product and product != "*" else None
    return None


@dataclass
class Comp:
    bom_ref: str
    name: str
    supplier: str
    cpe: str | None
    weight: float
    aliases: list[str] = field(default_factory=list)

    def match_terms(self) -> list[str]:
        seen: set[str] = set()
        terms: list[str] = []

        def add(t: str) -> None:
            t = t.lower().strip()
            if t and t not in seen:
                seen.add(t)
                terms.append(t)

        add(self.name)
        if self.cpe:
            p = parse_cpe_product(self.cpe)
            if p:
                add(p)
        words = self.name.split()
        if len(words) >= 2:
            first = words[0].lower()
            if len(first) >= 7 and first != (self.supplier or "").lower():
                add(first)
        for a in self.aliases:
            add(a)
        return terms


@dataclass
class Sbom:
    components: list[Comp]
    risks: list[dict]  # {affected_refs, known_cves}
    total_weight: float = 0.0

    def __post_init__(self):
        self.total_weight = sum(c.weight for c in self.components)

    def threat_phrases(self) -> list[str]:
        seen: set[str] = set()
        phrases: list[str] = []
        for c in self.components:
            for term in c.match_terms()[:2]:
                if len(term) < 4:
                    continue
                for verb in _THREAT_VERBS:
                    p = f"{term} {verb}"
                    if p not in seen:
                        seen.add(p)
                        phrases.append(p)
        return phrases


def load_sbom(path: pathlib.Path) -> Sbom:
    data = json.loads(path.read_text(encoding="utf-8"))
    comps = []
    for raw in data.get("components", []):
        props = {p["name"]: p["value"] for p in raw.get("properties", [])}
        crit = props.get("criticality", "unknown")
        aliases = [p["value"] for p in raw.get("properties", []) if p.get("name") == "match_alias"]
        comps.append(Comp(
            bom_ref=raw.get("bom-ref", ""), name=raw.get("name", ""),
            supplier=raw.get("supplier", {}).get("name", ""), cpe=raw.get("cpe"),
            weight=_CRITICALITY_WEIGHT.get(crit, _DEFAULT_WEIGHT), aliases=aliases,
        ))
    risks = []
    for raw in data.get("vulnerabilities", []):
        risks.append({
            "affected_refs": [a.get("ref", "") for a in raw.get("affects", [])],
            "known_cves": [c.upper() for c in raw.get("known_cves", [])],
        })
    return Sbom(comps, risks)


def load_profile_fields(path: pathlib.Path) -> dict:
    """Mirror config._load_business_profile: read TOP-LEVEL keys (as the live code does)."""
    p = json.loads(path.read_text(encoding="utf-8"))
    return {
        "sectors":      [s.lower() for s in p.get("sectors", [])],
        "technologies": [t.lower() for t in p.get("technologies", [])],
        "geographies":  [g.lower() for g in p.get("geographies", [])],
        "keywords":     [k.lower() for k in p.get("keywords", [])],
    }


_TEXT_FIELDS = ("info", "description")
_TEXT_ATTR_TYPES = frozenset({"text", "comment", "vulnerability"})


def event_to_text(raw: dict) -> str:
    parts = []
    for f in _TEXT_FIELDS:
        parts.append(raw.get(f, ""))
    for a in raw.get("Attribute", []):
        if a.get("type") in _TEXT_ATTR_TYPES:
            parts.append(a.get("value", ""))
    for t in raw.get("Tag", []):
        parts.append(t.get("name", ""))
    return " ".join(p for p in parts if p)


def _contains(term: str, haystack: str, word_boundary: bool) -> bool:
    if word_boundary:
        return re.search(r"\b" + re.escape(term) + r"\b", haystack) is not None
    return term in haystack


def _category_score(terms, haystack, saturation, wb) -> tuple[float, list[str]]:
    if not terms:
        return 0.0, []
    matched = [t for t in terms if _contains(t.lower(), haystack, wb)]
    return round(min(1.0, len(matched) / len(terms) / saturation), 4), matched


@dataclass
class Weights:
    asset: float = 0.30
    technology: float = 0.30
    sector: float = 0.30
    geography: float = 0.10


def score_event(raw: dict, sbom: Sbom, prof: dict, specific_keywords: list[str],
                wb: bool = False, w: Weights = Weights()) -> dict:
    """Faithful port of ScoringStage.process (asset + tech + sector + geo)."""
    hay = event_to_text(raw).lower()

    # SBOM component text match
    matched_weight, sbom_refs = 0.0, []
    for c in sbom.components:
        if any(_contains(t, hay, wb) for t in c.match_terms()):
            matched_weight += c.weight
            sbom_refs.append(c.bom_ref)
    sbom_s = round(matched_weight / sbom.total_weight, 4) if sbom.total_weight else 0.0

    # CVE cross-reference
    event_cves = {a["value"].upper() for a in raw.get("Attribute", [])
                  if a.get("type") == "vulnerability"}
    cve_s, cve_refs = 0.0, []
    if event_cves and sbom.total_weight:
        cw = {c.bom_ref: c.weight for c in sbom.components}
        mw = 0.0
        for r in sbom.risks:
            if event_cves & set(r["known_cves"]):
                for ref in r["affected_refs"]:
                    if ref not in cve_refs:
                        cve_refs.append(ref)
                        mw += cw.get(ref, 0.0)
        cve_s = round(min(1.0, mw / sbom.total_weight), 4)
        if cve_refs:
            ref_set = set(dict.fromkeys(sbom_refs + cve_refs))
            mw2 = sum(c.weight for c in sbom.components if c.bom_ref in ref_set)
            sbom_s = round(min(1.0, mw2 / sbom.total_weight), 4)
            sbom_refs = list(ref_set)

    kw_s, kw_matched = (_category_score(specific_keywords, hay, 0.006, wb)
                        if specific_keywords else (0.0, []))
    asset_s = min(1.0, sbom_s + kw_s)

    tech_s, tech_m = _category_score(prof["technologies"], hay, 0.30, wb)
    sector_s, sec_m = _category_score(prof["sectors"], hay, 0.50, wb)
    geo_s, geo_m = _category_score(prof["geographies"], hay, 0.50, wb)

    confidence = round(asset_s * w.asset + tech_s * w.technology
                       + sector_s * w.sector + geo_s * w.geography, 4)
    return {
        "confidence": confidence,
        "breakdown": {"asset": asset_s, "sbom_cve": cve_s, "tech": tech_s,
                      "sector": sector_s, "geography": geo_s},
        "matched_sbom_components": sbom_refs,
        "matched_profile_terms": kw_matched + tech_m + sec_m + geo_m,
    }


_BANDS = [(0.50, "HIGH"), (0.25, "MEDIUM"), (0.10, "LOW")]


def band(conf: float) -> str:
    for thr, label in _BANDS:
        if conf >= thr:
            return label
    return "BELOW"


# ======================================================================================
# Sub-command: assert-synthetic
# ======================================================================================

def cmd_assert_synthetic(args):
    sbom = load_sbom(args.sbom)
    prof = load_profile_fields(args.profile)
    specific_keywords = prof["keywords"] + sbom.threat_phrases()

    labels = {}
    with open(args.labels, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            labels[row["synthetic_id"]] = row

    corpus = {}
    with open(args.corpus, encoding="utf-8") as f:
        for line in f:
            o = json.loads(line)
            corpus[o["synthetic_id"]] = o["raw"]

    threshold = args.threshold
    rows, passes = [], 0
    band_order = {"BELOW": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}
    for sid, meta in labels.items():
        raw = corpus[sid]
        res = score_event(raw, sbom, prof, specific_keywords, wb=args.word_boundary)
        got = band(res["confidence"])
        exp = meta["expect_band"]
        expect_miss = meta["expect_miss"] == "1"
        gold_relevant = meta["gold_label"] == "relevant"
        pred_relevant = res["confidence"] >= threshold

        if expect_miss:
            # HP_OBLIQUE: scorer is EXPECTED to miss; "pass" = it correctly under-scores
            # (this case exists to motivate the LLM stage, not to test the scorer)
            ok = not pred_relevant
            verdict = "miss-as-expected" if ok else "unexpectedly-caught"
        else:
            ok = (pred_relevant == gold_relevant)
            verdict = "PASS" if ok else "FAIL"
        passes += int(ok)
        rows.append((sid, meta["klass"], exp, got, f"{res['confidence']:.4f}",
                     verdict, ",".join(res["matched_profile_terms"][:4])))

    print(f"\n{'='*92}")
    print(f"SYNTHETIC BAND ASSERTION  (threshold={threshold}, word_boundary={args.word_boundary})")
    print(f"{'='*92}")
    print(f"{'ID':8}{'class':12}{'exp':8}{'got':8}{'score':9}{'verdict':20}matched")
    print("-" * 92)
    for r in rows:
        print(f"{r[0]:8}{r[1]:12}{r[2]:8}{r[3]:8}{r[4]:9}{r[5]:20}{r[6]}")
    print("-" * 92)
    print(f"{passes}/{len(rows)} cases behaved as expected")

    # Substring-trap audit specifically
    traps = [r for r in rows if r[1] == "HN_SUBSTR"]
    fired = [r for r in traps if r[3] != "BELOW"]
    print(f"\nSubstring-trap audit: {len(traps)-len(fired)}/{len(traps)} traps correctly scored BELOW.")
    if fired:
        print("  FALSE POSITIVES from substring matching (would be FIXED by --word-boundary):")
        for r in fired:
            print(f"    {r[0]} ({r[6]}) scored {r[4]} -> band {r[3]}")


# ======================================================================================
# Sub-command: sweep  (precision / recall / F1 vs threshold)
# ======================================================================================

def _prf(tp, fp, fn, tn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    acc = (tp + tn) / (tp + fp + fn + tn) if (tp + fp + fn + tn) else 0.0
    return prec, rec, f1, acc


def cmd_sweep(args):
    # scored corpus: needs confidence + a way to join to gold labels by id
    scored = {}
    with open(args.scored, encoding="utf-8") as f:
        for line in f:
            o = json.loads(line)
            key = str(o.get("misp_id") or o.get("synthetic_id"))
            scored[key] = float(o["confidence"]) if o.get("confidence") is not None else 0.0

    gold = {}
    with open(args.labels, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            key = str(row.get("misp_id") or row.get("synthetic_id"))
            val = (row.get("gold_label") or "").strip().lower()
            if val in ("relevant", "1", "yes", "true"):
                gold[key] = 1
            elif val in ("not_relevant", "not-relevant", "0", "no", "false", "irrelevant"):
                gold[key] = 0

    keys = [k for k in gold if k in scored]
    if not keys:
        raise SystemExit("No overlap between scored corpus and gold labels (check id columns).")
    print(f"Evaluating on {len(keys)} labelled events "
          f"({sum(gold[k] for k in keys)} relevant / {len(keys)-sum(gold[k] for k in keys)} not).")

    steps = [round(0.02 * i, 2) for i in range(0, 51)]  # 0.00 .. 1.00
    best = (0.0, -1.0)  # (threshold, f1)
    pr_rows = []
    print(f"\n{'thr':>6}{'TP':>5}{'FP':>5}{'FN':>5}{'TN':>5}{'prec':>8}{'recall':>8}{'F1':>8}{'acc':>8}")
    for thr in steps:
        tp = fp = fn = tn = 0
        for k in keys:
            pred = 1 if scored[k] >= thr else 0
            g = gold[k]
            tp += pred and g
            fp += pred and not g
            fn += (not pred) and g
            tn += (not pred) and not g
        prec, rec, f1, acc = _prf(tp, fp, fn, tn)
        pr_rows.append((thr, prec, rec, f1, acc))
        if f1 > best[1]:
            best = (thr, f1)
        if abs((thr * 100) % 10) < 1e-6:  # print every 0.10 to keep it readable
            print(f"{thr:>6.2f}{tp:>5}{fp:>5}{fn:>5}{tn:>5}{prec:>8.3f}{rec:>8.3f}{f1:>8.3f}{acc:>8.3f}")

    print(f"\nBest F1 = {best[1]:.3f} at threshold = {best[0]:.2f}")
    # find threshold meeting the scope's >=80% accuracy criterion
    meeting = [(t, a) for (t, p, r, f, a) in pr_rows if a >= 0.80]
    if meeting:
        print(f"Scope criterion (>=80% accuracy) met at thresholds: "
              f"{meeting[0][0]:.2f}..{meeting[-1][0]:.2f} (max acc {max(a for _, a in meeting):.3f})")
    else:
        print("Scope criterion (>=80% accuracy) NOT met at any threshold on this labelled set.")

    if args.pr_out:
        with open(args.pr_out, "w", newline="", encoding="utf-8") as f:
            wr = csv.writer(f)
            wr.writerow(["threshold", "precision", "recall", "f1", "accuracy"])
            wr.writerows(pr_rows)
        print(f"PR curve written -> {args.pr_out}")


# ======================================================================================
# Sub-command: kappa  (inter-annotator agreement)
# ======================================================================================

def _to_bin(v: str) -> int | None:
    v = (v or "").strip().lower()
    if v in ("relevant", "1", "yes", "true"):
        return 1
    if v in ("not_relevant", "not-relevant", "0", "no", "false", "irrelevant"):
        return 0
    return None


def cmd_kappa(args):
    rows = list(csv.DictReader(open(args.labels, encoding="utf-8")))
    cols = args.cols
    # collect items where all annotators labelled
    data = []
    for row in rows:
        vals = [_to_bin(row.get(c, "")) for c in cols]
        if all(v is not None for v in vals):
            data.append(vals)
    n = len(data)
    if n == 0:
        raise SystemExit("No fully-labelled rows across the given columns.")

    if len(cols) == 2:
        a = [d[0] for d in data]
        b = [d[1] for d in data]
        po = sum(1 for x, y in zip(a, b) if x == y) / n
        # expected agreement
        pa1 = sum(a) / n; pb1 = sum(b) / n
        pe = pa1 * pb1 + (1 - pa1) * (1 - pb1)
        kappa = (po - pe) / (1 - pe) if (1 - pe) else 1.0
        print(f"Cohen's kappa ({cols[0]} vs {cols[1]}) on {n} items: {kappa:.3f}")
        print(f"  observed agreement = {po:.3f}, expected = {pe:.3f}")
        disagree = sum(1 for x, y in zip(a, b) if x != y)
        print(f"  disagreements: {disagree} (adjudicate these before computing final metrics)")
    else:
        # Fleiss' kappa for >2 raters, 2 categories
        N = n; k = 2
        P_sum = 0.0
        cat_tot = [0, 0]
        for vals in data:
            counts = [vals.count(0), vals.count(1)]
            r = len(vals)
            cat_tot[0] += counts[0]; cat_tot[1] += counts[1]
            P_i = (sum(c * c for c in counts) - r) / (r * (r - 1)) if r > 1 else 1.0
            P_sum += P_i
        Pbar = P_sum / N
        total = cat_tot[0] + cat_tot[1]
        pj = [c / total for c in cat_tot]
        Pe = sum(p * p for p in pj)
        kappa = (Pbar - Pe) / (1 - Pe) if (1 - Pe) else 1.0
        print(f"Fleiss' kappa ({len(cols)} raters) on {N} items: {kappa:.3f}")
        print(f"  mean observed agreement = {Pbar:.3f}, expected = {Pe:.3f}")

    print("\nInterpretation (Landis & Koch): <0 poor, 0-.20 slight, .21-.40 fair, "
          ".41-.60 moderate, .61-.80 substantial, .81-1 almost perfect.")


def main():
    ap = argparse.ArgumentParser(description="CTI curation benchmark evaluator")
    sub = ap.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("assert-synthetic")
    a.add_argument("--corpus", required=True, type=pathlib.Path)
    a.add_argument("--labels", required=True, type=pathlib.Path)
    a.add_argument("--sbom", required=True, type=pathlib.Path)
    a.add_argument("--profile", required=True, type=pathlib.Path)
    a.add_argument("--threshold", type=float, default=0.20)
    a.add_argument("--word-boundary", action="store_true",
                   help="use \\b word-boundary matching (the substring-fix experiment)")
    a.set_defaults(func=cmd_assert_synthetic)

    s = sub.add_parser("sweep")
    s.add_argument("--scored", required=True, type=pathlib.Path)
    s.add_argument("--labels", required=True, type=pathlib.Path)
    s.add_argument("--pr-out", type=pathlib.Path, default=None)
    s.set_defaults(func=cmd_sweep)

    k = sub.add_parser("kappa")
    k.add_argument("--labels", required=True, type=pathlib.Path)
    k.add_argument("--cols", nargs="+", required=True)
    k.set_defaults(func=cmd_kappa)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
