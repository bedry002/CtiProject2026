# CTI Curation Engine

An automated cyber threat intelligence (CTI) curation pipeline that connects to a MISP instance, scores incoming events for relevance against your organisation's profile and software inventory, and writes structured relevance tags back to MISP.

---

## What it does

1. **Polls MISP** on a configurable interval and fetches new events, skipping bulk IOC feed dumps automatically.
2. **Extracts entities** — CVEs, MITRE ATT&CK TTPs, threat actors, SBOM asset mentions, geographies — using regex and spaCy NER.
3. **Scores each event** against your organisation's technology stack, sector, and (optionally) ATT&CK platform coverage. Events below a confidence threshold are discarded.
4. **Optionally calls an LLM** (any OpenAI-compatible endpoint) to generate a short analyst narrative for relevant events.
5. **Tags events in MISP** with `curation:relevance=high/medium/low/not-relevant` and writes the score breakdown as a MISP attribute.
6. **Produces an HTML report** at `reports/curation_report.html` after every poll.

---

## Requirements

- Docker and Docker Compose
- A running MISP instance with API access
- (Optional) An OpenAI-compatible LLM endpoint for analyst summaries, or [Ollama](https://ollama.com) for local inference

---

## Installation

```bash
git clone https://github.com/bedry002/CtiProject2026.git
cd CtiProject2026
```

---

## Quick start

### 1. Configure your environment

```bash
cp .env.template .env
```

Open `.env` and fill in at minimum:

```env
MISP_URL=https://your-misp-instance
MISP_API_KEY=your_misp_automation_key
ORG_PROFILE_PATH=Assets/your_profile.json
ORG_SBOM_PATH=Assets/your_sbom.json
```

### 2. Build and start the form and tunnel

```bash
sudo docker compose up --build api
```

This builds the image on first run — installing all dependencies and cloudflared. Once built, the container starts automatically, launching the profile form API and opening a public Cloudflare tunnel. The tunnel URL is printed in the terminal — share it to access the form.

### 3. Run the pipeline

```bash
./run_pipeline.sh
```

Run this whenever you want to process new MISP events. The HTML report is written to `reports/curation_report.html` after each run.

> **Subsequent starts:** Once the image is built, just run `sudo docker compose up api` — no `--build` needed unless code or dependencies change.

---

## Profile format

The org profile tells the engine what your organisation looks like so it can judge whether a threat event is relevant.

```json
{
  "organisation": {
    "name": "Acme Corp",
    "naics_code": "5182"
  },
  "sectors": [
    "cloud hosting", "saas", "managed services"
  ],
  "technologies": [
    "kubernetes", "aws", "nginx", "postgresql", "ubuntu"
  ],
  "geographies": [
    "london", "united kingdom", "uk"
  ],
  "keywords": [
    "ransomware", "credential stuffing", "supply chain attack"
  ],
  "threat_actors": [
    "lazarus group", "apt29", "scattered spider"
  ],
  "cpe_list": [
    "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
    "cpe:2.3:a:postgresql:postgresql:15.0:*:*:*:*:*:*:*"
  ]
}
```

| Field | Purpose |
|---|---|
| `sectors` | Industry sector terms matched against event text |
| `technologies` | Specific products/platforms in use |
| `geographies` | Regions of operation |
| `keywords` | High-signal threat phrases — even a single match scores well |
| `threat_actors` | Tracked adversaries flagged by NER |
| `cpe_list` | CPE identifiers for NVD CVE enrichment and SBOM injection |

---

## SBOM format

The engine reads a CycloneDX-inspired JSON SBOM to match specific software components against events. Matching is based on component name, CPE product field, and configured aliases.

```json
{
  "components": [
    {
      "bom-ref": "nginx-proxy",
      "name": "nginx",
      "version": "1.24.0",
      "supplier": "nginx",
      "cpe": "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*",
      "properties": [
        { "name": "criticality", "value": "high" },
        { "name": "match_alias", "value": "nginx proxy" }
      ]
    }
  ],
  "vulnerabilities": [
    {
      "id": "CVE-RISK-001",
      "description": "nginx known CVEs",
      "affects": [{ "ref": "nginx-proxy" }],
      "ratings": [{ "severity": "high" }],
      "properties": [
        { "name": "known_cve", "value": "CVE-2023-44487" }
      ]
    }
  ]
}
```

Component criticality (`high`, `medium`, `low`) controls how much weight a match contributes to the final score.

---

## Providing your SBOM

The engine reads a CycloneDX-format SBOM from `Assets/SBOM.json` (or whatever path is set in the `ORG_SBOM_PATH` environment variable). There are three ways to get one into the engine.

### Option 1 — Upload through the web page (recommended)

Once the form API is running (`docker compose up api`), open the SBOM upload page in a browser: http://localhost:8000/sbom.

Drag one or more CycloneDX JSON files onto the page and click **Upload & Merge**. The page accepts multiple files in a single upload and shows the loaded SBOM's component count, criticality breakdown, and the source files that contributed to it. A **Clear SBOM** button resets the file when you want to start fresh.

When more than one file is uploaded (in one go or over multiple uploads), they are merged into `Assets/SBOM.json`:

- Components are deduplicated by `(name, version, cpe)`.
- Vulnerabilities are deduplicated by `id`.
- Each component is tagged with a `source_file` property so it is clear which upload contributed it.
- Components without an explicit `criticality` are assigned one automatically based on CycloneDX `type` (e.g. `operating-system` → high, `library` → medium).

The engine picks up the new SBOM the next time it starts. Restart the pipeline container to apply.

### Option 2 — Drop the file in directly

Place your CycloneDX JSON at `Assets/SBOM.json` (or any path you prefer) and set `ORG_SBOM_PATH` in `.env` accordingly. No upload needed.

### Option 3 — Validate before uploading

A CLI validator is provided to check an SBOM file for the fields the scoring engine relies on:

```bash
python validate_sbom.py path/to/your-sbom.json
```

It reports:
- Components missing a `cpe` (CVE matching will not work for these).
- Components missing a `criticality` rating (will be auto-assigned at upload time, but flagging is useful to know).
- Components with no `name` (blocking — these will be rejected at upload).

Run this against a candidate SBOM before uploading to confirm it will give you full scoring coverage.

## Scoring explained

Each event receives a confidence score between 0 and 1, computed from four weighted dimensions:

| Dimension | Default weight | What it measures |
|---|---|---|
| Asset | 30% | Matches against components in the organisation's SBOM (by name, CPE, alias). Saturates at one high-criticality match or roughly two medium-criticality matches. |
| Technology | 30% | Matches against the organisation's broader technology stack from the profile (products, platforms, frameworks named outside the SBOM). |
| Sector | 30% | How many of the organisation's declared sector terms appear in the event text. |
| Geography | 10% | Whether the event's geographic context overlaps the organisation's regions of operation. |

Where an event references a CVE that affects a component in the SBOM, the engine additionally applies a confidence floor (see `SCORING_CVE_MATCH_FLOOR` in the configuration reference) so confirmed-exposure events are guaranteed to clear the high-relevance band regardless of how the other three dimensions score.

Events are then banded:

| Band | Score | MISP tag |
|---|---|---|
| High | ≥ 0.50 | `curation:relevance=high` |
| Medium | 0.25 – 0.50 | `curation:relevance=medium` |
| Low | 0.10 – 0.25 | `curation:relevance=low` |
| Not relevant | < threshold | dropped / `curation:relevance=not-relevant` |

The default drop threshold is `0.20`. Adjust with `CONFIDENCE_THRESHOLD` in `.env`. Set to `0.0` to tag every event including not-relevant ones rather than dropping them.

---

## Configuration reference

All settings are read from `.env`. A full template with descriptions is in `.env.template`.

### Essential

```env
MISP_URL=https://your-misp-instance
MISP_API_KEY=your_api_key
ORG_PROFILE_PATH=Assets/your_profile.json
ORG_SBOM_PATH=Assets/your_sbom.json
```

### Tuning

```env
CONFIDENCE_THRESHOLD=0.20
POLL_LOOKBACK_HOURS=24
POLL_INTERVAL_SECONDS=30
POLL_RUN_ONCE=true
POLL_RESET_STATE=false
TAGGER_DRY_RUN=true
LLM_SKIP=true
```

### Scoring

```env
SCORING_CVE_MATCH_FLOOR=0.50
```

When an event references a CVE that matches a documented risk in your SBOM, the engine guarantees the event clears at least this confidence band — preventing the strongest possible relevance signal (a confirmed flaw in your own software) from being diluted across the weighted average. Set to `0.0` to disable the floor and fall back to pure weighted-average scoring. The default of `0.50` puts confirmed-exposure events in the HIGH band.

### LLM enrichment (optional)

```env
LLM_SKIP=false
LLM_API_URL=https://api.openai.com/v1/chat/completions
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4o-mini
```

For Groq:
```env
LLM_API_URL=https://api.groq.com/openai/v1/chat/completions
LLM_API_KEY=your_groq_api_key
LLM_MODEL=llama-3.3-70b-versatile
LLM_JSON_MODE=true
LLM_TIMEOUT_SECONDS=30
```

For local Ollama:
```env
LLM_API_URL=http://host.docker.internal:11434/v1/chat/completions
LLM_API_KEY=ollama
LLM_MODEL=llama3.2:1b
LLM_JSON_MODE=false
LLM_TIMEOUT_SECONDS=300
```

> **Linux hosts:** `host.docker.internal` requires `extra_hosts: ["host.docker.internal:host-gateway"]` in `docker-compose.yml` (already included), and Ollama must be configured with `OLLAMA_HOST=0.0.0.0`.

### NVD CVE enrichment (optional)

```env
NVD_ENRICH=true
NVD_API_KEY=your_nvd_key
```

### MITRE ATT&CK TTP scoring (optional)

```env
ATTACK_ENABLED=true
```

---

## Evaluation and testing

The engine ships with a labelled evaluation corpus and an offline harness for measuring scoring accuracy against the project's relevance target without needing a live MISP instance.

### Run the engine against the evaluation corpus

```bash
python eval/run_offline.py --sbom "Assets/SBOM.json" --threshold 0.20
```

This loads the labelled corpus from `eval/synthetic_corpus.jsonl`, runs the real NER and scoring stages over each event, and prints a per-event table with score, band, CVE-floor activation, and whether the event would be dropped at the chosen threshold. An HTML report is written to `reports/offline_demo_report.html`.

### Compute accuracy across thresholds

```bash
python eval/score_corpus.py
python evaluate.py sweep --scored eval/corpus.scored.jsonl --labels eval/synthetic_labels.csv
```

The first command scores the whole corpus into a JSONL file. The second sweeps across candidate confidence thresholds and prints precision, recall, F1, and accuracy at each, plus the band of thresholds at which the project's ≥80% accuracy target is met.

### The corpus

`eval/synthetic_corpus.jsonl` contains 25 labelled events designed to exercise the engine across six categories:

- Five obviously-relevant retail-sector threats
- Four obviously-irrelevant events from unrelated sectors (water treatment, maritime, agriculture, automotive)
- Five substring-trap events where a profile term appears only as part of an unrelated word (e.g. "Dockers" in a port story)
- Five oblique events that are genuinely relevant but written without profile-term overlap — these probe the LLM enrichment stage rather than the deterministic scorer
- Five events referencing real CVEs that match components in the testbed SBOM
- One out-of-stack CVE control event (a Cisco IOS XE flaw — software not in the testbed inventory) that verifies the CVE floor does not promote events whose CVEs miss the SBOM

`eval/synthetic_labels.csv` contains the gold-truth label for each event and which behavioural class it falls under.

### Unit and regression tests

```bash
python -m pytest tests/ -q
```

The suite includes regression tests that guard the CVE-to-SBOM floor (`test_cve_match_floor.py`), the accuracy target on the corpus (`test_accuracy_regression.py`), and the LLM-stage safety controls (`test_security_guards.py`).


## Running via Docker

### First run

```bash
sudo docker compose up --build api
```

### Subsequent starts

```bash
sudo docker compose up api
```

### Run the pipeline

```bash
./run_pipeline.sh
```

### Override environment variables for a single run

```bash
docker compose run --rm -e POLL_RESET_STATE=true -e CONFIDENCE_THRESHOLD=0.0 pipeline
```

### Viewing the report

```bash
# Linux headless server
cd reports && python3 -m http.server 8080
# browse to http://<server-ip>:8080/curation_report.html
```

### Scheduling weekly runs (cron)

```bash
crontab -e
```

---

## Testbed-only tooling (`tools/`)

The `tools/` directory contains scripts that are specific to the project's development testbed and are **not** part of the runtime engine.

- `tools/orchestrator.py` — generates an enriched SBOM by polling a Dependency-Track instance running on the testbed network, deduplicating components across containers, and writing the result to `Assets/SBOM.json`. This is a convenience for the testbed only — in any production deployment, the organisation provides their own SBOM via the `/sbom` upload page or by dropping a file at `Assets/SBOM.json`.
- `tools/config/targets.json` — the orchestrator's list of containers to scan and Dependency-Track project UUIDs. Testbed-specific.

The engine does not import from `tools/`. Removing the directory does not affect engine operation.
