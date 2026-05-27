# CTI Curation Engine; Codebase Guide

> Audience: system administrators and developers responsible for operating, maintaining, or extending the engine.

---

## What the engine does

The engine connects to a MISP instance, pulls cyber threat intelligence (CTI) events, and runs each event through a pipeline of stages; NER, scoring, LLM enrichment and tagging then writes a relevance tag and an optional analyst summary back to MISP. It also produces an HTML report for quick debugging and evaluation.

---

## Directory layout

```
CtiProject2026/
├── main.py                  Entry point — polling loop
├── config.py                Central configuration — loads .env, profile, SBOM
├── form_api.py              FastAPI web endpoint for submitting org profiles
├── orchestrator.py          Legacy orchestrator (superseded by main.py)
│
├── pipeline/                Core framework — not org-specific
│   ├── base.py              Abstract Stage class
│   ├── runner.py            Pipeline — drives events through stages
│   ├── event.py             CurationEvent data model
│   ├── text.py              Event-to-text conversion helpers
│   ├── constants.py         Shared constants (confidence bands)
│   ├── sbom.py              SBOM parser and data model
│   ├── naics.py             NAICS sector code → sector terms
│   ├── nvd.py               NVD CPE→CVE enrichment with cache
│   └── attack.py            MITRE ATT&CK bundle loader and TTP scorer
│
├── stages/                  Pipeline stages — one file per stage
│   ├── ingest.py            Stage 1 — Fetch events from MISP
│   ├── ner.py               Stage 2 — Named Entity Recognition
│   ├── scoring.py           Stage 3 — Relevance scoring
│   ├── llm_enricher.py      Stage 4 — LLM analyst narrative
│   ├── tagger.py            Stage 5 — Write tags back to MISP
│   └── report.py            Stage 6 — Generate HTML report
│
├── Assets/                  Org profiles and SBOM files
│   ├── Test-bed Profile.json         Apex Retail (broad test profile)
│   ├── SBOM.json                     Apex Retail SBOM
│   ├── pixelbloom_creative.json      PixelBloom Creative profile
│   ├── pixelbloom_sbom.json
│   ├── nova_stream_logistics.json
│   ├── nova_stream_sbom.json
│   ├── omnimutual_insurance.json
│   ├── omnimutual_sbom.json
│   ├── vanguard_biopharma.json
│   └── vanguard_biopharma_sbom.json
│
├── data/                    Runtime data — created on first run
│   ├── poll_state.txt        Timestamp of last successful poll
│   ├── nvd_cache.json        NVD API response cache (7-day TTL)
│   ├── mitre_attack_cache.json   ATT&CK STIX bundle cache
│   └── mitre_actor_cache.json    Threat actor cache
│
├── reports/
│   └── curation_report.html  Latest HTML scoring report
│
├── tests/                   test suite
├── .env                     Local secrets and overrides 
├── .env.template            Safe template to share
└── requirements.txt
```

---

## How data flows

```
MISP instance
    │
    ▼
[1] MISPIngestStage         Fetch events since last poll. Skip bulk IOC feeds
    │                       (>200 attributes). Fetch remaining in parallel.
    │  list[CurationEvent]
    ▼
[2] NERStage                Extract CVEs, TTPs, threat actors, SBOM asset
    │                       mentions, geographies using regex + spaCy.
    │  entities populated
    ▼
[3] ScoringStage            Compute a [0,1] confidence score from:
    │                         stack  (SBOM hits + keyword hits + tech hits)
    │                         sector (sector term matches)
    │                         ttp    (MITRE ATT&CK TTP relevance)
    │                       Drop events below CONFIDENCE_THRESHOLD.
    │  confidence populated
    ▼
[4] LLMEnricherStage        For relevant events, call an OpenAI-compatible
    │                       endpoint to generate an analyst narrative.
    │                       Skipped when LLM_SKIP=true.
    │  analyst_summary populated
    ▼
[5] MISPTaggerStage         Write curation:relevance=<band> tag back to MISP.
    │                       Add score breakdown and analyst summary as MISP
    │                       attributes. Dry-run by default.
    ▼
[6] ReportStage             Render an HTML report of all scored events and
                            write it to reports/curation_report.html.
```

---

## Module reference

### `pipeline/event.py` — CurationEvent

The single data object that passes through every stage. Fields are added progressively:

| Field | Set by | Purpose |
|---|---|---|
| `misp_id` | Ingest | Numeric MISP event ID |
| `misp_uuid` | Ingest | MISP UUID — needed for tagging |
| `raw` | Ingest | Full MISP event dict |
| `entities` | NER | Dict of extracted entity lists (cves, ttps, sbom_assets, …) |
| `confidence` | Scoring | Composite relevance score [0, 1] |
| `matched_profile_terms` | Scoring | Profile terms that fired |
| `matched_sbom_components` | Scoring | SBOM bom_ref values that matched |
| `score_breakdown` | Scoring | Per-dimension scores |
| `ioc_summary` | Scoring | IOC type counts |
| `analyst_summary` | LLM | Analyst-facing narrative |
| `implicit_relevance_flags` | LLM | Flags for adjacent risks |

---

### `pipeline/base.py` — Stage

All stages inherit from `Stage`. To add a new stage:

```python
from pipeline.base import Stage
from pipeline.event import CurationEvent

class MyStage(Stage):
    @property
    def name(self) -> str:
        return "my_stage"

    def process(self, event: CurationEvent) -> CurationEvent:
        # modify event in place and return it
        return event
```

Then register it in `main.py` inside `build_pipeline()`.

---

### `pipeline/runner.py` — Pipeline

Calls `stage.process_batch(events)` for each stage in order. Tracks timing per stage. If `PIPELINE_CONTINUE_ON_STAGE_ERROR=true`, a failing stage falls back to processing events one by one and drops only the ones that error, rather than aborting the whole batch.

---

### `stages/ingest.py` — MISPIngestStage

Two-phase fetch:
1. Metadata-only search — retrieves lightweight event stubs with attribute counts.
2. Full fetch — only events with ≤200 attributes are fetched in full (10 concurrent connections via `ThreadPoolExecutor`).

The 200-attribute ceiling filters out automated bulk feeds (PhishTank, MalwareBazaar) that would overwhelm scoring with no real signal. Adjust `_MAX_ATTRIBUTE_COUNT` in the file if your feeds differ.

---

### `stages/ner.py` — NERStage

Runs two passes over each event's text:

**Pass 1 — Regex:** CVE IDs, MITRE TTP IDs (T1234.001), IP addresses, domains, hashes. These are pattern-matched globally across the full event text.

**Pass 2 — spaCy + term lookup:** Splits text into context windows around known inventory terms, then runs spaCy NER (`en_core_web_lg`) over those windows only, much faster than running spaCy over the entire text. Matches are cross-checked against the loaded org profile and SBOM to confirm they are organisation-relevant.

spaCy is optional. If the model is unavailable, the stage falls back to regex only. Set `SPACY_AUTO_DOWNLOAD=true` to auto-download the model on first run.

The org asset index (`OrgAssets`) is built once per unique (profile_path, sbom_path) pair and cached in a module-level dict — safe for multi-threaded use.

---

### `stages/scoring.py` — ScoringStage

Computes a composite score from three weighted dimensions:

| Dimension | Default weight | What it measures |
|---|---|---|
| `stack` | 0.50 | `min(1.0, sbom_score + keyword_score + tech_score)` |
| `sector` | 0.25 | Fraction of org sector terms appearing in event text |
| `ttp` | 0.25 | ATT&CK TTP relevance to org platforms (0 if ATTACK_ENABLED=false) |

**SBOM scoring:** Each SBOM component has a `weight` (1.0=high, 0.6=medium, 0.3=low). The raw score is `sum(matched weights) / total_weight`. CVE cross-reference (event CVEs matched against SBOM risk entries) can upgrade the SBOM score. NER-confirmed asset hits add a small boost (up to +0.20).

**Keyword scoring:** `specific_keywords` from the profile are matched at a very low saturation (0.006), meaning even a single keyword hit yields a meaningful contribution.

**Saturation:** Category scores use a saturation parameter — hitting `saturation` fraction of terms gives a score of 1.0. This prevents needing 100% term coverage to score well.

Events below `CONFIDENCE_THRESHOLD` are dropped and do not reach later stages.

---

### `stages/llm_enricher.py` — LLMEnricherStage

Calls any OpenAI-compatible chat completions endpoint. The prompt is constructed from:
- Org profile context (sectors, tech stack, threat actor watchlist)
- Event entities extracted by NER
- Scoring results (confidence, matched terms, SBOM hits)

The system prompt includes explicit prompt injection guards — any instructions inside `<cti_text>` tags are explicitly told to be ignored.

Retries up to 3 times with exponential backoff. On failure, the event passes through without a summary (non-fatal).

---

### `stages/tagger.py` — MISPTaggerStage

Writes back to MISP:
- `curation:relevance=<high|medium|low|not-relevant>` tag
- `tlp:white` and `feed:curated` tags (for relevant events)
- A `text` attribute with the confidence score and breakdown
- A `text` attribute with the analyst summary (if present)

Old `curation:` tags are removed before writing new ones — re-running is safe.

Set `TAGGER_DRY_RUN=true` (default) to log what would be written without touching MISP.

---

### `stages/report.py` — ReportStage

Renders a self-contained HTML file with a summary dashboard and a scored event table. Each row includes confidence bar, score breakdown, IOC sample, and threat context pills (actors, TTPs, CVEs, geographies). Written to `reports/curation_report.html` every run.

---

### `pipeline/sbom.py` — SBOM loader

Parses a CycloneDX-style JSON SBOM into `SBOMProfile` (list of `SBOMComponent` + list of `SBOMRisk`). Each component has:
- `bom_ref` — unique identifier
- `name`, `version`, `supplier`, `cpe`
- `criticality` → `weight` (high=1.0, medium=0.6, low=0.3)
- `aliases` — additional match terms

`match_terms()` produces the discriminating strings used for scoring (name, CPE product field, significant aliases). Overly generic terms (supplier names, version strings) are excluded to prevent false positives.

`inject_profile_cpes()` adds synthetic SBOM components for CPEs listed in the org profile but not found in the SBOM file — covering technology not discovered by Syft/Grype.

`enrich_with_nvd()` appends NVD-sourced CVEs to risk entries. Called at startup from `config.py` when `NVD_ENRICH=true`.

---

### `pipeline/nvd.py` — NVD enrichment

Queries the NVD REST API (`/rest/json/cves/2.0`) to retrieve CVEs for each SBOM component's CPE. Results are cached in `data/nvd_cache.json` with a 7-day TTL. Rate-limited to ~0.65 seconds per request (NVD free tier: 5 requests/30 s). Pass `NVD_API_KEY` for the 50 req/30 s limit.

**Known limitation:** NVD rejects wildcard version strings in CPEs (e.g. `1.24.*`). Use pinned versions in your SBOM or profile CPEs for enrichment to work.

---

### `pipeline/attack.py` — MITRE ATT&CK

Downloads the Enterprise ATT&CK STIX bundle on first run and caches it locally. Builds a lookup table of technique ID → `{name, tactics, platforms}`. At scoring time, each TTP extracted by NER is looked up; its platforms are intersected with the org's inferred platforms (derived from `technologies` in the profile). The TTP score reflects how many matched TTPs target the org's platform set.

Enable with `ATTACK_ENABLED=true`. The bundle download is ~50 MB and runs once.

---

### `pipeline/naics.py` — NAICS expansion

Maps 2-digit NAICS sector codes to human-readable sector terms used in scoring. Called from `config.py` to augment profile sectors with terms implied by the org's NAICS code.

---

### `config.py` — Central configuration

Reads `.env`, loads the org profile JSON and SBOM, constructs `BusinessProfile` and `SBOMProfile`, and exports all configuration constants consumed by `main.py`. Edit here to change profile paths, scoring settings, or to add new optional enrichments.

---

### `form_api.py` — Profile submission API

A small FastAPI app that serves `profile_form.html` and accepts profile JSON submissions, writing them directly to the profile file. Run separately with `uvicorn form_api:app`. Not required for pipeline operation.

---

## Configuration reference

All settings are read from environment variables (loaded from `.env`).

### MISP connection

| Variable | Default | Description |
|---|---|---|
| `MISP_URL` | — | MISP instance URL (required) |
| `MISP_KEY` / `MISP_API_KEY` | — | MISP automation key (required) |

### Org profile

| Variable | Default | Description |
|---|---|---|
| `ORG_PROFILE_PATH` | `Assets/Test-bed Profile.json` | Path to org profile JSON |
| `ORG_SBOM_PATH` | `Assets/SBOM.json` | Path to SBOM JSON |

### NER

| Variable | Default | Description |
|---|---|---|
| `SPACY_AUTO_DOWNLOAD` | `true` | Download spaCy model automatically if missing |
| `SPACY_BOOTSTRAP_MODEL` | `en_core_web_lg` | spaCy model to use |
| `NER_DOC_SCOPED_ONLY` | `false` | Limit NER to document-level scope only |
| `MITRE_ACTOR_CACHE_PATH` | `data/mitre_actor_cache.json` | Threat actor cache location |

### Scoring and pipeline

| Variable | Default | Description |
|---|---|---|
| `CONFIDENCE_THRESHOLD` | `0.20` | Events below this score are dropped |
| `PIPELINE_CONTINUE_ON_STAGE_ERROR` | `false` | Drop only failing events rather than aborting |

### Polling

| Variable | Default | Description |
|---|---|---|
| `POLL_INTERVAL_SECONDS` | `30` | Seconds between polls |
| `POLL_STATE_PATH` | `data/poll_state.txt` | Where last-seen timestamp is stored |
| `POLL_RUN_ONCE` | `false` | Exit after a single poll (useful for testing) |
| `POLL_LOOKBACK_HOURS` | `24` | How far back the very first run looks |
| `POLL_RESET_STATE` | `false` | Ignore saved timestamp and start fresh |

### Tagging

| Variable | Default | Description |
|---|---|---|
| `TAGGER_DRY_RUN` | `true` | Log what would be tagged without writing to MISP |

### LLM enricher

| Variable | Default | Description |
|---|---|---|
| `LLM_SKIP` | `false` | Disable LLM stage entirely |
| `LLM_API_URL` | OpenAI endpoint | Any OpenAI-compatible URL |
| `LLM_API_KEY` | — | Bearer token |
| `LLM_MODEL` | `gpt-4o-mini` | Model name |
| `LLM_TEMPERATURE` | `0.4` | Sampling temperature |
| `LLM_MAX_TOKENS` | `512` | Max response tokens |
| `LLM_TIMEOUT_SECONDS` | `30` | HTTP timeout |

### NVD enrichment

| Variable | Default | Description |
|---|---|---|
| `NVD_ENRICH` | `false` | Enable NVD CVE enrichment at startup |
| `NVD_API_KEY` | — | NVD API key (higher rate limit) |
| `NVD_CACHE_PATH` | `data/nvd_cache.json` | NVD response cache file |

### MITRE ATT&CK

| Variable | Default | Description |
|---|---|---|
| `ATTACK_ENABLED` | `false` | Enable ATT&CK TTP scoring |
| `ATTACK_BUNDLE_PATH` | `data/mitre_attack_cache.json` | Local cache for STIX bundle |
| `ATTACK_BUNDLE_URL` | GitHub mitre/cti | Source URL for the bundle |

---

## Confidence bands

Defined in `pipeline/constants.py` and used by both the tagger and the report:

| Band | Range | MISP tag |
|---|---|---|
| High | ≥ 0.50 | `curation:relevance=high` |
| Medium | 0.25 – 0.50 | `curation:relevance=medium` |
| Low | 0.10 – 0.25 | `curation:relevance=low` |
| Not relevant | < 0.10 | `curation:relevance=not-relevant` |

---

## Org profile format

```json
{
  "organisation": {
    "name": "Acme Corp",
    "naics_code": "5182"
  },
  "sectors": ["cloud hosting", "saas", "managed services"],
  "technologies": ["kubernetes", "aws", "nginx", "postgresql"],
  "geographies": ["london", "united kingdom"],
  "keywords": ["ransomware", "credential stuffing", "supply chain"],
  "threat_actors": ["lazarus group", "apt29"],
  "cpe_list": [
    "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
  ]
}
```

- `sectors`, `technologies`, `geographies` — used directly in scoring term matching
- `keywords` — treated as `specific_keywords` with very high scoring sensitivity
- `threat_actors` — used by NER to flag known actors in event text
- `cpe_list` — injected as synthetic SBOM components; used by NVD enrichment

---

## SBOM format

The engine expects a CycloneDX-inspired JSON structure. Minimum required shape per component:

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
        {"name": "criticality", "value": "high"},
        {"name": "match_alias", "value": "nginx proxy"}
      ]
    }
  ],
  "vulnerabilities": [
    {
      "id": "RISK-001",
      "description": "Known CVEs for nginx",
      "affects": [{"ref": "nginx-proxy"}],
      "ratings": [{"severity": "high"}],
      "properties": [
        {"name": "known_cve", "value": "CVE-2023-44487"}
      ]
    }
  ]
}
```

---

## Scaling considerations

### Vertical (more events per poll)

- Increase `_FETCH_WORKERS` in `stages/ingest.py` (default 10) to fetch more events in parallel. Match your MISP server's connection pool.
- Increase `_MAX_ATTRIBUTE_COUNT` if your narrative events legitimately have many attributes.
- NER is the bottleneck (spaCy model load + per-event processing). `NER_DOC_SCOPED_ONLY=true` skips global regex sweeps and only processes text near known inventory terms — significantly faster on large events.

### Horizontal (multiple org profiles)

The pipeline is stateless between polls. To run multiple profiles simultaneously, run separate processes each with a different `ORG_PROFILE_PATH`, `ORG_SBOM_PATH`, and `POLL_STATE_PATH`. Point each to the same MISP instance.

### LLM throughput

The LLM stage is synchronous and single-threaded. If volume is high, set `LLM_SKIP=true` and run the LLM stage as a separate post-processing step, or implement `process_batch()` in `LLMEnricherStage` to parallelise calls.

### Adding a new pipeline stage

1. Create `stages/my_stage.py` inheriting from `pipeline.base.Stage`.
2. Implement `name` (property) and `process(event)`.
3. Optionally override `process_batch(events)` for batch-aware logic (e.g. bulk API calls).
4. Add an instance to the `stages` list in `main.py:build_pipeline()` at the appropriate position.

No other files need to change.

---

## Running in production

```bash
# Install dependencies
pip install -r requirements.txt

# Copy and fill in the env file
cp .env.template .env

# First run — processes last 24 hours
python main.py

# Continuous mode (remove POLL_RUN_ONCE=true from .env)
python main.py
```

To run as a systemd service, set `POLL_RUN_ONCE=false` and `POLL_INTERVAL_SECONDS` to your desired cadence, then manage the process with systemd or a container orchestrator.

---

## Tests

```bash
pytest tests/ -v
```

Key test files:
- `test_scoring_integration.py` — end-to-end scoring with a synthetic event
- `test_ner_matching.py` — NER term matching behaviour
- `test_ner_profile_assets.py` — profile/SBOM asset loading
- `test_text_builder.py` — event-to-text conversion
- `test_runner_fault_mode.py` — pipeline fault isolation behaviour
- `test_llm_enricher.py` — LLM prompt construction and response parsing
