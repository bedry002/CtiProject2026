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

# Your organisation profile and SBOM
ORG_PROFILE_PATH=Assets/your_profile.json
ORG_SBOM_PATH=Assets/your_sbom.json
```

### 2. Create your organisation profile

Create a JSON file describing your organisation (see [Profile format](#profile-format) below). Several example profiles are included in `Assets/`.

### 3. Build the image

```bash
docker compose build pipeline
```

This installs all Python dependencies and downloads the spaCy `en_core_web_lg` model — only needed once, or after code changes.

### 4. Run

```bash
# One-shot mode — set POLL_RUN_ONCE=true in .env, then:
docker compose run --rm pipeline
```

The HTML report is written to `reports/curation_report.html` on the host after each run.

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

## Scoring explained

Each event receives a confidence score between 0 and 1, computed from three weighted dimensions:

| Dimension | Default weight | What it measures |
|---|---|---|
| Stack | 50% | SBOM component mentions + keyword hits + technology matches |
| Sector | 25% | How many of your sector terms appear in the event |
| TTP | 25% | ATT&CK techniques in the event that target your platform set |

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
CONFIDENCE_THRESHOLD=0.20      # Drop events below this score
POLL_LOOKBACK_HOURS=24         # How far back the first run looks
POLL_INTERVAL_SECONDS=30       # Seconds between polls
POLL_RUN_ONCE=true             # Process one batch and exit
POLL_RESET_STATE=false         # Set true to ignore saved timestamp and start fresh
TAGGER_DRY_RUN=true            # Set false to actually write tags to MISP
LLM_SKIP=true                  # Set false to enable LLM analyst summaries
```

### LLM enrichment (optional)

The LLM stage works with any OpenAI-compatible endpoint — OpenAI, Groq, Ollama, Azure OpenAI, etc.

```env
LLM_SKIP=false
LLM_API_URL=https://api.openai.com/v1/chat/completions
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4o-mini
```

For Groq (recommended for speed — no local resources required):
```env
LLM_API_URL=https://api.groq.com/openai/v1/chat/completions
LLM_API_KEY=your_groq_api_key
LLM_MODEL=llama-3.3-70b-versatile
LLM_JSON_MODE=true
LLM_TIMEOUT_SECONDS=30
```

For local Ollama (install separately on host — see [ollama.com](https://ollama.com)):
```env
LLM_API_URL=http://host.docker.internal:11434/v1/chat/completions
LLM_API_KEY=ollama
LLM_MODEL=llama3.2:1b
LLM_JSON_MODE=false
LLM_TIMEOUT_SECONDS=300
```

> **Linux hosts:** `host.docker.internal` requires `extra_hosts: ["host.docker.internal:host-gateway"]` in `docker-compose.yml` (already included), and Ollama must be configured with `OLLAMA_HOST=0.0.0.0` to accept connections from the container.

### NVD CVE enrichment (optional)

Enriches SBOM components with CVEs from the NVD API at startup.

```env
NVD_ENRICH=true
NVD_API_KEY=your_nvd_key       # Get a free key at nvd.nist.gov for higher rate limits
```

> **Note:** CPEs in the SBOM must use pinned version numbers (e.g. `1.24.0`) not wildcards (`1.24.*`) for the NVD API to accept them.

### MITRE ATT&CK TTP scoring (optional)

```env
ATTACK_ENABLED=true
# Bundle downloaded once (~50 MB) and cached at ATTACK_BUNDLE_PATH
```

---

## Running via Docker

### Build

```bash
docker compose build pipeline
```

Rebuild whenever `requirements.txt` or the codebase changes.

### One-shot run

```bash
docker compose run --rm pipeline
```

`--rm` removes the container after it exits — only the named volume (`pipeline_data`, holding poll state) persists between runs.

### Override environment variables for a single run

```bash
docker compose run --rm -e POLL_RESET_STATE=true -e CONFIDENCE_THRESHOLD=0.0 pipeline
```

### Viewing the report

The report is written to `./reports/curation_report.html` on the host via a bind mount.

```bash
# Windows
start reports\curation_report.html

# Linux desktop
xdg-open reports/curation_report.html

# Linux headless server — serve it temporarily
cd reports && python3 -m http.server 8080
# then browse to http://<server-ip>:8080/curation_report.html
```

### Scheduling weekly runs (cron)

```bash
crontab -e
```

```
0 8 * * 1 cd /path/to/CtiProject2026 && docker compose run --rm pipeline >> cron.log 2>&1
```

Ensure `POLL_RESET_STATE=false` in `.env` so each run only processes events since the last poll.

---

## What gets written to MISP

When `TAGGER_DRY_RUN=false`, the engine writes:

| What | Where in MISP |
|---|---|
| Relevance tag | Event tag: `curation:relevance=high/medium/low/not-relevant` |
| TLP tag | Event tag: `tlp:white` (relevant events only) |
| Feed tag | Event tag: `feed:curated` (relevant events only) |
| Score breakdown | Event attribute (type: text, category: External analysis) |
| Analyst summary | Event attribute (type: text, category: External analysis) |

The engine cleans up old `curation:` tags before writing new ones, so re-running is safe.

---

## Adding a custom stage

```python
from pipeline.base import Stage
from pipeline.event import CurationEvent

class SlackNotifierStage(Stage):
    @property
    def name(self) -> str:
        return "slack_notifier"

    def process(self, event: CurationEvent) -> CurationEvent:
        if (event.confidence or 0) >= 0.50:
            # post to Slack
            pass
        return event
```

Register it in `main.py:build_pipeline()` after the scoring stage, then rebuild:

```bash
docker compose build pipeline
```

---

## Troubleshooting

**No events surfacing (score 0.0 for everything)**
- Check your profile has meaningful `sectors`, `technologies`, and `keywords`. Empty arrays score nothing.
- Look at what events are actually in your MISP feed — IDS/network observation events with only IP addresses will never match a profile.
- Run with `-e POLL_LOOKBACK_HOURS=500 -e POLL_RESET_STATE=true` to cast a wider net and see if older events score better.

**Events scoring lower than expected**
- The `ttp` dimension (25% weight) is 0 unless `ATTACK_ENABLED=true`.
- Check your SBOM component terms — very generic component names like `server` are excluded to prevent false positives.
- Broaden `keywords` in your profile to cover common threat categories relevant to your sector.

**NVD warnings at startup**
- CPEs with wildcard versions (`1.24.*`) are rejected by the NVD API. Use pinned versions in your SBOM/profile CPEs.

**LLM connection refused / timed out**
- Ollama: confirm it's running (`ollama list`) and bound to `0.0.0.0` not just `127.0.0.1`.
- Local CPU inference can take 1-5 minutes per event — increase `LLM_TIMEOUT_SECONDS` or switch to Groq for faster, resource-free inference.

**MISP authentication failed (403)**
- Generate a fresh API key in MISP under **Administration → List Users → your user → Auth keys**.

**MISP tags not being written**
- `TAGGER_DRY_RUN` defaults to `true`. Set it to `false` in `.env` to write tags.

---

## Project structure overview

```
main.py          Polling loop entry point
config.py        Loads .env, profile, SBOM — all config in one place
pipeline/        Framework: Stage base class, Pipeline runner, event model, helpers
stages/          One file per pipeline stage
Assets/          Org profiles and SBOMs — swap to change target organisation
data/            Runtime state (gitignored)
reports/         HTML output (gitignored)
Dockerfile       Container build definition
docker-compose.yml  Service definition and volume mounts
```

For a full module-by-module breakdown, see [CODEBASE_GUIDE.md](CODEBASE_GUIDE.md).
