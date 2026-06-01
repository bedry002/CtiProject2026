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

- Python 3.10+
- A running MISP instance with API access
- (Optional) An OpenAI-compatible LLM endpoint for analyst summaries

---

## Installation

```bash
git clone https://github.com/bedry002/CtiProject2026.git
cd CtiProject2026
pip install -r requirements.txt
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
MISP_KEY=your_misp_automation_key

# Your organisation profile and SBOM
ORG_PROFILE_PATH=Assets/your_profile.json
ORG_SBOM_PATH=Assets/your_sbom.json
```

### 2. Create your organisation profile

Create a JSON file describing your organisation (see [Profile format](#profile-format) below). Several example profiles are included in `Assets/`.

### 3. Run

```bash
# One-shot mode — process events from the last 24 hours and exit
POLL_RUN_ONCE=true python main.py

# Continuous mode — poll every 30 seconds
python main.py
```

The HTML report is written to `reports/curation_report.html` after each run.

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
| `cpe_list` | CPE identifiers injected as synthetic SBOM components for scoring |

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

Each event receives a confidence score between 0 and 1, computed from four weighted dimensions:

| Dimension | Default weight | What it measures |
|---|---|---|
| Asset | 30% | SBOM component mentions + keyword hits |
| Technology | 30% | Technology terms from your profile appearing in the event |
| Sector | 30% | Sector terms from your profile appearing in the event |
| Geography | 10% | Geography terms from your profile appearing in the event |

Events are then banded:

| Band | Score | MISP tag |
|---|---|---|
| High | ≥ 0.50 | `curation:relevance=high` |
| Medium | 0.25 – 0.50 | `curation:relevance=medium` |
| Low | 0.10 – 0.25 | `curation:relevance=low` |
| Not relevant | < threshold | dropped / `curation:relevance=not-relevant` |

The default drop threshold is `0.20`. Adjust with `CONFIDENCE_THRESHOLD` in `.env`.

---

## Configuration reference

All settings are read from `.env`. A full template with descriptions is in `.env.template`.

### Essential

```env
MISP_URL=https://your-misp-instance
MISP_KEY=your_api_key
ORG_PROFILE_PATH=Assets/your_profile.json
ORG_SBOM_PATH=Assets/your_sbom.json
```

### Tuning

```env
CONFIDENCE_THRESHOLD=0.20      # Drop events below this score
POLL_LOOKBACK_HOURS=24         # How far back the first run looks
POLL_INTERVAL_SECONDS=30       # Seconds between polls
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

For Groq:
```env
LLM_API_URL=https://api.groq.com/openai/v1/chat/completions
LLM_MODEL=llama-3.3-70b-versatile
```

For local Ollama:
```env
LLM_API_URL=http://localhost:11434/v1/chat/completions
LLM_API_KEY=ollama
LLM_MODEL=llama3.1:8b
LLM_JSON_MODE=false        # set true only if your Ollama build supports json_object mode
LLM_TIMEOUT_SECONDS=120    # local models are slower
```

---

## Integrating into your system

### As a long-running service

Run `main.py` as a process and manage it with systemd, Docker, or a process supervisor.

**systemd unit example:**

```ini
[Unit]
Description=CTI Curation Engine
After=network.target

[Service]
WorkingDirectory=/opt/CtiProject2026
ExecStart=/opt/venv/bin/python main.py
EnvironmentFile=/opt/CtiProject2026/.env
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
```

### As a Docker container

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
```

```bash
docker build -t cti-engine .
docker run -d \
  --env-file .env \
  -v $(pwd)/reports:/app/reports \
  -v $(pwd)/data:/app/data \
  cti-engine
```

### As a one-shot batch job (cron)

```bash
# Set POLL_RUN_ONCE=true in .env and POLL_RESET_STATE=false to continue from last run
0 * * * * cd /opt/CtiProject2026 && /opt/venv/bin/python main.py >> /var/log/cti-engine.log 2>&1
```

### Importing the pipeline in your own code

```python
from dotenv import load_dotenv
load_dotenv()

from config import BUSINESS_PROFILE, SBOM_PROFILE, CONFIDENCE_THRESHOLD
from pipeline.runner import Pipeline
from stages.ingest import MISPIngestStage
from stages.ner import NERStage
from stages.scoring import ScoringStage
from stages.report import ReportStage
import pathlib, time

pipeline = Pipeline([
    NERStage(),
    ScoringStage(
        BUSINESS_PROFILE, SBOM_PROFILE,
        threshold=CONFIDENCE_THRESHOLD,
    ),
    ReportStage(pathlib.Path("reports/report.html"), threshold=CONFIDENCE_THRESHOLD),
])

ingest = MISPIngestStage("https://your-misp", "your-key", False)
events = ingest.fetch(since_timestamp=int(time.time()) - 86400)
results = pipeline.run(events)

for event in results:
    print(event.misp_id, event.confidence, event.score_breakdown)
```

### Adding a custom stage

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

Register it in `main.py:build_pipeline()` after the scoring stage.

---

## What gets written to MISP

When `TAGGER_DRY_RUN=false`, the engine writes:

| What | Where in MISP |
|---|---|
| Relevance tag | Event tag: `curation:relevance=high/medium/low` |
| TLP tag | Event tag: `tlp:white` |
| Feed tag | Event tag: `feed:curated` |
| Score breakdown | Event attribute (type: text, category: External analysis) |
| Analyst summary | Event attribute (type: text, category: External analysis) |

The engine cleans up old `curation:` tags before writing new ones, so re-running is safe.

---

## Running tests

```bash
pytest tests/ -v
```

---

## Troubleshooting

**No events surfacing (score 0.0 for everything)**
- Check your profile has meaningful `sectors`, `technologies`, and `keywords`. Empty arrays score nothing.
- Look at what events are actually in your MISP feed — IDS/network observation events with only IP addresses will never match a profile.
- Run with `POLL_LOOKBACK_HOURS=500` to cast a wider net and see if older events score better.

**Events scoring lower than expected**
- Check your SBOM component terms — very generic names like `server` are excluded to prevent false positives.
- Broaden `keywords` in your profile; keyword hits feed the `asset` dimension and even a single match contributes meaningfully.
- Check that `technologies`, `sectors`, and `geographies` in your profile match terms that actually appear in event text.

**spaCy model not found**
- Set `SPACY_AUTO_DOWNLOAD=true` in `.env` and the model will be downloaded on first run.
- Or install manually: `python -m spacy download en_core_web_lg`

**MISP tags not being written**
- `TAGGER_DRY_RUN` defaults to `true`. Set it to `false` in `.env` to write tags.

---

## Project structure overview

```
main.py          Polling loop entry point
config.py        Loads .env, profile, SBOM — all config in one place
evaluate.py      Offline scoring evaluation (assert-synthetic, sweep, kappa)
pipeline/        Framework: Stage base class, Pipeline runner, event model, helpers
stages/          One file per pipeline stage
Assets/          Org profiles and SBOMs — swap to change target organisation
data/            Runtime state (gitignored)
reports/         HTML output (gitignored)
tests/           Pytest test suite
```

For a full module-by-module breakdown, see [CODEBASE_GUIDE.md](CODEBASE_GUIDE.md).
