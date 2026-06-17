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
CONFIDENCE_THRESHOLD=0.20
POLL_LOOKBACK_HOURS=24
POLL_INTERVAL_SECONDS=30
POLL_RUN_ONCE=true
POLL_RESET_STATE=false
TAGGER_DRY_RUN=true
LLM_SKIP=true
```

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
