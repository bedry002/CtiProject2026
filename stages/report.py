"""Report stage — renders scored events to an HTML report."""

import logging
import pathlib
from datetime import datetime, timezone
from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)

_CONFIDENCE_BAND = [
    (0.50, "high",   "#1a7a3e", "#d4edda"),
    (0.25, "medium", "#856404", "#fff3cd"),
    (0.00, "low",    "#721c24", "#f8d7da"),
]


def _band(confidence: float) -> tuple[str, str, str]:
    for threshold, label, fg, bg in _CONFIDENCE_BAND:
        if confidence >= threshold:
            return label, fg, bg
    return "low", "#721c24", "#f8d7da"


def _bar(confidence: float, width: int = 200) -> str:
    pct = min(int(confidence * 100), 100)  # 0–1 scale maps directly to 0–100%
    _, fg, _ = _band(confidence)
    return (
        f'<div style="background:#e9ecef;border-radius:4px;width:{width}px;height:12px;">'
        f'<div style="background:{fg};width:{pct}%;height:12px;border-radius:4px;"></div>'
        f'</div>'
    )


def _entity_pills(entities: dict[str, list[str]]) -> str:
    if not entities:
        return "<em style='color:#6c757d'>none</em>"
    pills = []
    colours = {"ORG": "#cfe2ff", "GPE": "#d1e7dd", "NORP": "#fff3cd",
               "PRODUCT": "#e2d9f3", "PERSON": "#fde8d8", "EVENT": "#f8d7da"}
    for label, values in entities.items():
        bg = colours.get(label, "#e9ecef")
        for v in values:
            pills.append(
                f'<span style="background:{bg};padding:1px 6px;border-radius:10px;'
                f'font-size:0.78em;margin:1px;display:inline-block">'
                f'<b>{label}</b> {v}</span>'
            )
    return " ".join(pills)


def _topic_pills(topics: list[tuple[str, float]]) -> str:
    if not topics:
        return "<em style='color:#6c757d'>none</em>"
    pills = []
    for word, score in topics[:5]:
        opacity = max(0.4, score * 8)
        pills.append(
            f'<span style="background:rgba(13,110,253,{opacity:.2f});color:white;'
            f'padding:1px 6px;border-radius:10px;font-size:0.78em;margin:1px;'
            f'display:inline-block">{word}</span>'
        )
    return " ".join(pills)


def _render(events: list[CurationEvent], all_count: int, threshold: float) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    relevant = [e for e in events if (e.confidence or 0) >= threshold]
    high   = sum(1 for e in events if (e.confidence or 0) >= 0.50)
    medium = sum(1 for e in events if 0.25 <= (e.confidence or 0) < 0.50)
    low    = sum(1 for e in events if threshold <= (e.confidence or 0) < 0.25)

    rows = []
    for e in sorted(events, key=lambda x: x.confidence or 0, reverse=True):
        conf = e.confidence or 0
        label, fg, bg = _band(conf)
        bd = e.score_breakdown
        breakdown_html = (
            f'<span title="SBOM">S:{bd.get("sbom",0):.2f}</span> '
            f'<span title="Keyword">K:{bd.get("keyword",0):.2f}</span> '
            f'<span title="Technology">T:{bd.get("technology",0):.2f}</span> '
            f'<span title="Context">C:{bd.get("context",0):.2f}</span>'
        ) if bd else ""
        sbom_html = (
            ", ".join(f'<code style="font-size:0.78em">{r}</code>' for r in e.matched_sbom_components)
            or "<em style='color:#6c757d'>none</em>"
        )
        rows.append(f"""
        <tr style="background:{bg}">
          <td style="color:{fg};font-weight:bold;white-space:nowrap">{label.upper()}</td>
          <td>{e.misp_id}</td>
          <td>{e.raw.get('date','')}</td>
          <td>{e.raw.get('info','')[:90]}</td>
          <td style="text-align:center">
            {_bar(conf)}<br>
            <code style="font-size:0.85em;font-weight:bold">{conf:.4f}</code><br>
            <small style="color:#6c757d;font-size:0.75em">{breakdown_html}</small>
          </td>
          <td style="font-size:0.82em">{sbom_html}</td>
          <td style="font-size:0.82em">{', '.join(e.matched_profile_terms)}</td>
          <td style="font-size:0.82em">{_entity_pills(e.entities)}</td>
          <td style="font-size:0.82em">{_topic_pills(e.topics)}</td>
        </tr>""")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Curation Engine Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #212529; }}
  h1 {{ color: #0d6efd; }} h2 {{ color: #495057; border-bottom: 1px solid #dee2e6; padding-bottom: 6px; }}
  .stat-grid {{ display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }}
  .stat {{ background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px;
           padding: 1rem 1.5rem; min-width: 130px; text-align: center; }}
  .stat .value {{ font-size: 2rem; font-weight: bold; color: #0d6efd; }}
  .stat .label {{ color: #6c757d; font-size: 0.85em; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.9em; }}
  th {{ background: #343a40; color: white; padding: 8px 10px; text-align: left; position: sticky; top: 0; }}
  td {{ padding: 7px 10px; vertical-align: top; border-bottom: 1px solid rgba(0,0,0,0.05); }}
  tr:hover td {{ filter: brightness(0.96); }}
  .meta {{ color: #6c757d; font-size: 0.85em; margin-bottom: 1.5rem; }}
</style>
</head>
<body>
<h1>Curation Engine — Scoring Report</h1>
<p class="meta">Generated: {now} &nbsp;|&nbsp; MISP events evaluated: {all_count} &nbsp;|&nbsp;
Confidence threshold: {threshold}</p>

<h2>Summary</h2>
<div class="stat-grid">
  <div class="stat"><div class="value">{all_count}</div><div class="label">Events evaluated</div></div>
  <div class="stat"><div class="value">{len(relevant)}</div><div class="label">Above threshold</div></div>
  <div class="stat"><div class="value" style="color:#1a7a3e">{high}</div><div class="label">High (&ge;0.15)</div></div>
  <div class="stat"><div class="value" style="color:#856404">{medium}</div><div class="label">Medium (0.08–0.15)</div></div>
  <div class="stat"><div class="value" style="color:#721c24">{low}</div><div class="label">Low (threshold–0.08)</div></div>
</div>

<h2>Event Scores</h2>
<table>
<thead>
  <tr>
    <th>Band</th><th>Event ID</th><th>Date</th><th>Info</th>
    <th>Confidence<br><small style="font-weight:normal">S=SBOM K=Keyword T=Tech C=Context</small></th>
    <th>SBOM Hits</th><th>Matched Terms</th><th>NER Entities</th><th>Topic Keywords</th>
  </tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>"""


class ReportStage(Stage):
    """Writes a scored-event HTML report after all other stages have run."""

    name = "report"

    def __init__(
        self,
        output_path: pathlib.Path,
        threshold: float = 0.05,
        all_count: int = 0,
    ) -> None:
        self._output_path = output_path
        self._threshold = threshold
        self._all_count = all_count

    def process(self, event: CurationEvent) -> CurationEvent:
        return event

    def process_batch(self, events: list[CurationEvent]) -> list[CurationEvent]:
        html = _render(events, self._all_count or len(events), self._threshold)
        self._output_path.parent.mkdir(exist_ok=True)
        self._output_path.write_text(html, encoding="utf-8")
        relevant = sum(1 for e in events if (e.confidence or 0) >= self._threshold)
        logger.info(
            "Report written → %s  (%d/%d relevant)",
            self._output_path, relevant, len(events),
        )
        return events
