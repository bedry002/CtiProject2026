"""Stage 6 — Renders scored events to an HTML debug report."""

from __future__ import annotations

import logging
import pathlib
from datetime import datetime, timezone

from pipeline.base import Stage
from pipeline.event import CurationEvent

logger = logging.getLogger(__name__)

_IOC_SAMPLE_TYPES = frozenset({
    "ip-src", "ip-dst", "domain", "hostname", "url",
    "md5", "sha256", "sha1", "vulnerability",
})
_HASH_TYPES = frozenset({"md5", "sha256", "sha1"})


def _attr_ioc_sample(attributes: list, n: int = 6) -> list[tuple[str, str]]:
    seen: set[str] = set()
    out: list[tuple[str, str]] = []
    for attr in attributes:
        if len(out) >= n:
            break
        t = attr.get("type", "")
        v = str(attr.get("value", "")).strip()
        if t in _IOC_SAMPLE_TYPES and v and v not in seen:
            seen.add(v)
            display = (v[:16] + "…") if t in _HASH_TYPES and len(v) > 16 else v
            out.append((t, display))
    return out


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


def _bar(confidence: float, fg: str, width: int = 200) -> str:
    pct = min(int(confidence * 100), 100)
    return (
        f'<div style="background:#e9ecef;border-radius:4px;width:{width}px;height:12px;">'
        f'<div style="background:{fg};width:{pct}%;height:12px;border-radius:4px;"></div>'
        f'</div>'
    )


def _threat_context_pills(entities: dict) -> str:
    parts: list[str] = []

    for item in entities.get("threat_actors", []):
        text = item["text"] if isinstance(item, dict) else str(item)
        parts.append(
            f'<span style="background:#e2d9f3;padding:1px 6px;border-radius:10px;'
            f'font-size:0.78em;margin:1px;display:inline-block">'
            f'<b>actor</b> {text}</span>'
        )

    # TTPs enriched with ATT&CK metadata — org-relevant ones highlighted green
    for ttp in entities.get("ttps", []):
        if not isinstance(ttp, dict):
            continue
        tid      = ttp.get("text", "")
        name     = ttp.get("name", "")
        tactics  = ttp.get("tactics", [])
        relevant = ttp.get("org_relevant", False)
        label    = tid
        if name:
            label += f" {name}"
        if tactics:
            label += f" [{tactics[0].replace('-', ' ')}]"
        bg = "#d4edda" if relevant else "#e9ecef"
        parts.append(
            f'<span style="background:{bg};padding:1px 6px;border-radius:10px;'
            f'font-size:0.78em;margin:1px;display:inline-block" '
            f'title="{"Targets org platforms" if relevant else "Platform not in org stack"}">'
            f'<b>ttp</b> {label}</span>'
        )

    for item in entities.get("cves", []):
        text = item["text"] if isinstance(item, dict) else str(item)
        parts.append(
            f'<span style="background:#f8d7da;padding:1px 6px;border-radius:10px;'
            f'font-size:0.78em;margin:1px;display:inline-block">'
            f'<b>cve</b> {text}</span>'
        )

    # Geography — not scored, shown for analyst awareness
    seen_geo: set[str] = set()
    for item in entities.get("geographies", []):
        text = (item["text"] if isinstance(item, dict) else str(item)).strip()
        if text and text.lower() not in seen_geo:
            seen_geo.add(text.lower())
            parts.append(
                f'<span style="background:#d3e3fd;padding:1px 6px;border-radius:10px;'
                f'font-size:0.78em;margin:1px;display:inline-block">'
                f'<b>geo</b> {text}</span>'
            )

    return " ".join(parts) or "<em style='color:#6c757d'>none</em>"


def _render(events: list[CurationEvent], all_count: int, threshold: float) -> str:
    now      = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    relevant = sum(1 for e in events if (e.confidence or 0) >= threshold)
    high     = sum(1 for e in events if (e.confidence or 0) >= 0.50)
    medium   = sum(1 for e in events if 0.25 <= (e.confidence or 0) < 0.50)
    low      = sum(1 for e in events if threshold <= (e.confidence or 0) < 0.25)

    rows: list[str] = []
    for e in sorted(events, key=lambda x: x.confidence or 0, reverse=True):
        conf           = e.confidence or 0
        label, fg, bg  = _band(conf)
        bd             = e.score_breakdown
        cve_badge = (' <span title="CVE matched SBOM component" style="color:#0d6efd">&#x2731;</span>'
                     if bd.get("sbom_cve", 0) > 0 else "")
        if bd and conf > 0:
            sp = round(bd.get("stack_contrib",  0) / conf * 100)
            ep = round(bd.get("sector_contrib", 0) / conf * 100)
            tp = round(bd.get("ttp_contrib",    0) / conf * 100)
            breakdown_html = f'Stack&nbsp;{sp}%{cve_badge} &nbsp; Sec&nbsp;{ep}% &nbsp; TTP&nbsp;{tp}%'
        else:
            breakdown_html = ""

        ioc         = e.ioc_summary
        total_iocs  = sum(ioc.values())
        sample      = _attr_ioc_sample(e.raw.get("Attribute", []))
        ioc_pills   = " ".join(
            f'<code style="font-size:0.75em;background:#e9ecef;padding:1px 4px;border-radius:3px">{t}:{v}</code>'
            for t, v in sample
        )
        ioc_line    = (
            f'{total_iocs} IOCs &nbsp;<small style="color:#6c757d">'
            f'vuln:{ioc.get("vulnerability",0)} '
            f'net:{sum(ioc.get(t,0) for t in ("hostname","domain","ip-src","ip-dst","url"))} '
            f'file:{sum(ioc.get(t,0) for t in ("md5","sha256","sha1","filename"))}</small>'
            + (f'<br><span style="font-size:0.78em">{ioc_pills}</span>' if ioc_pills else "")
        ) if total_iocs else "<em style='color:#6c757d'>none</em>"

        nvd_cves = e.entities.get("nvd_cves", [])
        if nvd_cves:
            nvd_html = " ".join(
                f'<code style="font-size:0.75em;background:#f8d7da;padding:1px 4px;'
                f'border-radius:3px;white-space:nowrap">{c}</code>'
                for c in nvd_cves
            )
        else:
            nvd_html = "<em style='color:#6c757d'>none — enable NVD_ENRICH=true</em>" if not e.matched_sbom_components else "<em style='color:#6c757d'>no CVEs</em>"

        summary_row = ""
        if e.analyst_summary:
            flags_html = (
                f'<br><small style="color:#6c757d">Flags: {"; ".join(e.implicit_relevance_flags)}</small>'
                if e.implicit_relevance_flags else ""
            )
            summary_row = (
                f'<tr style="background:{bg}">'
                f'<td colspan="8" style="border-left:3px solid #d4a017;padding:5px 14px 8px">'
                f'<b style="color:#856404;font-size:0.82em">&#x1F9E0; Analyst Summary</b>'
                f'<p style="margin:3px 0;font-size:0.88em">{e.analyst_summary}</p>'
                f'{flags_html}</td></tr>'
            )

        rows.append(f"""
        <tr style="background:{bg}">
          <td style="color:{fg};font-weight:bold;white-space:nowrap">{label.upper()}</td>
          <td>{e.misp_id}</td>
          <td>{e.raw.get('date','')}</td>
          <td>{e.raw.get('info','')[:90]}</td>
          <td style="text-align:center">
            {_bar(conf, fg)}<br>
            <code style="font-size:0.85em;font-weight:bold">{conf:.4f}</code><br>
            <small style="color:#6c757d;font-size:0.75em">{breakdown_html}</small>
          </td>
          <td style="font-size:0.82em">{ioc_line}</td>
          <td style="font-size:0.82em">{nvd_html}</td>
          <td style="font-size:0.82em">{_threat_context_pills(e.entities)}</td>
        </tr>{summary_row}""")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Curation Engine Report</title>
<style>
  body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #212529; }}
  h1 {{ color: #0d6efd; }} h2 {{ color: #495057; border-bottom: 1px solid #dee2e6; padding-bottom: 6px; }}
  .stat-grid {{ display: flex; gap: 1rem; margin: 1rem 0; flex-wrap: wrap; }}
  .stat {{ background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 8px; padding: 1rem 1.5rem; min-width: 130px; text-align: center; }}
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
<p class="meta">Generated: {now} &nbsp;|&nbsp; MISP events evaluated: {all_count} &nbsp;|&nbsp; Confidence threshold: {threshold}</p>
<h2>Summary</h2>
<div class="stat-grid">
  <div class="stat"><div class="value">{all_count}</div><div class="label">Events evaluated</div></div>
  <div class="stat"><div class="value">{relevant}</div><div class="label">Above threshold</div></div>
  <div class="stat"><div class="value" style="color:#1a7a3e">{high}</div><div class="label">High (&ge;0.50)</div></div>
  <div class="stat"><div class="value" style="color:#856404">{medium}</div><div class="label">Medium (0.25–0.50)</div></div>
  <div class="stat"><div class="value" style="color:#721c24">{low}</div><div class="label">Low (0.10–0.25)</div></div>
</div>
<h2>Event Scores</h2>
<table>
<thead>
  <tr>
    <th>Band</th><th>Event ID</th><th>Date</th><th>Info</th>
    <th>Confidence<br><small style="font-weight:normal">Stack · Sec · TTP as % of total</small></th>
    <th>IOCs</th><th>NVD CVEs<br><small style="font-weight:normal">for matched SBOM components</small></th><th>Threat Context<br><small style="font-weight:normal">actors &nbsp;ttps &nbsp;cves &nbsp;geo</small></th>
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

    @property
    def name(self) -> str:
        return "report"

    def __init__(self, output_path: pathlib.Path, threshold: float = 0.05, all_count: int = 0) -> None:
        self._output_path = output_path
        self._threshold   = threshold
        self._all_count   = all_count

    def process(self, event: CurationEvent) -> CurationEvent:
        return event

    def process_batch(self, events: list[CurationEvent]) -> list[CurationEvent]:
        html = _render(events, self._all_count or len(events), self._threshold)
        self._output_path.parent.mkdir(exist_ok=True)
        self._output_path.write_text(html, encoding="utf-8")
        relevant = sum(1 for e in events if (e.confidence or 0) >= self._threshold)
        logger.info("Report written → %s  (%d/%d relevant)", self._output_path, relevant, len(events))
        return events
