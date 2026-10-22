"""Offline report generation: JSON, CSV, and escaped static HTML.

Covers the "structured findings, evidence capture, timestamps, and
machine-readable JSON/CSV output" requirement. HTML output escapes every
interpolated value with ``html.escape`` - evidence pulled from a banner or
vuln description can never inject markup into the report.
"""
from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from scripter.models import PrioritizedFinding

_CSV_FIELDS = [
    "rank", "score", "host", "port", "service", "version", "signature_id", "cve_id",
    "description", "severity", "exploitability", "time_to_validate_minutes", "status",
    "confidence", "evidence", "matched_at",
]


def _finding_to_dict(pf: PrioritizedFinding) -> dict:
    m = pf.match
    return {
        "rank": pf.rank,
        "score": pf.score,
        "host": m.host,
        "port": m.port,
        "service": m.service,
        "version": m.version,
        "signature_id": m.signature_id,
        "cve_id": m.cve_id,
        "description": m.description,
        "severity": m.severity.value,
        "exploitability": m.exploitability.value,
        "time_to_validate_minutes": m.time_to_validate_minutes,
        "status": m.status.value,
        "confidence": m.confidence,
        "evidence": m.evidence,
        "matched_at": m.matched_at.isoformat(),
    }


def write_json(findings: list[PrioritizedFinding], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps([_finding_to_dict(f) for f in findings], indent=2), encoding="utf-8")
    return out_path


def write_csv(findings: list[PrioritizedFinding], out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        for f in findings:
            writer.writerow(_finding_to_dict(f))
    return out_path


def write_html(findings: list[PrioritizedFinding], out_path: Path, title: str = "Scripter findings") -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for f in findings:
        d = _finding_to_dict(f)
        cells = "".join(f"<td>{html.escape(str(v))}</td>" for v in d.values())
        rows.append(f"<tr>{cells}</tr>")
    headers = "".join(f"<th>{html.escape(k)}</th>" for k in _CSV_FIELDS)
    doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{html.escape(title)}</title>
<style>
body {{ font-family: system-ui, sans-serif; margin: 2rem; }}
table {{ border-collapse: collapse; width: 100%; }}
th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.85rem; }}
th {{ background: #eee; }}
tr:nth-child(even) {{ background: #fafafa; }}
</style>
</head>
<body>
<h1>{html.escape(title)}</h1>
<p>{len(findings)} finding(s), ranked by score (severity x confidence x exploitability, scaled by validation time).</p>
<table>
<thead><tr>{headers}</tr></thead>
<tbody>
{''.join(rows)}
</tbody>
</table>
</body>
</html>
"""
    out_path.write_text(doc, encoding="utf-8")
    return out_path
