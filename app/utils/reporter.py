"""
Bug Hunter AI — Report Generator
Produces HTML, JSON, and Markdown security reports.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, List, Optional, Tuple

from jinja2 import Environment, PackageLoader, select_autoescape


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Bug Hunter AI — Security Report</title>
  <style>
    :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3;
            --muted: #8b949e; --critical: #ff4757; --high: #ff6b35; --medium: #ffa502;
            --low: #2ed573; --info: #1e90ff; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif;
           font-size: 14px; line-height: 1.6; padding: 2rem; }
    .header { border: 1px solid var(--border); border-radius: 8px; padding: 2rem;
              margin-bottom: 2rem; background: var(--card); }
    .header h1 { font-size: 1.8rem; color: #58a6ff; margin-bottom: 0.5rem; }
    .header .tagline { color: var(--muted); font-size: 0.9rem; }
    .meta { display: grid; grid-template-columns: repeat(3, 1fr); gap: 1rem;
            margin-top: 1rem; }
    .meta-item label { color: var(--muted); font-size: 0.8rem; display: block; }
    .stats { display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem;
             margin-bottom: 2rem; }
    .stat-card { background: var(--card); border: 1px solid var(--border);
                 border-radius: 8px; padding: 1rem; text-align: center; }
    .stat-card .number { font-size: 2rem; font-weight: bold; }
    .stat-card .label { color: var(--muted); font-size: 0.8rem; }
    .finding { background: var(--card); border: 1px solid var(--border);
               border-radius: 8px; padding: 1.5rem; margin-bottom: 1rem; }
    .finding-header { display: flex; align-items: center; gap: 1rem; margin-bottom: 1rem; }
    .badge { padding: 0.25rem 0.75rem; border-radius: 4px; font-size: 0.75rem;
             font-weight: bold; text-transform: uppercase; }
    .badge-CRITICAL { background: var(--critical); color: #fff; }
    .badge-HIGH { background: var(--high); color: #fff; }
    .badge-MEDIUM { background: var(--medium); color: #000; }
    .badge-LOW { background: var(--low); color: #000; }
    .badge-INFO { background: var(--info); color: #fff; }
    .finding h3 { flex: 1; font-size: 1rem; }
    .section { margin-bottom: 1rem; }
    .section label { color: var(--muted); font-size: 0.8rem; display: block; margin-bottom: 0.25rem; }
    .code { background: #0d1117; border: 1px solid var(--border); border-radius: 4px;
            padding: 0.75rem; font-family: monospace; font-size: 0.85rem;
            white-space: pre-wrap; overflow-x: auto; }
    .footer { margin-top: 3rem; border-top: 1px solid var(--border); padding-top: 1rem;
              color: var(--muted); font-size: 0.8rem; text-align: center; }
    .warning { background: #2d1b00; border: 1px solid #ff6b35; border-radius: 8px;
               padding: 1rem; margin-bottom: 2rem; }
    .warning strong { color: var(--high); }
  </style>
</head>
<body>

<div class="header">
  <h1>🐺 Bug Hunter AI — Security Report</h1>
  <p class="tagline">Find • Explain • Fix • Verify — Local AI Cybersecurity Assistant</p>
  <div class="meta">
    <div class="meta-item"><label>Target</label><span>{{ target }}</span></div>
    <div class="meta-item"><label>Scan Date</label><span>{{ scan_date }}</span></div>
    <div class="meta-item"><label>Tools Used</label><span>{{ tools }}</span></div>
  </div>
</div>

<div class="warning">
  <strong>⚠ Authorization Required</strong><br>
  This report was generated for an authorized security assessment. Unauthorized scanning may be illegal.
</div>

<div class="stats">
  <div class="stat-card"><div class="number" style="color:var(--critical)">{{ counts.CRITICAL }}</div><div class="label">Critical</div></div>
  <div class="stat-card"><div class="number" style="color:var(--high)">{{ counts.HIGH }}</div><div class="label">High</div></div>
  <div class="stat-card"><div class="number" style="color:var(--medium)">{{ counts.MEDIUM }}</div><div class="label">Medium</div></div>
  <div class="stat-card"><div class="number" style="color:var(--low)">{{ counts.LOW }}</div><div class="label">Low</div></div>
  <div class="stat-card"><div class="number" style="color:var(--info)">{{ counts.INFO }}</div><div class="label">Info</div></div>
</div>

{% for finding in findings %}
<div class="finding">
  <div class="finding-header">
    <span class="badge badge-{{ finding.severity }}">{{ finding.severity }}</span>
    <h3>{{ finding.title }}</h3>
    <span style="color:var(--muted);font-size:0.8rem">{{ finding.detected_by }}</span>
  </div>

  {% if finding.description %}
  <div class="section">
    <label>Description</label>
    <p>{{ finding.description }}</p>
  </div>
  {% endif %}

  {% if finding.evidence %}
  <div class="section">
    <label>Evidence</label>
    <div class="code">{{ finding.evidence }}</div>
  </div>
  {% endif %}

  {% if finding.root_cause %}
  <div class="section">
    <label>Root Cause</label>
    <p>{{ finding.root_cause }}</p>
  </div>
  {% endif %}

  {% if finding.remediation %}
  <div class="section">
    <label>Recommended Fix</label>
    <p>{{ finding.remediation }}</p>
  </div>
  {% endif %}

  <div class="section">
    <label>Status</label>
    <span>{{ finding.status }}</span> &nbsp;|&nbsp;
    <label style="display:inline">Confidence</label> <span>{{ finding.confidence }}</span>
  </div>
</div>
{% endfor %}

<div class="footer">
  <p>Generated by Bug Hunter AI • {{ generated_at }} • All data stored locally</p>
  <p>🔒 No data was uploaded to any cloud service</p>
</div>

</body>
</html>"""


class ReportGenerator:
    """Generates security reports in HTML, JSON, and Markdown formats."""

    def generate(
        self,
        scan: Any,
        target: Any,
        findings: List[Any],
        fmt: str = "html",
    ) -> Tuple[str, str]:
        """
        Generate a report.

        Returns:
            Tuple of (content: str, content_type: str)
        """
        if fmt == "json":
            return self._json(scan, target, findings)
        elif fmt == "markdown":
            return self._markdown(scan, target, findings)
        else:
            return self._html(scan, target, findings)

    def _html(self, scan: Any, target: Any, findings: List[Any]) -> Tuple[str, str]:
        from jinja2 import Environment

        env = Environment(autoescape=True)
        tmpl = env.from_string(HTML_TEMPLATE)

        counts: dict = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        html = tmpl.render(
            target=target.value if target else "Unknown",
            scan_date=scan.created_at.strftime("%Y-%m-%d %H:%M UTC") if scan.created_at else "N/A",
            tools=", ".join(scan.tools_used or []),
            counts=counts,
            findings=findings,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        )
        return html, "text/html"

    def _json(self, scan: Any, target: Any, findings: List[Any]) -> Tuple[str, str]:
        data = {
            "report_type": "security_assessment",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scan": {
                "id": scan.id,
                "status": scan.status,
                "tools": scan.tools_used,
                "created_at": scan.created_at.isoformat() if scan.created_at else None,
            },
            "target": {
                "name": target.name if target else None,
                "value": target.value if target else None,
                "type": target.target_type if target else None,
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": _count_by(findings, "severity"),
                "by_status": _count_by(findings, "status"),
            },
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "category": f.category,
                    "severity": f.severity,
                    "confidence": f.confidence,
                    "affected_component": f.affected_component,
                    "description": f.description,
                    "evidence": f.evidence,
                    "root_cause": f.root_cause,
                    "remediation": f.remediation,
                    "status": f.status,
                    "detected_by": f.detected_by,
                    "detected_at": f.detected_at.isoformat() if f.detected_at else None,
                }
                for f in findings
            ],
        }
        return json.dumps(data, indent=2), "application/json"

    def _markdown(self, scan: Any, target: Any, findings: List[Any]) -> Tuple[str, str]:
        lines = [
            "# Bug Hunter AI — Security Report",
            "",
            f"**Target:** {target.value if target else 'Unknown'}  ",
            f"**Scan Date:** {scan.created_at.strftime('%Y-%m-%d %H:%M UTC') if scan.created_at else 'N/A'}  ",
            f"**Tools Used:** {', '.join(scan.tools_used or [])}  ",
            f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
            "",
            "> ⚠️ **Authorization Warning**: Only scan systems you are authorized to test.",
            "",
            "## Summary",
            "",
            f"| Severity | Count |",
            "| --- | --- |",
        ]

        counts = _count_by(findings, "severity")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            lines.append(f"| {sev} | {counts.get(sev, 0)} |")

        lines.extend(["", "## Findings", ""])

        for i, f in enumerate(findings, 1):
            lines.extend([
                f"### {i}. [{f.severity}] {f.title}",
                "",
                f"**Category:** {f.category}  ",
                f"**Confidence:** {f.confidence}  ",
                f"**Detected By:** {f.detected_by}  ",
                f"**Status:** {f.status}  ",
                "",
            ])
            if f.description:
                lines.extend(["**Description:**", f.description, ""])
            if f.evidence:
                lines.extend(["**Evidence:**", f"```\n{f.evidence}\n```", ""])
            if f.root_cause:
                lines.extend(["**Root Cause:**", f.root_cause, ""])
            if f.remediation:
                lines.extend(["**Recommended Fix:**", f.remediation, ""])
            lines.append("---")

        lines.extend([
            "",
            "*Generated by Bug Hunter AI — Local AI Cybersecurity Assistant*",
            "*All data stored locally. No cloud upload.*",
        ])

        return "\n".join(lines), "text/markdown"


def _count_by(items: List[Any], field: str) -> dict:
    counts: dict = {}
    for item in items:
        val = getattr(item, field, None)
        if val:
            counts[val] = counts.get(val, 0) + 1
    return counts
