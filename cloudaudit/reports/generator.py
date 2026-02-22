"""cloudaudit — Report Generator v2 with full branding and compliance sections."""

from __future__ import annotations
import json, time
from datetime import datetime, timezone
from html import escape
from typing import Any, Dict, List

from cloudaudit.core.models import ScanStats
from cloudaudit.core.constants import __version__, __tool_name__, __author__, __author_url__, __tagline__

_SEV_COLORS = {
    "Critical": "#c0392b", "High": "#e67e22",
    "Medium": "#d4ac0d", "Low": "#27ae60", "Informational": "#2980b9",
}

def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

def _badge(sev: str) -> str:
    bg = _SEV_COLORS.get(sev, "#7f8c8d")
    fg = "#fff" if sev != "Medium" else "#333"
    return f'<span style="background:{bg};color:{fg};padding:2px 9px;border-radius:10px;font-size:.78em;font-weight:700">{escape(sev)}</span>'

class ReportGenerator:

    @classmethod
    def json(cls, stats: ScanStats, org: str = "") -> str:
        return json.dumps({
            "meta": {
                "tool": __tool_name__, "version": __version__,
                "author": __author__, "author_url": __author_url__,
                "generated_at": _now(), "organisation": org, "tagline": __tagline__,
            },
            "scan": stats.to_dict(),
        }, indent=2, default=str)

    @classmethod
    def markdown(cls, stats: ScanStats, org: str = "") -> str:
        c   = stats.container_info
        now = _now()
        sev = cls._sev_counts(stats)
        elapsed = round(time.time() - stats.start_time, 1)

        lines = [
            f"# {__tool_name__} Security Report", "",
            f"**Organisation:** {org}  ",
            f"**Generated:** {now}  ",
            f"**Tool:** {__tool_name__} v{__version__} — Powered by {__author__}  ",
            f"**Contact:** {__author_url__}  ", "",
            "---", "", "## Container Information", "",
            "| Field | Value |", "|-------|-------|",
            f"| URL | `{c.raw_url if c else 'N/A'}` |",
            f"| Provider | {c.container_type.value if c else 'N/A'} |",
            f"| Name | `{c.container_name if c else 'N/A'}` |",
            f"| Region | {c.region if c else 'N/A'} |",
            f"| Public | {'**YES — MISCONFIGURED**' if c and c.is_public else 'No'} |", "",
            "---", "", "## Audit Summary", "",
            "| Metric | Value |", "|--------|-------|",
            f"| Files Discovered | {stats.total_files} |",
            f"| Files Scanned | {stats.scanned_files} |",
            f"| Archives Extracted | {stats.archive_files} |",
            f"| Risk Score | **{stats.risk_score:.1f} / 10** |",
            f"| Total Findings | **{len(stats.findings)}** |",
            f"| Duration | {elapsed}s |", "",
            "### Severity Breakdown", "",
            "| Severity | Count |", "|----------|-------|",
        ]
        for s in ["Critical","High","Medium","Low","Informational"]:
            lines.append(f"| {s} | {sev.get(s, 0)} |")

        if stats.ai_summary:
            lines += ["", "---", "", "## AI Executive Summary", "", stats.ai_summary, ""]

        lines += ["", "---", "", "## Technical Findings", ""]
        for sev_name in ["Critical","High","Medium","Low","Informational"]:
            bucket = [f for f in stats.findings if f.severity.value == sev_name]
            if not bucket: continue
            lines += [f"### {sev_name} ({len(bucket)})", ""]
            for f in bucket:
                ai_tag = " `[AI]`" if "AI:" in (f.scanner or "") else ""
                ar_tag = " `[ARCHIVE]`" if f.from_archive else ""
                lines += [
                    f"#### `{f.file_name}` — {f.rule_name}{ai_tag}{ar_tag}", "",
                    f"- **Category:** {f.category.value}",
                    f"- **Description:** {f.description}",
                    f"- **Confidence:** {f.confidence:.0%}  |  **Line:** {f.line_number or 'N/A'}",
                    f"- **Compliance:** {', '.join(f.compliance_refs) or 'N/A'}",
                    f"- **Remediation:** {f.recommendation}", "",
                ]

        comp_hits: Dict[str, set] = {}
        for f in stats.findings:
            for ref in f.compliance_refs:
                comp_hits.setdefault(ref, set()).add(f.rule_name)
        if comp_hits:
            lines += ["---", "", "## Compliance Mapping", "",
                      "| Control | Triggered By |", "|---------|------------|"]
            for ref, rules in sorted(comp_hits.items()):
                lines.append(f"| {ref} | {', '.join(sorted(rules)[:3])} |")

        if stats.errors:
            lines += ["", "---", "", "## Scan Errors", ""]
            for e in stats.errors[:20]:
                lines.append(f"- `{e}`")

        lines += [
            "", "---", "",
            f"*{__tool_name__} v{__version__} — {__tagline__}*  ",
            f"*Developed by {__author__} — {__author_url__}*",
        ]
        return "\n".join(lines)

    @classmethod
    def html(cls, stats: ScanStats, org: str = "") -> str:
        c       = stats.container_info
        now     = _now()
        sev     = cls._sev_counts(stats)
        elapsed = round(time.time() - stats.start_time, 1)

        def card(label, value, color="#3498db"):
            return (f'<div class="card" style="border-left-color:{color}">'
                    f'<div class="card-label">{escape(str(label))}</div>'
                    f'<div class="card-value">{escape(str(value))}</div></div>')

        # findings html
        fhtml = ""
        for sn in ["Critical","High","Medium","Low","Informational"]:
            bucket = [f for f in stats.findings if f.severity.value == sn]
            if not bucket: continue
            col = _SEV_COLORS.get(sn, "#ccc")
            fhtml += f'<h3 style="color:{col};margin-top:22px">{escape(sn)} ({len(bucket)})</h3>'
            for f in bucket:
                ar = '<span class="tag tag-ar">ARCHIVE</span>' if f.from_archive else ""
                ai = '<span class="tag tag-ai">AI</span>' if "AI:" in (f.scanner or "") else ""
                fhtml += f"""
<div class="finding" style="border-left-color:{col}">
  <div class="fh"><code>{escape(f.file_name)}</code> {_badge(sn)} {ar} {ai}</div>
  <table class="ft">
    <tr><td>Rule</td><td><code>{escape(f.rule_name)}</code></td></tr>
    <tr><td>Description</td><td>{escape(f.description)}</td></tr>
    <tr><td>Category</td><td>{escape(f.category.value)}</td></tr>
    <tr><td>Detection</td><td>{"AI Heuristic" if "AI:" in (f.scanner or "") else "Deterministic Pattern"}</td></tr>
    <tr><td>Confidence</td><td>{f.confidence:.0%} | Line: {f.line_number or "N/A"}</td></tr>
    <tr><td>Compliance</td><td>{escape(", ".join(f.compliance_refs)) or "N/A"}</td></tr>
    <tr><td>Remediation</td><td>{escape(f.recommendation)}</td></tr>
  </table>
  {'<pre class="ctx">' + escape(f.context) + '</pre>' if f.context else ''}
  <p class="ur"><a href="{escape(f.file_url)}" target="_blank">{escape(f.file_url[:80])}</a></p>
</div>"""

        # ai section
        import re as _re
        ahtml = ""
        if stats.ai_summary:
            s = escape(stats.ai_summary)
            s = _re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", s)
            s = s.replace("\n\n","</p><p>").replace("\n","<br>")
            ahtml = f'<section><h2>AI Executive Summary</h2><div class="aib"><p>{s}</p></div></section>'

        # compliance
        comp_hits: Dict[str, set] = {}
        for f in stats.findings:
            for ref in f.compliance_refs:
                comp_hits.setdefault(ref, set()).add(f.rule_name)
        chtml = ""
        if comp_hits:
            rows = "".join(
                f'<tr><td><code>{escape(r)}</code></td><td>{escape(", ".join(sorted(rls)[:4]))}</td></tr>'
                for r, rls in sorted(comp_hits.items())
            )
            chtml = (f'<section><h2>Compliance Mapping</h2>'
                     f'<table class="ct"><thead><tr><th>Control</th><th>Triggered By</th></tr></thead>'
                     f'<tbody>{rows}</tbody></table></section>')

        risk_col = "#c0392b" if stats.risk_score >= 7 else "#e67e22" if stats.risk_score >= 4 else "#27ae60"

        return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>CloudAudit Report | {escape(org)} | {now[:10]}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f1117;color:#e2e8f0;line-height:1.65}}
a{{color:#63b3ed}} code{{background:#2d3748;padding:1px 4px;border-radius:3px;font-size:.9em}}
.page{{max-width:1100px;margin:0 auto;padding:24px}}
header{{background:#1a202c;border:1px solid #2d3748;padding:26px 30px;border-radius:8px;margin-bottom:4px}}
header h1{{font-size:1.7em;color:#90cdf4;font-weight:700;letter-spacing:.03em}}
header .sub{{color:#718096;font-size:.86em;margin-top:6px}}
.warn{{background:#742a2a;border:1px solid #9b2c2c;color:#fed7d7;padding:10px 18px;font-size:.84em;margin:4px 0;border-radius:4px}}
section{{background:#1a202c;border:1px solid #2d3748;padding:22px 26px;margin-bottom:4px;border-radius:6px}}
h2{{font-size:1.05em;color:#90cdf4;border-bottom:1px solid #2d3748;padding-bottom:7px;margin-bottom:14px;text-transform:uppercase;letter-spacing:.07em}}
h3{{font-size:.98em;color:#e2e8f0;margin:16px 0 6px}}
.cg{{display:grid;grid-template-columns:repeat(auto-fit,minmax(148px,1fr));gap:10px}}
.card{{background:#2d3748;border-left:4px solid #4299e1;border-radius:5px;padding:13px}}
.card-label{{font-size:.7em;color:#718096;text-transform:uppercase;letter-spacing:.06em}}
.card-value{{font-size:1.6em;font-weight:700;color:#e2e8f0;margin-top:3px}}
.risk{{font-size:2.6em;font-weight:800;color:{risk_col}}}
.finding{{border-left:4px solid #4a5568;border-radius:4px;padding:14px;margin:9px 0;background:#2d3748}}
.fh{{display:flex;align-items:center;gap:7px;flex-wrap:wrap;margin-bottom:9px;font-weight:600}}
.ft{{width:100%;border-collapse:collapse;font-size:.82em}}
.ft td{{padding:4px 7px;border-bottom:1px solid #4a5568;vertical-align:top}}
.ft td:first-child{{color:#718096;width:100px;font-weight:600}}
.ctx,.ctx pre{{background:#171923;color:#a0aec0;padding:9px;border-radius:4px;font-size:.77em;overflow-x:auto;margin-top:9px;white-space:pre-wrap}}
.ur{{margin-top:7px;font-size:.79em}}
.tag{{font-size:.66em;padding:1px 6px;border-radius:8px;font-weight:700}}
.tag-ar{{background:#553c9a;color:#e9d8fd}} .tag-ai{{background:#1a4731;color:#9ae6b4}}
.aib{{background:#1c3030;border:1px solid #2c5f5f;border-radius:5px;padding:18px;line-height:1.85;color:#c6f6d5}}
.ct{{width:100%;border-collapse:collapse;font-size:.84em}}
.ct th{{background:#2d3748;padding:8px;text-align:left;color:#718096;font-size:.76em;text-transform:uppercase}}
.ct td{{padding:7px 8px;border-bottom:1px solid #2d3748}}
.mg{{display:grid;grid-template-columns:1fr 1fr;gap:5px;font-size:.87em}}
.mg dt{{color:#718096}} .mg dd{{color:#e2e8f0;font-weight:500}}
footer{{text-align:center;padding:24px;color:#4a5568;font-size:.81em;background:#1a202c;border-radius:6px;margin-top:4px}}
footer strong{{color:#718096}}
</style></head>
<body><div class="page">
<header>
  <h1>CloudAudit Security Report</h1>
  <div class="sub">Organisation: <strong style="color:#e2e8f0">{escape(org)}</strong>&nbsp;|&nbsp;{escape(now)}&nbsp;|&nbsp;{__tool_name__} v{__version__}</div>
</header>
<div class="warn">INTERNAL USE ONLY — Sensitive security findings. Distribute to authorised personnel only. Read-only audit — no write operations performed.</div>
<section>
  <h2>Container Information</h2>
  <dl class="mg">
    <dt>Provider</dt><dd>{escape(c.container_type.value if c else "N/A")}</dd>
    <dt>Name</dt><dd><code>{escape(c.container_name if c else "N/A")}</code></dd>
    <dt>URL</dt><dd style="word-break:break-all"><code>{escape((c.raw_url if c else "N/A")[:80])}</code></dd>
    <dt>Region</dt><dd>{escape(c.region if c else "N/A")}</dd>
    <dt>Public Access</dt><dd style="color:{'#fc8181' if c and c.is_public else '#68d391'}">{"YES — MISCONFIGURED" if c and c.is_public else "No"}</dd>
  </dl>
</section>
<section>
  <h2>Audit Summary</h2>
  <div class="cg">
    {card("Found", stats.total_files)}
    {card("Scanned", stats.scanned_files)}
    {card("Archives", stats.archive_files, "#6b46c1")}
    {card("Critical", sev.get("Critical",0), _SEV_COLORS["Critical"])}
    {card("High", sev.get("High",0), _SEV_COLORS["High"])}
    {card("Duration", f"{elapsed}s")}
  </div>
  <div style="margin-top:16px">Risk Score: <span class="risk">{stats.risk_score:.1f}</span><span style="color:#4a5568;font-size:1.2em"> / 10</span></div>
</section>
{ahtml}
<section><h2>Technical Findings</h2>{fhtml if fhtml else '<p style="color:#68d391">No findings above the minimum severity threshold.</p>'}</section>
{chtml}
<section>
  <h2>File Inventory (first 250)</h2>
  <table class="ct"><thead><tr><th>Key</th><th>Type</th><th>Size</th></tr></thead>
  <tbody>{"".join(f'<tr><td><code>{escape(ef.key[:80])}</code></td><td>{escape(ef.file_type.value)}</td><td>{ef.size_bytes//1024} KB</td></tr>' for ef in stats.exposed_files[:250])}</tbody></table>
</section>
<footer>
  <p><strong>{__tool_name__} v{__version__}</strong> — {escape(__tagline__)}</p>
  <p>Developed by <strong>{__author__}</strong> — <a href="{__author_url__}">{__author_url__}</a></p>
  <p>Defensive read-only audit. No write operations were performed.</p>
</footer>
</div></body></html>"""

    @staticmethod
    def _sev_counts(stats: ScanStats) -> Dict[str, int]:
        c: Dict[str, int] = {}
        for f in stats.findings:
            c[f.severity.value] = c.get(f.severity.value, 0) + 1
        return c
