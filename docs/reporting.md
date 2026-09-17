# Reporting

Source: `reports/generator.py`

CloudAudit can generate a report in any of six formats from a single scan.

## Output Formats

Specify one or more with `--format`:

| Format | Flag value | Use case |
|---|---|---|
| JSON | `json` | SIEM ingestion, ticketing integration, custom tooling |
| HTML | `html` | Dark-theme report for stakeholder distribution |
| Markdown | `markdown` | Confluence, Notion, Jira, GitHub wiki |
| SARIF 2.1.0 | `sarif` | GitHub Advanced Security code scanning ingestion |
| CSV | `csv` | Flat findings table for spreadsheets |
| PDF | `pdf` | Optional dependency (`xhtml2pdf`) — printable stakeholder report |
| All of the above | `all` (default) | Generates every format in one run |

```bash
cloudaudit -u https://mybucket.s3.amazonaws.com/ \
           --confirm-ownership --org-name "Acme Corp" \
           --format sarif -o reports/audit
```

PDF export requires the optional dependency:

```bash
pip install cloudaudit[pdf]
```

If it's not installed, `--format pdf` fails with a clear message telling you
how to install it rather than silently producing no output.

## JSON Report

Machine-readable output with full finding metadata:

```json
{
  "meta": {
    "tool": "CloudAudit",
    "version": "1.2.0",
    "author": "xtawb",
    "author_url": "https://linktr.ee/xtawb",
    "generated_at": "2026-01-01T00:00:00Z",
    "organisation": "Acme Corp",
    "tagline": "Powered by xtawb | Defensive. Intelligent. Enterprise-Grade."
  },
  "scan": {
    "container_info": { "...": "..." },
    "findings": [
      {
        "file_url": "https://...",
        "file_name": ".env",
        "file_type": "Environment",
        "category": "Secret Exposure",
        "rule_name": "AWS_ACCESS_KEY",
        "description": "AWS Access Key ID detected ...",
        "severity": "Critical",
        "match": "AKIA12***",
        "context": "... surrounding lines ...",
        "line_number": 12,
        "recommendation": "Rotate this key immediately ...",
        "compliance_refs": ["CIS 2.1.5", "NIST IA-5"],
        "confidence": 0.97,
        "scanner": "DETERMINISTIC",
        "from_archive": false
      }
    ],
    "risk_score": 8.7,
    "ai_summary": "...",
    "total_files": 847,
    "scanned_files": 421,
    "archive_files": 3
  }
}
```

This is also the format consumed by `cloudaudit diff <old.json> <new.json>`
and by `cloudaudit history`.

## SARIF Report

Valid SARIF 2.1.0, suitable for `github/codeql-action/upload-sarif` in CI —
see [`cloudaudit init-ci`](cli-reference.md#cloudaudit-init-ci) for a ready-made GitHub
Actions workflow that wires this up automatically.

## HTML Report

A professional dark-theme report for stakeholder distribution. Sections:

- **Header** — tool name, organisation, generation timestamp
- **Warning banner** — internal-use-only notice
- **Container information** — provider, name, URL, region, public access status
- **Audit summary** — stat cards (files found, scanned, archives, critical count, risk score)
- **AI executive summary** — formatted AI-generated summary, including the
  exposure trend delta when prior scan history exists (see
  [Risk Engine](risk-engine.md#exposure-trend-delta))
- **Technical findings** — per-finding cards with severity badge, rule,
  description, compliance, recommendation
- **Compliance mapping** — table mapping each control reference to the
  rules that triggered it
- **File inventory** — first 250 discovered files with type and size
- **Footer** — tool version, author, author URL, defensive notice

Findings are tagged visually:

- `[AI]` badge (green) — AI heuristic detection
- `[ARCHIVE]` badge (purple) — finding from inside an extracted archive

## Markdown & CSV Reports

Markdown contains the same sections as HTML in table form, suitable for
pasting into wikis. CSV is a flat one-row-per-finding table for spreadsheet
analysis and quick filtering.

## Report Sections (JSON/HTML/Markdown)

| Section | Description |
|---|---|
| Container Information | Provider type, name, URL, region, public access status |
| Audit Summary | Files discovered/scanned/skipped, duration, risk score, severity breakdown |
| AI Executive Summary | 4-6 paragraph CISO-level narrative (AI or heuristic generated), including trend delta |
| Technical Findings | Full findings grouped by severity with all metadata |
| AI Insights | AI-generated per-file findings labelled separately from deterministic |
| Compliance Mapping | Table of control references triggered by findings |
| Risk Breakdown | Severity-weighted score with category multiplier explanation |
| Remediation Steps | Per-finding actionable remediation guidance |
| Scan Timeline | Phase durations and file inventory |
| Tool Metadata | Version, timestamp, configuration used |

## Suppressing Known/Accepted Findings

Pass `--baseline baseline.json` to suppress findings that have already been
triaged and accepted as risk. Suppressed findings are excluded from the
report body but counted in `ScanStats.suppressed_count` so nothing silently
disappears from the audit trail. See [Configuration](configuration.md) for
the baseline file format.

## Batch & Multi-Target Reports

`--targets-file urls.txt` produces one full report set per target plus a
combined `<output>_batch_summary.json` aggregating risk scores and finding
counts across all scanned targets.

## Branding

All reports include consistent branding in headers, footers, and metadata:

```text
Generated by CloudAudit v1.2.0 — Powered by xtawb
Contact: https://linktr.ee/xtawb
Defensive read-only audit. No write operations were performed.
```
