"""
cloudaudit.utils.webhook — Opt-In Scan Summary Webhook Notifications

Posts a small, already-redacted JSON summary (target, risk score, severity
counts, and a handful of top findings by rule/severity/file — never raw
secret values, which are never present in a Finding to begin with) to a
user-supplied webhook URL at the end of a scan.

The payload includes both a Slack-style "text" field and a Discord-style
"content" field so the same POST works against either platform's incoming
webhook format without extra configuration.

This is the one place in cloudaudit that intentionally sends an outbound
POST — it is not part of the read-only HTTP client used against audit
targets; it only ever talks to the webhook URL the user explicitly provided.
"""

from __future__ import annotations

import json
import logging
import urllib.request
from typing import Optional

from cloudaudit.core.constants import DEFAULT_WEBHOOK_TIMEOUT, __tool_name__
from cloudaudit.core.models import ScanStats, Severity

logger = logging.getLogger("cloudaudit.webhook")


def build_payload(stats: ScanStats, target: str, org: str) -> dict:
    sev_counts = {s.value: 0 for s in Severity}
    for f in stats.findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    top_findings = sorted(
        stats.findings, key=lambda f: f.severity.int_value, reverse=True
    )[:5]

    lines = [
        f"*{__tool_name__} scan summary* for `{target}`",
        f"Organisation: {org or 'N/A'}",
        f"Risk score: {stats.risk_score:.1f} / 10",
        f"Findings: {len(stats.findings)} "
        f"(Critical={sev_counts.get('Critical', 0)}, High={sev_counts.get('High', 0)}, "
        f"Medium={sev_counts.get('Medium', 0)}, Low={sev_counts.get('Low', 0)})",
    ]
    if stats.suppressed_count:
        lines.append(f"Suppressed via baseline: {stats.suppressed_count}")
    if top_findings:
        lines.append("Top findings:")
        for f in top_findings:
            lines.append(f"  - [{f.severity.value}] {f.rule_name} — {f.file_name}")

    text = "\n".join(lines)

    return {
        # Slack incoming-webhook format
        "text": text,
        # Discord incoming-webhook format
        "content": text,
        # Structured payload for any custom consumer
        "cloudaudit": {
            "target": target,
            "organisation": org,
            "risk_score": stats.risk_score,
            "total_findings": len(stats.findings),
            "severity_counts": sev_counts,
            "suppressed_count": stats.suppressed_count,
            "top_findings": [
                {
                    "rule_name": f.rule_name,
                    "severity": f.severity.value,
                    "category": f.category.value,
                    "file_name": f.file_name,
                }
                for f in top_findings
            ],
        },
    }


def send_webhook(url: str, stats: ScanStats, target: str, org: str,
                  timeout: Optional[float] = None) -> tuple[bool, str]:
    """
    POST a redacted scan summary to a Slack/Discord-compatible webhook URL.
    Never raises — returns (ok, message) so a failed notification never fails the scan.
    """
    payload = build_payload(stats, target, org)
    body = json.dumps(payload).encode("utf-8")
    try:
        req = urllib.request.Request(
            url,
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": f"{__tool_name__}-Webhook/1.0"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=timeout or DEFAULT_WEBHOOK_TIMEOUT) as resp:
            status = getattr(resp, "status", 200)
            if 200 <= status < 300:
                return True, f"Webhook delivered (HTTP {status})"
            return False, f"Webhook returned HTTP {status}"
    except Exception as exc:
        logger.warning("Webhook delivery failed: %s", exc)
        return False, f"Webhook delivery failed: {exc}"
