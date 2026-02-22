"""
cloudaudit.ai.analyzer — AI-Driven File Intelligence

Performs semantic analysis that goes beyond regex pattern matching:
  - Contextual secret detection (AI understands intent, not just pattern)
  - Configuration security assessment
  - Anomaly scoring with explanation
  - Compliance correlation
  - Deduplication of findings
  - Finding enrichment with AI confidence

Clearly separates:
  - DETERMINISTIC findings (from SecretScanner — regex + entropy)
  - AI_HEURISTIC findings (from this module — semantic analysis)
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.utils.helpers import calculate_entropy, redact, url_filename

logger = logging.getLogger("cloudaudit.ai.analyzer")


@dataclass
class AIFinding:
    """A finding produced by AI semantic analysis."""
    file_url:       str
    file_name:      str
    file_type:      FileType
    rule_name:      str
    description:    str
    severity:       Severity
    match:          str             # Always redacted
    recommendation: str
    confidence:     float
    ai_provider:    str
    ai_model:       str
    detection_type: str = "AI_HEURISTIC"   # Clear label vs "DETERMINISTIC"
    compliance_refs:List[str] = field(default_factory=list)
    context:        str = ""

    def to_finding(self) -> Finding:
        return Finding(
            file_url=self.file_url,
            file_name=self.file_name,
            file_type=self.file_type,
            category=FindingCategory.SECRET_EXPOSURE,
            rule_name=self.rule_name,
            description=f"[AI] {self.description}",
            severity=self.severity,
            match=self.match,
            context=self.context,
            recommendation=self.recommendation,
            compliance_refs=self.compliance_refs,
            confidence=self.confidence,
            scanner=f"AI:{self.ai_provider}/{self.ai_model}",
        )


class AIFileAnalyzer:
    """
    Uses an AI provider to perform semantic analysis of file content.

    Only invoked for HIGH-VALUE or SUSPICIOUS files to control API costs.
    """

    # File characteristics that trigger AI analysis
    _HIGH_VALUE_PATTERNS = [
        r"\.env$",
        r"config\.(json|yaml|yml|toml|ini)$",
        r"\.pem$", r"\.key$",
        r"credentials?",
        r"secret",
        r"(docker|kubernetes|k8s)",
        r"terraform",
        r"\.sql$",
        r"\.backup$",
        r"settings\.(py|rb|php|js)",
        r"application\.(properties|yml|yaml)",
        r"\.aws/",
        r"\.ssh/",
    ]

    def __init__(self, provider_chain) -> None:
        self._chain    = provider_chain
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self._HIGH_VALUE_PATTERNS]

    def should_analyse_with_ai(self, file_url: str, file_type: FileType) -> bool:
        """Determine if this file warrants AI analysis (controls API spend)."""
        fname = url_filename(file_url).lower()
        path  = file_url.lower()

        # Always analyse certificate/key files
        if file_type == FileType.CERTIFICATE:
            return True

        # Always analyse environment files
        if file_type == FileType.ENVIRONMENT:
            return True

        # Pattern-based decision for others
        return any(p.search(path) or p.search(fname) for p in self._compiled)

    def analyse(
        self,
        content: str,
        file_url: str,
        file_type: FileType,
        existing_findings: List[Finding],
    ) -> List[AIFinding]:
        """
        Run AI semantic analysis on file content.
        Returns list of AI-generated findings (may be empty).
        """
        if not content.strip():
            return []

        # Prepare sanitised content (partially redact obvious secrets before sending)
        sanitised = self._sanitise_for_ai(content)

        try:
            response = self._chain.analyse_file_content(
                filename=url_filename(file_url),
                filetype=file_type.value,
                content=sanitised,
            )
        except Exception as exc:
            logger.debug("AI file analysis failed for %s: %s", file_url, exc)
            return []

        if not response.ok:
            return []

        return self._parse_ai_response(
            response.text, file_url, file_type,
            response.provider, response.model,
        )

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _sanitise_for_ai(content: str) -> str:
        """
        Partially redact high-entropy strings before sending to AI.
        The AI sees enough context to understand the finding without seeing raw secrets.
        """
        # Redact long base64/hex strings (likely keys)
        sanitised = re.sub(
            r"\b([A-Za-z0-9+/]{40,}={0,2})\b",
            lambda m: redact(m.group(1), keep_chars=8),
            content,
        )
        # Redact anything that looks like a full private key block
        sanitised = re.sub(
            r"(-----BEGIN[^-]+-----)[^-]+(-----END[^-]+-----)",
            r"\1 [REDACTED] \2",
            sanitised,
            flags=re.DOTALL,
        )
        return sanitised[:5000]

    @staticmethod
    def _parse_ai_response(
        text: str,
        file_url: str,
        file_type: FileType,
        ai_provider: str,
        ai_model: str,
    ) -> List[AIFinding]:
        """Parse AI JSON response into AIFinding objects."""
        findings: List[AIFinding] = []

        # Strip markdown code fences if present
        text = text.strip()
        if text.startswith("```"):
            text = re.sub(r"^```[a-z]*\n?", "", text)
            text = re.sub(r"\n?```$", "", text)

        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            logger.debug("AI returned non-JSON for %s", file_url)
            return []

        for item in data.get("findings", []):
            try:
                sev_str = item.get("severity", "medium").lower()
                sev_map = {
                    "critical":      Severity.CRITICAL,
                    "high":          Severity.HIGH,
                    "medium":        Severity.MEDIUM,
                    "low":           Severity.LOW,
                    "informational": Severity.INFORMATIONAL,
                }
                severity   = sev_map.get(sev_str, Severity.MEDIUM)
                confidence = float(item.get("confidence", 0.6))
                # AI findings get a small confidence penalty vs deterministic
                confidence = min(confidence * 0.9, 0.95)

                findings.append(AIFinding(
                    file_url=file_url,
                    file_name=url_filename(file_url),
                    file_type=file_type,
                    rule_name=f"AI_{item.get('type', 'DETECTION').upper().replace(' ', '_')}",
                    description=item.get("description", "AI-detected security issue"),
                    severity=severity,
                    match=item.get("line_hint", "[AI detected — no explicit match]"),
                    recommendation=item.get("recommendation", "Review file content and remediate as appropriate."),
                    confidence=confidence,
                    ai_provider=ai_provider,
                    ai_model=ai_model,
                ))
            except Exception as exc:
                logger.debug("Failed to parse AI finding item: %s — %s", item, exc)

        return findings


class AnomalyScorer:
    """
    ML-inspired anomaly scoring using entropy analysis and pattern correlation.
    No external ML library required — uses statistical heuristics + optional AI scoring.
    """

    def __init__(self, provider_chain=None) -> None:
        self._chain = provider_chain

    def score_content(
        self,
        content: str,
        file_url: str,
        existing_findings: List[Finding],
    ) -> Tuple[float, str]:
        """
        Returns (anomaly_score: 0-10, explanation: str).
        Score is computed deterministically, optionally enriched by AI.
        """
        score = 0.0
        reasons = []

        # Factor 1: High-entropy string density
        lines = content.split("\n")
        high_entropy_lines = 0
        entropy_strings = []
        for line in lines:
            tokens = re.split(r'[\s=:"\',]+', line)
            for tok in tokens:
                if len(tok) > 15:
                    ent = calculate_entropy(tok)
                    if ent > 4.5:
                        high_entropy_lines += 1
                        entropy_strings.append(tok[:20] + "...")
                        break

        entropy_ratio = high_entropy_lines / max(len(lines), 1)
        if entropy_ratio > 0.3:
            score += 3.0
            reasons.append(f"High entropy string density: {entropy_ratio:.0%} of lines")
        elif entropy_ratio > 0.1:
            score += 1.5
            reasons.append(f"Elevated entropy strings: {entropy_ratio:.0%} of lines")

        # Factor 2: Existing finding severity amplification
        if existing_findings:
            crit = sum(1 for f in existing_findings if f.severity == Severity.CRITICAL)
            high = sum(1 for f in existing_findings if f.severity == Severity.HIGH)
            score += crit * 1.5 + high * 0.8
            if crit > 0:
                reasons.append(f"{crit} critical-severity pattern matches")

        # Factor 3: Sensitive keyword density
        sensitive_keywords = [
            "password", "passwd", "secret", "token", "key", "credential",
            "private", "cert", "auth", "access", "api_key", "apikey",
        ]
        content_lower = content.lower()
        keyword_hits = sum(content_lower.count(kw) for kw in sensitive_keywords)
        keyword_density = keyword_hits / max(len(content.split()), 1)
        if keyword_density > 0.05:
            score += 2.0
            reasons.append(f"High sensitive keyword density ({keyword_hits} hits)")
        elif keyword_density > 0.02:
            score += 0.8

        # Factor 4: File size relative to extension (e.g. tiny .env with many secrets)
        fname = url_filename(file_url).lower()
        if fname.endswith((".env", ".pem", ".key")) and len(content) < 2000:
            score += 1.0  # Small sensitive files are often real config files

        score = min(score, 10.0)
        explanation = " | ".join(reasons) if reasons else "No significant anomalies detected"

        # Optional: enrich with AI score if available
        if self._chain and score > 3.0:
            patterns = [f.rule_name for f in existing_findings[:10]]
            try:
                ai_resp = self._chain.score_anomaly(
                    file_url, entropy_strings[:5], patterns
                )
                if ai_resp.ok:
                    ai_data = json.loads(ai_resp.text)
                    ai_score = float(ai_data.get("score", score))
                    ai_expl  = ai_data.get("explanation", "")
                    # Blend: 60% heuristic, 40% AI
                    score = 0.6 * score + 0.4 * ai_score
                    if ai_expl:
                        explanation += f" | AI: {ai_expl}"
            except Exception:
                pass  # Don't fail on AI scoring errors

        return round(score, 2), explanation
