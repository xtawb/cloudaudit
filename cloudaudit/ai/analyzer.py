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

This module only talks to a *remote* provider. The offline equivalent lives in
``cloudaudit.intelligence.local_ai`` and is always run by the engine, so a
missing or failing provider never removes semantic analysis from an audit.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cloudaudit.ai.providers import extract_json
from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.utils.helpers import calculate_entropy, redact, url_filename

logger = logging.getLogger("cloudaudit.ai.analyzer")


_SEVERITY_MAP = {
    "critical":      Severity.CRITICAL,
    "high":          Severity.HIGH,
    "medium":        Severity.MEDIUM,
    "moderate":      Severity.MEDIUM,
    "low":           Severity.LOW,
    "info":          Severity.INFORMATIONAL,
    "informational": Severity.INFORMATIONAL,
}

# AI finding "type" text → report category (first match wins).
_CATEGORY_HINTS: Tuple[Tuple[str, FindingCategory], ...] = (
    (r"pii|personal|email|phone|ssn|address|gdpr|customer data|card", FindingCategory.PII_EXPOSURE),
    (r"infra|internal|hostname|ip address|network|topology|endpoint", FindingCategory.INFRASTRUCTURE_INF),
    (r"public|acl|bucket polic|anonymous access", FindingCategory.PUBLIC_ACCESS),
    (r"misconfig|compliance|insecure|weak|debug|tls|ssl|cors|encrypt|logging|policy", FindingCategory.COMPLIANCE),
    (r"private key|certificate|keystore|credential file", FindingCategory.CREDENTIAL_FILE),
)


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
    category:       FindingCategory = FindingCategory.SECRET_EXPOSURE
    line_number:    Optional[int] = None

    def to_finding(self) -> Finding:
        return Finding(
            file_url=self.file_url,
            file_name=self.file_name,
            file_type=self.file_type,
            category=self.category,
            rule_name=self.rule_name,
            description=f"[AI] {self.description}",
            severity=self.severity,
            match=self.match,
            context=self.context,
            line_number=self.line_number,
            recommendation=self.recommendation,
            compliance_refs=self.compliance_refs,
            confidence=self.confidence,
            scanner=f"AI:{self.ai_provider}/{self.ai_model}",
        )


def _redact_tokens(text: str) -> str:
    """Redact anything token-shaped. Applied to content sent to AI *and* to text AI sends back."""
    return re.sub(
        r"(?<![A-Za-z0-9+/_\-])([A-Za-z0-9+/_\-]{24,}={0,2})",
        lambda m: redact(m.group(1), keep_chars=6),
        text,
    )


class AIFileAnalyzer:
    """
    Uses an AI provider to perform semantic analysis of file content.

    Only invoked for HIGH-VALUE or SUSPICIOUS files to control API costs.
    """

    # File characteristics that trigger AI analysis
    _HIGH_VALUE_PATTERNS = [
        r"\.env(\.|$)",
        r"(^|/)(config|conf|settings|secrets?|deploy|infra)/",
        r"config\.(json|yaml|yml|toml|ini|php|js)$",
        r"\.pem$", r"\.key$",
        r"credentials?",
        r"secret",
        r"(docker|kubernetes|k8s|compose)",
        r"terraform|\.tf(vars|state)?$",
        r"\.sql$",
        r"\.backup$|\.bak$",
        r"settings\.(py|rb|php|js)",
        r"application\.(properties|yml|yaml)",
        r"appsettings.*\.json$",
        r"\.aws/",
        r"\.ssh/",
        r"\.(npmrc|pypirc|netrc|htpasswd|pgpass)$",
    ]

    MAX_FINDINGS_PER_FILE = 15

    def __init__(self, provider_chain) -> None:
        self._chain    = provider_chain
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self._HIGH_VALUE_PATTERNS]

    @property
    def enabled(self) -> bool:
        """False once the remote provider is absent or has been disabled for this run."""
        return bool(getattr(self._chain, "has_remote", False))

    def should_analyse_with_ai(self, file_url: str, file_type: FileType) -> bool:
        """Determine if this file warrants AI analysis (controls API spend)."""
        if not self.enabled:
            return False
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
        Returns list of AI-generated findings (may be empty). Never raises.
        """
        if not content.strip() or not self.enabled:
            return []

        # Prepare sanitised content (partially redact obvious secrets before sending)
        sanitised = self._sanitise_for_ai(content)
        known = ", ".join(sorted({
            f"{f.rule_name}@L{f.line_number}" if f.line_number else f.rule_name
            for f in existing_findings
        }))[:600]

        try:
            response = self._chain.analyse_file_content(
                url_filename(file_url), file_type.value, sanitised, known,
            )
        except Exception as exc:
            logger.debug("AI file analysis failed for %s: %s", file_url, exc)
            return []

        if not response.ok:
            return []

        findings = self._parse_ai_response(
            response.text, file_url, file_type,
            response.provider, response.model,
        )
        return self._drop_already_known(findings, existing_findings)[: self.MAX_FINDINGS_PER_FILE]

    # ── Internal helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _sanitise_for_ai(content: str) -> str:
        """
        Partially redact secrets before sending to AI.
        The AI sees enough context to understand the finding without seeing raw secrets.
        """
        # Redact anything that looks like a full private key block
        sanitised = re.sub(
            r"(-----BEGIN[^-]+-----).*?(-----END[^-]+-----)",
            r"\1 [REDACTED] \2",
            content[:20000],
            flags=re.DOTALL,
        )
        # Redact long token-shaped strings (keys, hashes, base64 blobs)
        sanitised = _redact_tokens(sanitised)
        # Redact the value side of secret-bearing assignments and URL passwords
        sanitised = re.sub(
            r"(?i)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|private[_-]?key|credential)\w*[\"']?\s*[=:]\s*[\"']?)([^\s\"',;]{6,})",
            lambda m: m.group(1) + redact(m.group(2), keep_chars=3),
            sanitised,
        )
        sanitised = re.sub(r"(://[^/\s:@]{1,64}:)([^@\s]{3,})(@)", r"\1***\3", sanitised)
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

        data = extract_json(text)
        if isinstance(data, list):
            data = {"findings": data}
        if not isinstance(data, dict):
            logger.debug("AI returned non-JSON for %s", file_url)
            return []
        items = data.get("findings", [])
        if not isinstance(items, list):
            return []

        for item in items:
            if not isinstance(item, dict):
                continue
            try:
                severity = _SEVERITY_MAP.get(str(item.get("severity", "medium")).strip().lower(), Severity.MEDIUM)
                try:
                    confidence = float(item.get("confidence", 0.6))
                except (TypeError, ValueError):
                    confidence = 0.6
                if confidence > 1.0:          # model answered on a 0-100 scale
                    confidence /= 100.0
                # AI findings get a small confidence penalty vs deterministic
                confidence = max(0.05, min(confidence * 0.9, 0.95))

                kind = re.sub(r"[^A-Za-z0-9]+", "_", str(item.get("type") or "DETECTION")).strip("_").upper()[:48]
                description = _redact_tokens(str(item.get("description") or "AI-detected security issue"))[:400]
                hint = _redact_tokens(str(item.get("line_hint") or ""))[:120]
                line_m = re.search(r"(?:line|L)\s*#?\s*(\d{1,7})", hint, re.IGNORECASE)

                category = FindingCategory.SECRET_EXPOSURE
                probe = f"{kind} {description}".lower().replace("_", " ")
                for pattern, cat in _CATEGORY_HINTS:
                    if re.search(pattern, probe):
                        category = cat
                        break

                findings.append(AIFinding(
                    file_url=file_url,
                    file_name=url_filename(file_url),
                    file_type=file_type,
                    rule_name=f"AI_{kind or 'DETECTION'}",
                    description=description,
                    severity=severity,
                    match=hint or "[AI detected — no explicit match]",
                    recommendation=str(item.get("recommendation") or
                                       "Review file content and remediate as appropriate.")[:400],
                    confidence=confidence,
                    ai_provider=ai_provider,
                    ai_model=ai_model,
                    category=category,
                    line_number=int(line_m.group(1)) if line_m else None,
                ))
            except Exception as exc:
                logger.debug("Failed to parse AI finding item: %s", exc)

        return findings

    @staticmethod
    def _drop_already_known(ai_findings: List[AIFinding], existing: List[Finding]) -> List[AIFinding]:
        """Remove AI findings that restate something a deterministic scanner already reported."""
        known_lines = {f.line_number for f in existing if f.line_number}
        seen: set = set()
        kept: List[AIFinding] = []
        for af in ai_findings:
            if af.line_number and af.line_number in known_lines \
                    and af.category in (FindingCategory.SECRET_EXPOSURE, FindingCategory.CREDENTIAL_FILE):
                continue
            key = (af.rule_name, af.line_number, af.description[:60].lower())
            if key in seen:
                continue
            seen.add(key)
            kept.append(af)
        return kept


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
        use_ai: bool = False,
    ) -> Tuple[float, str]:
        """
        Returns (anomaly_score: 0-10, explanation: str).
        Score is computed deterministically; ``use_ai`` optionally blends in a
        remote model's opinion (off by default — it costs one request per file).
        """
        score = 0.0
        reasons = []

        # Factor 1: High-entropy string density
        lines = content.split("\n")
        high_entropy_lines = 0
        entropy_strings = []
        for line in lines:
            if len(line) > 2000:
                continue
            tokens = re.split(r'[\s=:"\',]+', line)
            for tok in tokens:
                if len(tok) > 15:
                    ent = calculate_entropy(tok)
                    if ent > 4.5:
                        high_entropy_lines += 1
                        entropy_strings.append(redact(tok, keep_chars=4))
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
            score += min(crit * 1.5 + high * 0.8, 6.0)
            if crit > 0:
                reasons.append(f"{crit} critical-severity pattern matches")

        # Factor 3: Sensitive keyword density
        sensitive_keywords = [
            "password", "passwd", "secret", "token", "credential",
            "private", "api_key", "apikey",
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

        # Optional: enrich with AI score if a remote provider is live
        if use_ai and self._chain is not None and getattr(self._chain, "has_remote", False) and score > 3.0:
            patterns = [f.rule_name for f in existing_findings[:10]]
            try:
                ai_resp = self._chain.score_anomaly(url_filename(file_url), entropy_strings[:5], patterns)
                ai_data = extract_json(ai_resp.text) if ai_resp.ok else None
                if isinstance(ai_data, dict) and ai_resp.provider != "heuristic":
                    ai_score = max(0.0, min(float(ai_data.get("score", score)), 10.0))
                    ai_expl  = str(ai_data.get("explanation", ""))[:300]
                    # Blend: 60% heuristic, 40% AI
                    score = 0.6 * score + 0.4 * ai_score
                    if ai_expl:
                        explanation += f" | AI: {ai_expl}"
            except Exception:
                pass  # Don't fail on AI scoring errors

        return round(score, 2), explanation
