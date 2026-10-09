"""
cloudaudit.core.pipeline — per-file content analysis pipeline

One place that turns "the text of a file" into findings, so that every source
of content gets exactly the same analysis:

    storage objects · archive members · Docker image layers ·
    extracted document text · the accuracy benchmark

Stages (in order):
  1. SecretScanner            — typed / generic credential rules
  2. TerraformStateScanner    — structural walk of *.tfstate
  3. Third-party plugins      — cloudaudit.scanners entry points
  4. LocalIntelligence        — semantic assignments, config audit, JWT context
  5. EntropyHunter            — high-entropy strings, filtered by the token classifier

Stages 4-5 are the "deep" stages; they can be skipped for content where they
only add cost or noise (vendored trees, OS files in image layers, huge blobs).
"""

from __future__ import annotations

from typing import List, Optional, Sequence

from cloudaudit.core.constants import DEFAULT_MIN_ENTROPY
from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.intelligence.advanced import EntropyHunter
from cloudaudit.intelligence.local_ai import LocalIntelligence, is_credential_finding, is_noise_file
from cloudaudit.intelligence.terraform_scanner import TerraformStateScanner
from cloudaudit.scanners.plugin_loader import run_plugins
from cloudaudit.scanners.secret_scanner import SecretScanner
from cloudaudit.utils.helpers import url_filename

# Beyond this size the deep stages are skipped: they are line-oriented and a
# multi-megabyte text blob is a data file, not configuration.
DEEP_ANALYSIS_MAX_CHARS = 2 * 1024 * 1024


class ContentAnalyzer:
    """Runs the full per-file analysis pipeline. One instance per audit run."""

    def __init__(
        self,
        min_entropy: float = DEFAULT_MIN_ENTROPY,
        custom_patterns: Optional[Sequence] = None,
        plugins: Optional[Sequence] = None,
    ) -> None:
        self.min_entropy = min_entropy
        self.secret      = SecretScanner(min_entropy=min_entropy, custom_patterns=list(custom_patterns or []))
        self.terraform   = TerraformStateScanner()
        self.local       = LocalIntelligence()
        self.entropy     = EntropyHunter()
        self.plugins     = list(plugins or [])

    def analyse(self, content: str, url: str, file_type: FileType, deep: bool = True) -> List[Finding]:
        """Return every finding for one file's text. ``deep=False`` runs stages 1-3 only."""
        findings: List[Finding] = self.secret.scan(content, url, file_type)

        # Dedicated Terraform state scanner — walks resources[].instances[].attributes
        # structurally instead of relying only on generic regex/entropy matching.
        if file_type == FileType.TERRAFORM and url_filename(url).lower().endswith((".tfstate", ".tfstate.backup")):
            findings.extend(self.terraform.scan(content, url))

        if self.plugins:
            meta = {"url": url, "file_name": url_filename(url), "file_type": file_type}
            findings.extend(run_plugins(self.plugins, content, meta))

        if deep and len(content) <= DEEP_ANALYSIS_MAX_CHARS:
            findings.extend(self.local.analyse_file(content, url, file_type, findings))
            findings.extend(self.entropy_findings(content, url, file_type, findings))
        return findings

    def entropy_findings(
        self, content: str, url: str, file_type: FileType, existing: List[Finding]
    ) -> List[Finding]:
        """High-entropy strings that no rule explained, judged by the token classifier."""
        if is_noise_file(url):
            return []
        taken = {f.line_number for f in existing if f.line_number and is_credential_finding(f)}
        out: List[Finding] = []
        for hit in self.entropy.scan(content, threshold=self.min_entropy, classifier=self.local.classifier):
            if hit.line_number in taken:
                continue
            strong = hit.score >= 0.8
            out.append(Finding(
                file_url=url,
                file_name=url_filename(url),
                file_type=file_type,
                category=FindingCategory.SECRET_EXPOSURE,
                rule_name="HIGH_ENTROPY_STRING",
                description=(
                    f"High-entropy string detected (entropy={hit.entropy:.2f}, "
                    f"secret-likelihood {hit.score:.0%}) — possible undiscovered secret"
                ),
                severity=Severity.MEDIUM if strong else Severity.LOW,
                match=hit.value,
                context=hit.context,
                line_number=hit.line_number,
                recommendation="Review this string — high entropy may indicate an undocumented credential or key.",
                compliance_refs=["NIST IA-5"],
                confidence=round(min(0.35 + 0.5 * hit.score, 0.85), 3),
                scanner="EntropyHunter",
                value_hash=hit.value_hash,
            ))
        return out
