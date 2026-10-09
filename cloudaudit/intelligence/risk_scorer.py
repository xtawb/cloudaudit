"""
cloudaudit — Risk Scoring Engine (v3)

Computes a 0–10 composite risk score from:
  - Severity, weighted by each finding's confidence (a 30%-confidence guess
    no longer weighs the same as a validated provider token)
  - Finding category
  - Diminishing returns per rule (the 400th email address in a CSV adds
    almost nothing; the first AWS key adds a lot)
  - Compound exposures identified by the correlation engine
  - Presence of validated cloud / provider credentials
  - Whether the container is publicly listable
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Dict, List

from cloudaudit.core.models import ContainerInfo, Finding, FindingCategory, Severity


class RiskScorer:

    # Severity weights
    _SEV_WEIGHTS = {
        Severity.CRITICAL:      4.0,
        Severity.HIGH:          2.0,
        Severity.MEDIUM:        0.8,
        Severity.LOW:           0.2,
        Severity.INFORMATIONAL: 0.0,
    }

    # Category multipliers
    _CAT_MULT = {
        FindingCategory.SECRET_EXPOSURE:    1.5,
        FindingCategory.CREDENTIAL_FILE:    1.4,
        FindingCategory.PII_EXPOSURE:       1.2,
        FindingCategory.ARCHIVE_CONTENT:    1.1,
        FindingCategory.INFRASTRUCTURE_INF: 0.8,
        FindingCategory.METADATA_LEAKAGE:   0.6,
        FindingCategory.PUBLIC_ACCESS:      0.9,
        FindingCategory.COMPLIANCE:         0.7,
    }

    # Each further finding of the same rule contributes this fraction of the previous one.
    _RULE_DECAY = 0.6

    _CLOUD_CRED_RULES = (
        "AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GCP_SERVICE_ACCOUNT_KEY", "AZURE_STORAGE_KEY",
        "GITHUB_PAT", "GITLAB_TOKEN", "STRIPE_SECRET_KEY", "DIGITALOCEAN_TOKEN", "VAULT_TOKEN",
        "PRIVATE_KEY", "DATABASE_URL", "CONNECTION_STRING_PASSWORD", "AGE_SECRET_KEY",
    )

    def compute(self, findings: List[Finding], container: ContainerInfo) -> float:
        if not findings:
            # Public listing with no findings still carries baseline risk
            return 2.0 if container.is_public else 0.5

        by_rule: Dict[str, List[float]] = defaultdict(list)
        for f in findings:
            weight = self._SEV_WEIGHTS.get(f.severity, 0.0)
            mult   = self._CAT_MULT.get(f.category, 1.0)
            conf   = f.confidence if f.confidence > 0 else 0.5
            by_rule[f.rule_name].append(weight * mult * (0.4 + 0.6 * min(conf, 1.0)))

        raw = 0.0
        for weights in by_rule.values():
            for i, w in enumerate(sorted(weights, reverse=True)):
                if i > 40:
                    break
                raw += w * (self._RULE_DECAY ** i)

        # Normalise to 0–10 scale using a soft cap
        score = 10 * (1 - math.exp(-raw / 9))

        confident = [f for f in findings if f.confidence >= 0.7]

        # Floor: a confident critical credential is never a "moderate" result.
        if any(
            f.severity == Severity.CRITICAL
            and f.category in (FindingCategory.SECRET_EXPOSURE, FindingCategory.CREDENTIAL_FILE)
            and f.scanner not in ("MisconfigAnalyzer",)
            for f in confident
        ):
            score = max(score, 7.5)

        # Floor: validated cloud / provider credentials → push toward 10
        if any(
            f.rule_name in self._CLOUD_CRED_RULES and f.severity == Severity.CRITICAL
            for f in confident
        ):
            score = max(score, 8.5)

        # Floor: compound exposures (complete credential pairs, secrets files)
        if any(f.rule_name.startswith("COMPOUND_") and f.severity == Severity.CRITICAL for f in findings):
            score = max(score, 9.0)

        # Ceiling: nothing above Low severity cannot be a high-risk result
        if all(f.severity in (Severity.LOW, Severity.INFORMATIONAL) for f in findings):
            score = min(score, 3.5 if container.is_public else 2.5)

        if not container.is_public:
            score *= 0.85

        return round(min(score, 10.0), 2)
