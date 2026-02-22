"""
cloudaudit — Risk Scoring Engine

Computes a 0–10 composite risk score based on:
  - Finding severity distribution
  - Presence of credential types (cloud keys vs. generic)
  - Container type (S3 public vs. Azure private-but-listed)
  - Archive findings (secondary exposure vectors)
  - Compliance reference coverage
"""

from __future__ import annotations

from typing import List

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
        FindingCategory.COMPLIANCE:         0.5,
    }

    def compute(self, findings: List[Finding], container: ContainerInfo) -> float:
        if not findings:
            # Public listing with no findings still carries baseline risk
            return 2.0 if container.is_public else 0.5

        raw = 0.0
        for f in findings:
            weight = self._SEV_WEIGHTS.get(f.severity, 0.0)
            mult   = self._CAT_MULT.get(f.category, 1.0)
            raw   += weight * mult

        # Normalise to 0–10 scale using a soft cap
        import math
        score = 10 * (1 - math.exp(-raw / 8))

        # Bonus: if critical cloud credential findings exist → push toward 10
        has_cloud_creds = any(
            f.rule_name in ("AWS_ACCESS_KEY", "AWS_SECRET_KEY", "GCP_SERVICE_ACCOUNT_KEY",
                            "AZURE_STORAGE_KEY", "GITHUB_PAT")
            and f.severity == Severity.CRITICAL
            for f in findings
        )
        if has_cloud_creds:
            score = max(score, 8.5)

        return round(min(score, 10.0), 2)
