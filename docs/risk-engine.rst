Risk Engine
===========

Source: ``intelligence/risk_scorer.py``

CloudAudit computes a composite 0–10 risk score that provides a single, defensible
measure of the overall security exposure of a scanned container.

Scoring Formula
---------------

.. code-block:: text

   raw_score = sum(
       severity_weight[finding.severity]
       × category_multiplier[finding.category]
       for each finding
   )

   risk_score = 10 × (1 - exp(-raw_score / 8))

The exponential saturation function ensures:

* Small numbers of low-severity findings produce a proportionally low score
* Large accumulations of findings approach (but never exceed) 10
* A single Critical finding in a high-multiplier category can produce a score of 4–6

Severity Weights
----------------

.. list-table::
   :header-rows: 1
   :widths: 30 20 50

   * - Severity
     - Weight
     - Rationale
   * - Critical
     - 4.0
     - Immediate compromise risk — credential exposure, PII
   * - High
     - 2.0
     - Significant risk — likely exploitable, needs 24h remediation
   * - Medium
     - 0.8
     - Moderate risk — worth remediating in next sprint
   * - Low
     - 0.2
     - Informational — background noise, fix opportunistically
   * - Informational
     - 0.0
     - No direct risk — included for completeness

Category Multipliers
--------------------

.. list-table::
   :header-rows: 1
   :widths: 35 20 45

   * - Category
     - Multiplier
     - Description
   * - SECRET_EXPOSURE
     - 1.5×
     - Credentials, API keys, tokens in file content
   * - CREDENTIAL_FILE
     - 1.4×
     - Entire credential file exposed (.env, id_rsa)
   * - PII_EXPOSURE
     - 1.2×
     - Personally identifiable information
   * - ARCHIVE_CONTENT
     - 1.1×
     - Secret found inside a downloaded archive
   * - PUBLIC_ACCESS
     - 0.9×
     - Container-level misconfiguration
   * - INFRASTRUCTURE_INFO
     - 0.8×
     - Internal IPs, hostnames, service topology
   * - METADATA_LEAKAGE
     - 0.6×
     - EXIF data, server headers, auxiliary info

Override Conditions
-------------------

**Cloud credential floor**: If any finding from the following rule set is Critical severity,
the risk score floor is raised to **8.5**:

* ``AWS_ACCESS_KEY``, ``AWS_SECRET_KEY``
* ``GCP_SERVICE_ACCOUNT_KEY``
* ``AZURE_STORAGE_KEY``
* ``GITHUB_PAT``, ``GITLAB_TOKEN``

Rationale: These findings have direct account takeover potential. A score below 8.5 would
understate the business impact.

**Public container baseline**: A container with public access configured but no findings
(possible for correctly structured public data buckets) scores at least **2.0** to reflect
the inherent exposure risk.

Score Interpretation
--------------------

.. list-table::
   :header-rows: 1
   :widths: 20 20 60

   * - Range
     - Rating
     - Recommended Action
   * - 8.0 – 10.0
     - CRITICAL
     - Incident response procedures. Rotate all affected credentials immediately.
   * - 6.0 – 7.9
     - HIGH
     - Remediate within 24–72 hours. CISO notification recommended.
   * - 4.0 – 5.9
     - ELEVATED
     - Remediate within the current sprint. Review access controls.
   * - 2.0 – 3.9
     - MODERATE
     - Schedule remediation. Review bucket policies.
   * - 0.0 – 1.9
     - LOW
     - Monitor. Verify configuration at next review cycle.

Example Calculations
--------------------

**Single exposed AWS access key (Critical, SECRET_EXPOSURE):**

.. code-block:: text

   raw = 4.0 × 1.5 = 6.0
   score = 10 × (1 - e^(-6.0/8)) = 10 × (1 - 0.472) = 5.28
   → Override applied (cloud credential): score = max(5.28, 8.5) = 8.5

**Public bucket with 5 High findings (CREDENTIAL_FILE) and 10 Medium findings:**

.. code-block:: text

   raw = (5 × 2.0 × 1.4) + (10 × 0.8 × 0.9) = 14.0 + 7.2 = 21.2
   score = 10 × (1 - e^(-21.2/8)) = 10 × (1 - 0.072) = 9.28

AI Confidence Integration
--------------------------

When an AI provider is configured and anomaly scoring is performed, the anomaly score
from the ``AnomalyScorer`` is blended into per-file risk assessment:

.. code-block:: python

   # 60% heuristic deterministic, 40% AI anomaly score
   blended = 0.6 * heuristic_score + 0.4 * ai_score

This blended score is used for per-file prioritisation within the report's
"Risk Breakdown" section but does not affect the global composite score.
