"""
cloudaudit.intelligence.terraform_scanner — Dedicated Terraform State Scanner

Terraform ``.tfstate`` files are JSON documents, and secrets stored inside
them (database passwords, cloud provider keys, connection strings generated
by providers) live at very well-defined locations:

    {
      "resources": [
        {
          "mode": "managed",
          "type": "aws_db_instance",
          "name": "primary",
          "instances": [
            {"attributes": {"password": "...", "endpoint": "...", ...}}
          ]
        }
      ]
    }

Rather than relying solely on generic regex scanning of the raw text (which
still runs via ``SecretScanner``), this module walks the actual
``resources[].instances[].attributes`` structure and flags sensitive
attribute *names* regardless of the value's shape/entropy — Terraform
provider attributes for secrets are frequently short, low-entropy, or
otherwise unlikely to trip the generic entropy-gated patterns (e.g. a
plain-text ``master_password = "hunter2"``).

Each finding is tagged with the originating resource address
(``<type>.<name>`` or ``data.<type>.<name>``, with the instance index/key
appended for `count`/`for_each` resources) so analysts can locate the exact
resource block in the Terraform configuration.

All matched values are redacted before being stored in the Finding — the
raw secret value is never persisted or logged, consistent with the rest of
the scanner suite.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, List

from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.utils.helpers import redact, url_filename

logger = logging.getLogger("cloudaudit.terraform_scanner")

# Attribute *names* (not values) that indicate sensitive content regardless
# of the value's entropy/shape.
_SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|private_key|access_key|secret_key|"
    r"api_key|api_token|auth_token|client_secret|connection_string|conn_str|"
    r"credential|token|master_password|admin_password)"
)

# Attribute names that are sensitive-*sounding* but structurally never hold
# a secret value in common providers — excluded to reduce false positives.
_KEY_ALLOWLIST = {
    "password_length", "password_reset_required", "secret_count",
    "token_expiry", "key_name", "key_id", "kms_key_id", "key_algorithm",
}

MAX_WALK_DEPTH = 12


class TerraformStateScanner:
    """Parses ``.tfstate`` JSON and flags sensitive resource attributes."""

    def scan(self, content: str, file_url: str) -> List[Finding]:
        try:
            data = json.loads(content)
        except (json.JSONDecodeError, ValueError, TypeError):
            return []

        if not isinstance(data, dict) or "resources" not in data:
            return []  # Not a recognisable tfstate document

        findings: List[Finding] = []
        resources = data.get("resources") or []
        if not isinstance(resources, list):
            return []

        for resource in resources:
            if not isinstance(resource, dict):
                continue
            mode  = resource.get("mode", "managed")
            rtype = resource.get("type", "unknown_resource")
            name  = resource.get("name", "unknown")

            instances = resource.get("instances") or []
            if not isinstance(instances, list):
                continue

            for instance in instances:
                if not isinstance(instance, dict):
                    continue
                attrs = instance.get("attributes")
                if not isinstance(attrs, dict):
                    continue

                address = f"{rtype}.{name}" if mode == "managed" else f"data.{rtype}.{name}"
                index_key = instance.get("index_key")
                if index_key is not None:
                    address += f"[{index_key}]"

                findings.extend(self._walk(attrs, address, file_url))

        if findings:
            logger.info(
                "TerraformStateScanner: %d sensitive attribute(s) found in %s",
                len(findings), file_url,
            )
        return findings

    # ── Recursive attribute walk ───────────────────────────────────────────────

    def _walk(self, node: Any, address: str, file_url: str, prefix: str = "", depth: int = 0) -> List[Finding]:
        findings: List[Finding] = []
        if depth > MAX_WALK_DEPTH:
            return findings

        if isinstance(node, dict):
            for key, value in node.items():
                path = f"{prefix}.{key}" if prefix else str(key)
                if isinstance(value, (dict, list)):
                    findings.extend(self._walk(value, address, file_url, path, depth + 1))
                elif isinstance(value, str) and value.strip():
                    if self._is_sensitive_key(key):
                        findings.append(self._make_finding(address, path, value, file_url))
        elif isinstance(node, list):
            for i, item in enumerate(node):
                findings.extend(self._walk(item, address, file_url, f"{prefix}[{i}]", depth + 1))

        return findings

    @staticmethod
    def _is_sensitive_key(key: str) -> bool:
        key_lower = str(key).lower()
        if key_lower in _KEY_ALLOWLIST:
            return False
        return bool(_SENSITIVE_KEY_RE.search(key_lower))

    @staticmethod
    def _make_finding(address: str, attr_path: str, value: str, file_url: str) -> Finding:
        return Finding(
            file_url=file_url,
            file_name=url_filename(file_url),
            file_type=FileType.TERRAFORM,
            category=FindingCategory.CREDENTIAL_FILE,
            rule_name="TERRAFORM_STATE_SENSITIVE_ATTRIBUTE",
            description=(
                f"Sensitive attribute '{attr_path}' exposed in plaintext inside "
                f"Terraform state resource {address}"
            ),
            severity=Severity.CRITICAL,
            match=redact(value),
            context=f"resource address: {address}  |  attribute: {attr_path}",
            recommendation=(
                "Terraform state files routinely contain plaintext secrets generated or "
                "passed to providers. Never store .tfstate in publicly exposed storage — "
                "use a remote backend with encryption and access control (e.g. Terraform "
                "Cloud, S3 with SSE-KMS + bucket policy, Azure Storage with private "
                "endpoints). Rotate any credential found here immediately."
            ),
            compliance_refs=["NIST IA-5", "CIS 2.1.5", "SOC2 CC6.7"],
            confidence=0.9,
            scanner="TerraformStateScanner",
        )
