"""
cloudaudit.intelligence.aws_acl — AWS Bucket ACL / Policy Inspection

Optional, read-only enrichment: when boto3 is installed and AWS credentials
are available in the environment (env vars, shared credentials file, instance
role, etc.), this module calls three read-only S3 APIs —

    get_bucket_acl, get_bucket_policy, get_bucket_policy_status

— to confirm *why* a bucket is publicly exposed, beyond what an anonymous
HTTP crawl can see. No write/delete S3 API is ever called.

Gracefully no-ops (returns an empty list) if boto3 is not installed or no
credentials / permissions are available — this is a best-effort enrichment,
never a hard requirement of the scan.
"""

from __future__ import annotations

import json
import logging
from typing import List

from cloudaudit.core.models import Finding, FileType, FindingCategory, Severity

logger = logging.getLogger("cloudaudit.aws_acl")

_PUBLIC_GRANTEE_URIS = {
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
}


def is_available() -> bool:
    try:
        import boto3  # noqa: F401
        return True
    except ImportError:
        return False


def check_bucket(bucket_name: str, region: str = "", raw_url: str = "") -> List[Finding]:
    """
    Best-effort inspection of a bucket's ACL and policy using boto3.
    Returns an empty list (with a debug log) if unavailable for any reason.
    """
    if not bucket_name:
        return []

    try:
        import boto3
        from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError
    except ImportError:
        logger.info("--aws-acl-check requested but boto3 is not installed. "
                    "Run: pip install boto3 — skipping ACL/policy enrichment.")
        return []

    findings: List[Finding] = []
    try:
        client = boto3.client("s3", region_name=region or None)
    except Exception as exc:
        logger.info("Could not create boto3 S3 client: %s — skipping ACL/policy enrichment.", exc)
        return []

    # ── get_bucket_acl ──────────────────────────────────────────────────────
    try:
        acl = client.get_bucket_acl(Bucket=bucket_name)
        public_grants = []
        for grant in acl.get("Grants", []):
            grantee = grant.get("Grantee", {})
            uri = grantee.get("URI", "")
            if uri in _PUBLIC_GRANTEE_URIS:
                public_grants.append((uri.rsplit("/", 1)[-1], grant.get("Permission", "")))

        if public_grants:
            desc = ", ".join(f"{who}={perm}" for who, perm in public_grants)
            findings.append(_finding(
                bucket_name, raw_url, "AWS_ACL_PUBLIC_GRANT",
                f"Bucket ACL grants access to a public group: {desc}",
                Severity.CRITICAL,
                "Remove public ACL grants (aws s3api put-bucket-acl) and enable "
                "S3 Block Public Access at the account and bucket level.",
            ))
    except (ClientError, BotoCoreError, NoCredentialsError) as exc:
        logger.debug("get_bucket_acl failed for %s: %s", bucket_name, exc)
    except Exception as exc:
        logger.debug("Unexpected error calling get_bucket_acl for %s: %s", bucket_name, exc)

    # ── get_bucket_policy ───────────────────────────────────────────────────
    try:
        pol_resp = client.get_bucket_policy(Bucket=bucket_name)
        policy = json.loads(pol_resp.get("Policy", "{}"))
        wildcard_statements = []
        for stmt in policy.get("Statement", []):
            principal = stmt.get("Principal")
            is_wildcard = principal == "*" or (
                isinstance(principal, dict) and principal.get("AWS") in ("*", ["*"])
            )
            if is_wildcard and stmt.get("Effect") == "Allow":
                wildcard_statements.append(stmt.get("Sid", "(unnamed statement)"))

        if wildcard_statements:
            findings.append(_finding(
                bucket_name, raw_url, "AWS_POLICY_WILDCARD_PRINCIPAL",
                f"Bucket policy allows access to Principal: * in statement(s): "
                f"{', '.join(wildcard_statements)}",
                Severity.CRITICAL,
                "Restrict the bucket policy Principal to specific accounts/roles. "
                "Remove any 'Principal': '*' Allow statements unless intentionally public.",
            ))
    except (ClientError, BotoCoreError, NoCredentialsError) as exc:
        logger.debug("get_bucket_policy failed for %s: %s", bucket_name, exc)
    except Exception as exc:
        logger.debug("Unexpected error calling get_bucket_policy for %s: %s", bucket_name, exc)

    # ── get_bucket_policy_status ────────────────────────────────────────────
    try:
        status = client.get_bucket_policy_status(Bucket=bucket_name)
        if status.get("PolicyStatus", {}).get("IsPublic"):
            findings.append(_finding(
                bucket_name, raw_url, "AWS_POLICY_STATUS_PUBLIC",
                "AWS reports this bucket's policy status as publicly accessible "
                "(s3:GetBucketPolicyStatus -> IsPublic=true).",
                Severity.HIGH,
                "Review the bucket policy and ACLs; enable S3 Block Public Access "
                "unless public access is explicitly required.",
            ))
    except (ClientError, BotoCoreError, NoCredentialsError) as exc:
        logger.debug("get_bucket_policy_status failed for %s: %s", bucket_name, exc)
    except Exception as exc:
        logger.debug("Unexpected error calling get_bucket_policy_status for %s: %s", bucket_name, exc)

    return findings


def _finding(bucket_name, raw_url, rule, description, severity, recommendation) -> Finding:
    return Finding(
        file_url=raw_url or f"s3://{bucket_name}",
        file_name=bucket_name,
        file_type=FileType.OTHER,
        category=FindingCategory.PUBLIC_ACCESS,
        rule_name=rule,
        description=description,
        severity=severity,
        match=f"[{bucket_name}]",
        recommendation=recommendation,
        compliance_refs=["CIS 2.1", "NIST SC-7", "SOC2 CC6.1"],
        confidence=0.97,
        scanner="AWSBucketACLInspector",
    )
