"""
cloudaudit.intelligence.aws_inventory — owner-side S3 inventory (--aws-inventory)

An anonymous crawl can only audit a bucket whose *listing* is public. The more
common real-world misconfiguration is quieter: the bucket is not listable, but
individual objects in it are publicly readable (object ACLs, a policy scoped to
a prefix, a forgotten "make public"). Nobody can enumerate them from outside —
but anyone holding a URL can read them, and an anonymous audit sees nothing.

With ``--aws-inventory`` the bucket owner's own AWS credentials (environment,
shared credentials file, SSO, instance role — whatever boto3 resolves) are
used for exactly two read-only calls:

    get_bucket_location, list_objects_v2

The engine then checks each listed object with an unauthenticated HEAD request,
and analyses the content of the ones that are publicly readable exactly as a
normal scan would. Private objects are counted, never downloaded.

No write or delete API is ever called. This only works on buckets the active
AWS identity is allowed to list.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, List, Optional, Tuple
from urllib.parse import quote, urlparse

from cloudaudit.core.exceptions import AuditError

logger = logging.getLogger("cloudaudit.aws_inventory")

DEFAULT_MAX_OBJECTS = 5000

_BUCKET_RE = r"[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9]"
_VHOST_RE = re.compile(
    rf"^(?P<bucket>{_BUCKET_RE})\.s3[.-](?:(?P<region>[a-z]{{2}}(?:-gov)?-[a-z]+-\d)\.)?amazonaws\.com(?:\.cn)?$"
)
_PATH_HOST_RE = re.compile(r"^s3[.-](?:(?P<region>[a-z]{2}(?:-gov)?-[a-z]+-\d)\.)?amazonaws\.com(?:\.cn)?$")


@dataclass
class BucketInventory:
    bucket:    str
    region:    str
    prefix:    str = ""
    objects:   List[dict] = field(default_factory=list)   # {"key", "size", "last_modified", "etag"}
    truncated: bool = False                               # stopped at max_objects


def is_available() -> bool:
    try:
        import boto3  # noqa: F401
        return True
    except ImportError:
        return False


def parse_bucket(url: str) -> Optional[Tuple[str, str, str]]:
    """
    ``(bucket, prefix, region_hint)`` from an S3 reference, or None.

    Accepts ``s3://bucket/prefix``, virtual-hosted URLs
    (``https://bucket.s3.eu-west-1.amazonaws.com/prefix``) and path-style URLs
    (``https://s3.eu-west-1.amazonaws.com/bucket/prefix``).
    """
    if not url:
        return None
    parsed = urlparse(url.strip())
    host = (parsed.hostname or "").lower()
    path = parsed.path.lstrip("/")

    if parsed.scheme == "s3":
        bucket = (parsed.netloc or "").lower()
        return (bucket, path, "") if re.fullmatch(_BUCKET_RE, bucket) else None

    m = _VHOST_RE.match(host)
    if m:
        return m.group("bucket"), path, m.group("region") or ""
    m = _PATH_HOST_RE.match(host)
    if m and path:
        bucket, _, prefix = path.partition("/")
        if re.fullmatch(_BUCKET_RE, bucket.lower()):
            return bucket.lower(), prefix, m.group("region") or ""
    return None


def bucket_url(bucket: str, region: str) -> str:
    """Canonical HTTPS endpoint of a bucket (path-style when the name contains dots)."""
    region = region or "us-east-1"
    if "." in bucket:           # dotted names break the wildcard TLS certificate
        return f"https://s3.{region}.amazonaws.com/{bucket}/"
    return f"https://{bucket}.s3.{region}.amazonaws.com/"


def object_url(bucket: str, region: str, key: str) -> str:
    return bucket_url(bucket, region) + quote(key, safe="/~")


def _normalise_region(location: Optional[str]) -> str:
    if not location:
        return "us-east-1"              # the API returns null for us-east-1
    return "eu-west-1" if location == "EU" else location


def list_bucket(
    bucket: str,
    prefix: str = "",
    max_objects: int = DEFAULT_MAX_OBJECTS,
    client: Any = None,
) -> BucketInventory:
    """
    List a bucket with the caller's own AWS credentials (read-only).

    Raises ``AuditError`` with an actionable message when boto3 is missing, no
    credentials resolve, or the identity may not list the bucket.
    """
    if client is None:
        try:
            import boto3
        except ImportError as exc:
            raise AuditError("--aws-inventory requires boto3. Run: pip install cloudaudit[aws]") from exc
        client = boto3.client("s3")

    try:
        location = client.get_bucket_location(Bucket=bucket).get("LocationConstraint")
    except Exception as exc:
        raise AuditError(_explain(exc, bucket, "read the location of")) from exc
    inventory = BucketInventory(bucket=bucket, region=_normalise_region(location), prefix=prefix)

    try:
        paginator = client.get_paginator("list_objects_v2")
        kwargs = {"Bucket": bucket, "PaginationConfig": {"PageSize": 1000}}
        if prefix:
            kwargs["Prefix"] = prefix
        for page in paginator.paginate(**kwargs):
            for obj in page.get("Contents", []) or []:
                key = obj.get("Key", "")
                if not key or key.endswith("/"):        # folder placeholder objects
                    continue
                if len(inventory.objects) >= max_objects:
                    inventory.truncated = True
                    return inventory
                inventory.objects.append({
                    "key":           key,
                    "size":          int(obj.get("Size", 0) or 0),
                    "last_modified": str(obj.get("LastModified", "") or ""),
                    "etag":          str(obj.get("ETag", "") or "").strip('"'),
                })
    except AuditError:
        raise
    except Exception as exc:
        raise AuditError(_explain(exc, bucket, "list")) from exc
    return inventory


def _explain(exc: Exception, bucket: str, action: str) -> str:
    name = type(exc).__name__
    code = ""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = str(response.get("Error", {}).get("Code", ""))
    if name in ("NoCredentialsError", "PartialCredentialsError") or "credentials" in str(exc).lower():
        return ("--aws-inventory: no AWS credentials were found. Configure them the usual way "
                "(AWS_PROFILE, `aws sso login`, environment variables or an instance role).")
    if code in ("AccessDenied", "403", "AllAccessDisabled"):
        return (f"--aws-inventory: the active AWS identity is not allowed to {action} bucket '{bucket}'. "
                "This mode only works on buckets you own or administer (needs s3:ListBucket and s3:GetBucketLocation).")
    if code in ("NoSuchBucket", "404"):
        return f"--aws-inventory: bucket '{bucket}' does not exist."
    return f"--aws-inventory: could not {action} bucket '{bucket}' ({name}{': ' + code if code else ''})."
