"""
cloudaudit — Container Type Auto-Detector

Inspects the HTTP response (headers + body) from the target URL and
determines the cloud storage provider, container name, and region without
requiring the user to specify them manually.

Detection uses:
  1. HTTP response headers  (x-amz-*, x-goog-*, x-ms-*, Server)
  2. XML namespace from the list response body
  3. Hostname pattern matching
  4. Response body element fingerprinting (<ListBucketResult>, <EnumerationResults>, etc.)
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from typing import Optional
from urllib.parse import urlparse

import aiohttp

from cloudaudit.core.constants import (
    AWS_S3_HEADERS,
    AWS_S3_NAMESPACES,
    AZURE_HEADERS,
    GCS_HEADERS,
)
from cloudaudit.core.models import ContainerInfo, ContainerType

logger = logging.getLogger("cloudaudit.detector")

# ── Hostname regex patterns ────────────────────────────────────────────────────
_AWS_S3_HOST_RE   = re.compile(
    r"(?:(?P<bucket>[^.]+)\.)?s3[.-](?P<region>[^.]+)\.amazonaws\.com"
)
_AWS_CF_HOST_RE   = re.compile(r"cloudfront\.net$")
_GCS_HOST_RE      = re.compile(r"storage\.googleapis\.com|(?P<bucket>[^.]+)\.storage\.googleapis\.com")
_AZURE_HOST_RE    = re.compile(r"(?P<account>[^.]+)\.blob\.core\.windows\.net")


class ContainerDetector:
    """
    Analyse a URL + HTTP response to identify the cloud storage provider
    and extract container/bucket metadata automatically.
    """

    def detect(
        self,
        url: str,
        response: aiohttp.ClientResponse,
        body: str,
    ) -> ContainerInfo:
        headers = {k.lower(): v for k, v in response.headers.items()}
        parsed  = urlparse(url)
        host    = parsed.hostname or ""

        info = ContainerInfo(raw_url=url)

        # ── 1. Try header-based detection first (fastest) ──────────────────────
        if any(h in headers for h in AWS_S3_HEADERS):
            info.container_type = ContainerType.AWS_S3
        elif any(h in headers for h in GCS_HEADERS):
            info.container_type = ContainerType.GCS
        elif any(h in headers for h in AZURE_HEADERS):
            info.container_type = ContainerType.AZURE_BLOB

        # ── 2. Hostname pattern matching ───────────────────────────────────────
        if info.container_type == ContainerType.UNKNOWN:
            m = _AWS_S3_HOST_RE.search(host)
            if m:
                info.container_type = ContainerType.AWS_S3
                if m.group("region"):
                    info.region = m.group("region")
                if m.group("bucket"):
                    info.container_name = m.group("bucket")

            elif _AWS_CF_HOST_RE.search(host):
                info.container_type = ContainerType.CLOUDFRONT

            elif _GCS_HOST_RE.search(host):
                info.container_type = ContainerType.GCS
                gm = _GCS_HOST_RE.search(host)
                if gm and gm.group("bucket"):
                    info.container_name = gm.group("bucket")

            elif _AZURE_HOST_RE.search(host):
                info.container_type = ContainerType.AZURE_BLOB
                am = _AZURE_HOST_RE.search(host)
                if am:
                    info.container_name = am.group("account")

        # ── 3. XML body fingerprinting (most reliable for content) ────────────
        if body.strip().startswith("<?xml") or body.strip().startswith("<"):
            self._parse_xml_body(body, info)

        # ── 4. HTML open directory detection ─────────────────────────────────
        if info.container_type == ContainerType.UNKNOWN:
            if re.search(r"<title>Index of", body, re.IGNORECASE):
                info.container_type = ContainerType.OPEN_DIRECTORY
            elif re.search(r"<a\s+href=", body, re.IGNORECASE):
                info.container_type = ContainerType.GENERIC

        # ── 5. Fill in metadata from response headers ─────────────────────────
        info.server_header = headers.get("server", "")
        if region := headers.get("x-amz-bucket-region", ""):
            info.region = region
        info.extra_headers = {
            k: v for k, v in headers.items()
            if k in ("server", "content-type", "x-amz-bucket-region",
                     "x-goog-stored-content-encoding", "x-ms-version")
        }

        # ── 6. Assess public access ───────────────────────────────────────────
        # If we got a 200 with a listing body, it's definitively public
        info.is_public = (response.status == 200)
        if info.is_public and info.container_type == ContainerType.AWS_S3:
            info.notes.append(
                "S3 Block Public Access is NOT enabled — bucket listing is publicly accessible."
            )

        return info

    # ── XML parsing helpers ────────────────────────────────────────────────────

    def _parse_xml_body(self, body: str, info: ContainerInfo) -> None:
        """Extract container name and type from XML listing body."""
        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return

        tag = root.tag
        ns  = ""
        if tag.startswith("{"):
            ns, _, local = tag[1:].partition("}")
        else:
            local = tag

        # AWS S3: <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
        if local in ("ListBucketResult", "ListAllMyBucketsResult") or ns in AWS_S3_NAMESPACES:
            info.container_type = ContainerType.AWS_S3
            if not info.container_name:
                name_el = root.find(f"{{{ns}}}Name" if ns else "Name")
                if name_el is not None and name_el.text:
                    info.container_name = name_el.text.strip()
            region_el = root.find(f"{{{ns}}}BucketRegion" if ns else "BucketRegion")
            if region_el is not None and region_el.text:
                info.region = region_el.text.strip()

        # GCS: <ListBucketResult> (GCS uses same XML schema as S3 in XML API)
        elif local == "ListBucketResult":
            # Could be GCS or S3-compatible — rely on header detection above
            if not info.container_name:
                name_el = root.find("Name")
                if name_el is not None and name_el.text:
                    info.container_name = name_el.text.strip()

        # Azure Blob: <EnumerationResults ServiceEndpoint="...">
        elif local == "EnumerationResults":
            info.container_type = ContainerType.AZURE_BLOB
            # Azure puts container name in the ContainerName element
            cont_el = root.find("ContainerName")
            if cont_el is not None and cont_el.text:
                info.container_name = cont_el.text.strip()
            # Or from attribute on the root
            endpoint = root.get("ServiceEndpoint", "")
            if endpoint and not info.container_name:
                # e.g. https://myaccount.blob.core.windows.net/mycontainer/
                parts = [p for p in endpoint.rstrip("/").split("/") if p]
                if parts:
                    info.container_name = parts[-1]
