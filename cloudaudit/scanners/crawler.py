"""
cloudaudit — Recursive File Crawler

Supports:
  • AWS S3 XML listing (with IsTruncated / ContinuationToken pagination)
  • GCS XML listing (same schema, different namespace)
  • Azure Blob XML listing
  • Generic HTML directory listings (Apache, nginx, etc.)
  • CloudFront / CDN (falls back to HTML parsing)

Respects:
  • max_depth recursion limit
  • ignore_paths filters
  • file size filtering (via HEAD requests when sizes are in XML)
"""

from __future__ import annotations

import asyncio
import logging
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse

from cloudaudit.core.config import AuditConfig
from cloudaudit.core.constants import SKIP_DOWNLOAD_EXTENSIONS
from cloudaudit.core.models import ContainerType, ExposedFile, FileType
from cloudaudit.scanners.file_classifier import FileClassifier
from cloudaudit.utils.http_client import HTTPClient

logger = logging.getLogger("cloudaudit.crawler")

# ── S3 / GCS XML namespaces ───────────────────────────────────────────────────
_S3_NS = "http://s3.amazonaws.com/doc/2006-03-01/"

# ── HTML link extraction ──────────────────────────────────────────────────────
_HREF_RE = re.compile(r'<a[^>]+href=["\']([^"\'?#][^"\']*)["\']', re.IGNORECASE)


class FileCrawler:
    """
    Recursively discover all objects/files exposed in a cloud storage endpoint.

    Strategy selection is automatic based on the detected container type.
    """

    def __init__(self, config: AuditConfig) -> None:
        self._config    = config
        self._classifier = FileClassifier()
        self._discovered: List[ExposedFile] = []
        self._visited_urls: Set[str] = set()

    async def crawl(
        self,
        http: HTTPClient,
        base_url: str,
        container_type: ContainerType,
    ) -> List[ExposedFile]:
        """
        Entry point. Returns list of all discovered ExposedFile objects.
        """
        self._discovered = []
        self._visited_urls = set()

        if container_type in (ContainerType.AWS_S3, ContainerType.GCS):
            await self._crawl_s3_xml(http, base_url)
        elif container_type == ContainerType.AZURE_BLOB:
            await self._crawl_azure_xml(http, base_url)
        else:
            # Generic HTML directory listing or CloudFront
            await self._crawl_html(http, base_url, depth=0)

        logger.info("Crawler finished: %d files discovered", len(self._discovered))
        return self._discovered

    # ── AWS S3 / GCS XML crawler ───────────────────────────────────────────────

    async def _crawl_s3_xml(self, http: HTTPClient, base_url: str) -> None:
        """
        Parse S3 ListBucketResult XML.
        Handles IsTruncated=true pagination automatically via ContinuationToken.
        Also uses CommonPrefixes for virtual folder enumeration.
        """
        continuation_token: Optional[str] = None
        prefixes_to_crawl: list[str] = [""]   # start at root prefix

        processed_prefixes: Set[str] = set()

        while prefixes_to_crawl:
            prefix = prefixes_to_crawl.pop(0)
            if prefix in processed_prefixes:
                continue
            processed_prefixes.add(prefix)

            continuation_token = None  # reset per prefix
            while True:
                # Build the listing URL
                params = "list-type=2&delimiter=%2F"
                if prefix:
                    params += f"&prefix={prefix}"
                if continuation_token:
                    params += f"&continuation-token={continuation_token}"

                list_url = f"{base_url.rstrip('/')}/?{params}"
                logger.debug("S3 listing: %s", list_url)

                try:
                    resp = await http.get(list_url)
                    if resp.status != 200:
                        logger.warning("S3 listing returned HTTP %d for prefix=%r", resp.status, prefix)
                        break
                    body = await resp.text(errors="replace")
                except Exception as exc:
                    logger.debug("S3 listing error (prefix=%r): %s", prefix, exc)
                    break

                is_truncated, token, keys, sub_prefixes = self._parse_s3_xml(body, base_url)

                for ef in keys:
                    if self._should_include(ef):
                        self._discovered.append(ef)

                # Queue sub-prefixes (virtual folders) for recursive crawling
                for sp in sub_prefixes:
                    if sp not in processed_prefixes:
                        prefixes_to_crawl.append(sp)

                if is_truncated and token:
                    continuation_token = token
                else:
                    break

    def _parse_s3_xml(
        self, body: str, base_url: str
    ) -> Tuple[bool, Optional[str], List[ExposedFile], List[str]]:
        """
        Returns (is_truncated, continuation_token, [ExposedFile], [sub_prefixes]).
        Handles both old-style (Marker) and new ListObjectsV2 (ContinuationToken).
        """
        files: List[ExposedFile] = []
        sub_prefixes: List[str] = []
        is_truncated = False
        token: Optional[str] = None

        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            logger.debug("XML parse error: %s", exc)
            return False, None, files, sub_prefixes

        # Detect namespace
        tag = root.tag
        ns = ""
        if tag.startswith("{"):
            ns = tag[1:].split("}")[0]

        def _find(el: ET.Element, name: str) -> Optional[ET.Element]:
            return el.find(f"{{{ns}}}{name}" if ns else name)

        def _findall(el: ET.Element, name: str) -> list[ET.Element]:
            return el.findall(f"{{{ns}}}{name}" if ns else name)

        def _text(el: ET.Element, name: str) -> str:
            child = _find(el, name)
            return child.text.strip() if child is not None and child.text else ""

        # IsTruncated
        trunc_el = _find(root, "IsTruncated")
        if trunc_el is not None and trunc_el.text:
            is_truncated = trunc_el.text.strip().lower() == "true"

        # ContinuationToken (v2) or NextMarker (v1)
        token_el = _find(root, "NextContinuationToken") or _find(root, "NextMarker")
        if token_el is not None and token_el.text:
            token = token_el.text.strip()

        # Contents (files)
        for content in _findall(root, "Contents"):
            key  = _text(content, "Key")
            size = _text(content, "Size")
            mtime= _text(content, "LastModified")
            etag = _text(content, "ETag").strip('"')

            if not key or key.endswith("/"):
                continue   # skip directory markers

            url = self._key_to_url(base_url, key)
            ef  = ExposedFile(
                url=url,
                key=key,
                size_bytes=int(size) if size.isdigit() else 0,
                last_modified=mtime,
                file_type=self._classifier.classify(url),
                etag=etag,
            )
            files.append(ef)

        # CommonPrefixes (virtual directories → recurse into them)
        for cp in _findall(root, "CommonPrefixes"):
            prefix_el = _find(cp, "Prefix")
            if prefix_el is not None and prefix_el.text:
                sub_prefixes.append(prefix_el.text.strip())

        return is_truncated, token, files, sub_prefixes

    # ── Azure Blob XML crawler ─────────────────────────────────────────────────

    async def _crawl_azure_xml(self, http: HTTPClient, base_url: str) -> None:
        """Azure Blob listing uses ?restype=container&comp=list."""
        marker: Optional[str] = None
        while True:
            params = "restype=container&comp=list"
            if marker:
                params += f"&marker={marker}"
            list_url = f"{base_url.rstrip('/')}?{params}"
            try:
                resp = await http.get(list_url)
                if resp.status != 200:
                    break
                body = await resp.text(errors="replace")
            except Exception as exc:
                logger.debug("Azure listing error: %s", exc)
                break

            new_files, next_marker = self._parse_azure_xml(body, base_url)
            for ef in new_files:
                if self._should_include(ef):
                    self._discovered.append(ef)

            if next_marker:
                marker = next_marker
            else:
                break

    def _parse_azure_xml(
        self, body: str, base_url: str
    ) -> Tuple[List[ExposedFile], Optional[str]]:
        files: List[ExposedFile] = []
        next_marker: Optional[str] = None

        try:
            root = ET.fromstring(body)
        except ET.ParseError:
            return files, None

        blobs = root.find("Blobs")
        if blobs is None:
            return files, None

        for blob in blobs.findall("Blob"):
            name_el = blob.find("Name")
            if name_el is None or not name_el.text:
                continue
            key = name_el.text.strip()

            props = blob.find("Properties")
            size = 0
            mtime = ""
            if props is not None:
                size_el  = props.find("Content-Length")
                mtime_el = props.find("Last-Modified")
                size  = int(size_el.text) if size_el is not None and size_el.text else 0
                mtime = mtime_el.text if mtime_el is not None and mtime_el.text else ""

            url = self._key_to_url(base_url, key)
            files.append(ExposedFile(
                url=url,
                key=key,
                size_bytes=size,
                last_modified=mtime,
                file_type=self._classifier.classify(url),
            ))

        marker_el = root.find("NextMarker")
        if marker_el is not None and marker_el.text:
            next_marker = marker_el.text.strip()

        return files, next_marker

    # ── Generic HTML directory listing crawler ─────────────────────────────────

    async def _crawl_html(
        self, http: HTTPClient, url: str, depth: int
    ) -> None:
        """Recursively crawl an HTML directory listing (Apache/nginx style)."""
        if depth > self._config.max_depth:
            return
        if url in self._visited_urls:
            return
        self._visited_urls.add(url)

        try:
            resp = await http.get(url)
            if resp.status != 200:
                return
            html = await resp.text(errors="replace")
        except Exception as exc:
            logger.debug("HTML crawl error at %s: %s", url, exc)
            return

        files, dirs = self._parse_html_links(html, url)

        for file_url, key in files:
            ef = ExposedFile(
                url=file_url,
                key=key,
                file_type=self._classifier.classify(file_url),
            )
            if self._should_include(ef):
                self._discovered.append(ef)

        tasks = [
            self._crawl_html(http, dir_url, depth + 1)
            for dir_url in dirs
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    def _parse_html_links(
        self, html: str, base_url: str
    ) -> Tuple[List[Tuple[str, str]], List[str]]:
        """Return ([(file_url, key), ...], [dir_url, ...])."""
        files: List[Tuple[str, str]] = []
        dirs:  List[str] = []
        seen:  Set[str]  = set()
        base_parsed = urlparse(base_url)

        for m in _HREF_RE.finditer(html):
            href = m.group(1).strip()
            if href in ("", "../", "./", "#") or href in seen:
                continue
            if any(p in href for p in self._config.ignore_paths):
                continue
            # Skip absolute links to different hosts
            parsed = urlparse(href)
            if parsed.netloc and parsed.netloc != base_parsed.netloc:
                continue
            seen.add(href)

            full_url = urljoin(base_url, href)
            key      = urlparse(full_url).path.lstrip("/")

            if href.endswith("/"):
                dirs.append(full_url)
            else:
                files.append((full_url, key))

        return files, dirs

    # ── Helpers ────────────────────────────────────────────────────────────────

    def _key_to_url(self, base_url: str, key: str) -> str:
        return base_url.rstrip("/") + "/" + key.lstrip("/")

    def _should_include(self, ef: ExposedFile) -> bool:
        """Return True if this file should be included in the audit scope."""
        ext = Path(ef.key).suffix.lower()

        # Skip binary media — no content to analyse
        if ext in SKIP_DOWNLOAD_EXTENSIONS:
            return False

        # Skip configured ignore paths
        if any(p in ef.key for p in self._config.ignore_paths):
            return False

        # If caller specified explicit extension allow-list, enforce it
        if self._config.extensions:
            allowed = {e.lstrip(".") for e in self._config.extensions}
            if ext.lstrip(".") not in allowed:
                return False

        # Skip files that are too large (we know size from XML listing)
        if ef.size_bytes and ef.size_bytes > self._config.max_file_size:
            logger.debug("Skipping %s — too large (%d bytes)", ef.key, ef.size_bytes)
            return False

        return True
