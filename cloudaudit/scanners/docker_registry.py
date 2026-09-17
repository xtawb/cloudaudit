"""
cloudaudit.scanners.docker_registry — Read-Only Docker Registry Layer Scanner

Implements just enough of the Docker Registry HTTP API v2 (distribution spec)
to:
  1. Resolve `registry/image:tag` to a registry host + repository + reference.
  2. Fetch the image manifest (following manifest lists / OCI indexes to a
     single-platform manifest).
  3. Download each layer blob (size-capped) via the read-only HTTPClient.
  4. Extract layer contents with the existing ArchiveExtractor (same zip-slip /
     decompression-bomb protections used for regular archives).
  5. Run the existing SecretScanner over extracted text files.

Only HTTP GET is ever issued — no image is pulled with a container runtime,
nothing is executed, and no registry write/delete endpoint is used.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from cloudaudit.core.constants import DEFAULT_DOCKER_REGISTRY, MAX_DOCKER_LAYER_SIZE
from cloudaudit.core.models import FileType, Finding
from cloudaudit.scanners.archive_extractor import ArchiveExtractor
from cloudaudit.scanners.file_classifier import FileClassifier
from cloudaudit.scanners.secret_scanner import SecretScanner
from cloudaudit.utils.http_client import HTTPClient

logger = logging.getLogger("cloudaudit.docker_registry")

_MANIFEST_ACCEPT = ", ".join([
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v1+json",
])

_LAYER_MEDIA_TYPES = {
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.oci.image.layer.v1.tar",
}


@dataclass
class DockerScanSummary:
    image_ref:      str
    registry:       str
    repository:     str
    reference:      str
    manifest_digest: str = ""
    layers_scanned: int = 0
    layers_skipped: int = 0
    files_scanned:  int = 0
    errors:         List[str] = field(default_factory=list)


def parse_image_ref(ref: str) -> Tuple[str, str, str]:
    """
    Parse `registry/repo:tag` (or `repo:tag`, `repo`, `repo@sha256:...`) into
    (registry_host, repository, reference).
    """
    ref = ref.strip()
    digest_ref: Optional[str] = None
    if "@" in ref:
        ref, _, digest_ref = ref.partition("@")

    if "/" in ref:
        first, remainder = ref.split("/", 1)
    else:
        first, remainder = "", ref

    if first and ("." in first or ":" in first or first == "localhost"):
        registry = first
        repo_and_tag = remainder
    else:
        registry = DEFAULT_DOCKER_REGISTRY
        repo_and_tag = ref
        if "/" not in repo_and_tag:
            repo_and_tag = "library/" + repo_and_tag

    tag = "latest"
    last_segment = repo_and_tag.rsplit("/", 1)[-1]
    if ":" in last_segment:
        repo, _, tag = repo_and_tag.rpartition(":")
    else:
        repo = repo_and_tag

    reference = f"sha256:{digest_ref}" if digest_ref else tag
    if digest_ref and digest_ref.startswith("sha256:"):
        reference = digest_ref

    return registry, repo, reference


class DockerRegistryClient:
    """Minimal read-only Docker Registry v2 API client."""

    def __init__(self, http: HTTPClient, registry: str, repository: str) -> None:
        self._http = http
        self._registry = registry
        self._repository = repository
        self._token: Optional[str] = None

    @property
    def _base(self) -> str:
        scheme = "http" if self._registry.startswith("localhost") else "https"
        return f"{scheme}://{self._registry}/v2"

    async def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token}"} if self._token else {}

    async def _authenticate(self, www_authenticate: str) -> None:
        """Handle a 401 challenge: fetch a bearer token from the realm advertised."""
        params = dict(re.findall(r'(\w+)="([^"]*)"', www_authenticate))
        realm = params.get("realm")
        if not realm:
            return
        query = "&".join(
            f"{k}={v}" for k, v in params.items() if k in ("service", "scope")
        )
        token_url = f"{realm}?{query}" if query else realm
        try:
            resp = await self._http.get(token_url)
            if resp.status == 200:
                data = json.loads(await resp.text(errors="replace"))
                self._token = data.get("token") or data.get("access_token")
            else:
                resp.release()
        except Exception as exc:
            logger.debug("Docker registry auth failed: %s", exc)

    async def get_manifest(self, reference: str) -> Tuple[Optional[dict], str]:
        """Fetch (and follow manifest lists to) a single-platform manifest. Returns (manifest, digest)."""
        url = f"{self._base}/{self._repository}/manifests/{reference}"
        manifest, digest = await self._get_manifest_raw(url)
        if manifest is None:
            return None, ""

        media_type = manifest.get("mediaType", "")
        if "list" in media_type or "index" in media_type:
            candidates = manifest.get("manifests", [])
            chosen = None
            for m in candidates:
                platform = m.get("platform", {})
                if platform.get("os") == "linux" and platform.get("architecture") in ("amd64", "x86_64"):
                    chosen = m
                    break
            chosen = chosen or (candidates[0] if candidates else None)
            if not chosen:
                return None, digest
            sub_url = f"{self._base}/{self._repository}/manifests/{chosen['digest']}"
            return await self._get_manifest_raw(sub_url)

        return manifest, digest

    async def _get_manifest_raw(self, url: str) -> Tuple[Optional[dict], str]:
        headers = {"Accept": _MANIFEST_ACCEPT, **await self._auth_headers()}
        resp = await self._http.get(url, headers=headers)
        if resp.status == 401:
            resp.release()
            await self._authenticate(resp.headers.get("WWW-Authenticate", ""))
            headers = {"Accept": _MANIFEST_ACCEPT, **await self._auth_headers()}
            resp = await self._http.get(url, headers=headers)

        if resp.status != 200:
            resp.release()
            return None, ""

        text = await resp.text(errors="replace")
        digest = resp.headers.get("Docker-Content-Digest", "")
        try:
            return json.loads(text), digest
        except Exception:
            return None, digest

    async def get_blob(self, digest: str, max_bytes: int) -> bytes:
        url = f"{self._base}/{self._repository}/blobs/{digest}"
        headers = await self._auth_headers()
        try:
            return await self._http.download_bytes(url, max_bytes, headers=headers)
        except Exception:
            # Retry once in case the token needed refreshing for the blob host/scope
            resp = await self._http.get(url, headers=headers, allow_redirects=False)
            if resp.status == 401:
                resp.release()
                await self._authenticate(resp.headers.get("WWW-Authenticate", ""))
                headers = await self._auth_headers()
                return await self._http.download_bytes(url, max_bytes, headers=headers)
            resp.release()
            raise


async def scan_docker_image(
    http: HTTPClient,
    image_ref: str,
    max_layer_size: int = MAX_DOCKER_LAYER_SIZE,
) -> Tuple[List[Finding], DockerScanSummary]:
    """
    Read-only scan of a Docker image's layers for secrets.
    Returns (findings, summary). Never raises — errors are collected in the summary.
    """
    registry, repository, reference = parse_image_ref(image_ref)
    summary = DockerScanSummary(
        image_ref=image_ref, registry=registry, repository=repository, reference=reference
    )
    findings: List[Finding] = []

    client = DockerRegistryClient(http, registry, repository)
    try:
        manifest, digest = await client.get_manifest(reference)
    except Exception as exc:
        summary.errors.append(f"Failed to fetch manifest: {exc}")
        return findings, summary

    if not manifest:
        summary.errors.append(
            f"Could not retrieve manifest for {image_ref} (registry={registry}, repo={repository})"
        )
        return findings, summary

    summary.manifest_digest = digest
    layers = manifest.get("layers", [])
    if not layers and "fsLayers" in manifest:  # legacy v1 schema
        layers = [{"digest": l["blobSum"]} for l in manifest.get("fsLayers", [])]

    scanner = SecretScanner()
    extractor = ArchiveExtractor()

    for layer in layers:
        layer_digest = layer.get("digest", "")
        media_type = layer.get("mediaType", "")
        size = layer.get("size", 0)

        if media_type and media_type not in _LAYER_MEDIA_TYPES and "tar" not in media_type:
            summary.layers_skipped += 1
            summary.errors.append(f"Skipped unsupported layer media type: {media_type}")
            continue

        if size and size > max_layer_size:
            summary.layers_skipped += 1
            summary.errors.append(f"Skipped oversized layer {layer_digest[:19]} ({size} bytes)")
            continue

        try:
            blob = await client.get_blob(layer_digest, max_layer_size)
        except Exception as exc:
            summary.layers_skipped += 1
            summary.errors.append(f"Failed to download layer {layer_digest[:19]}: {exc}")
            continue

        try:
            members = extractor.extract(blob, f"layer-{layer_digest[:12]}.tar.gz")
        except Exception as exc:
            summary.layers_skipped += 1
            summary.errors.append(f"Failed to extract layer {layer_digest[:19]}: {exc}")
            continue

        summary.layers_scanned += 1
        pseudo_url = f"docker://{registry}/{repository}:{reference}!/{layer_digest[:19]}"
        for rel_path, content_bytes in members:
            try:
                text = content_bytes.decode("utf-8", errors="replace")
            except Exception:
                continue
            ft = FileClassifier.classify(rel_path)
            file_findings = scanner.scan(text, f"{pseudo_url}!/{rel_path}", ft)
            for f in file_findings:
                f.from_archive = True
                f.archive_path = rel_path
            findings.extend(file_findings)
            summary.files_scanned += 1

    return findings, summary
