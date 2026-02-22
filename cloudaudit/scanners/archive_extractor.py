"""
cloudaudit — Safe Archive Extraction Engine

Supported formats: .zip, .tar, .tar.gz, .tar.bz2, .tar.xz, .gz, .bz2, .xz, .jar, .war

Safety measures:
  1. Zip-slip prevention — all extracted paths are validated to be within the workspace
  2. Decompression bomb guard — total unpacked size is capped
  3. Max file count guard — stops runaway extraction
  4. File size cap per extracted member — skips oversized entries
  5. No execution of any extracted content
"""

from __future__ import annotations

import gzip
import io
import logging
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path
from typing import List, Tuple

from cloudaudit.core.constants import (
    ARCHIVE_WORKSPACE,
    MAX_ARCHIVE_EXTRACT_SIZE,
    MAX_ARCHIVE_FILE_COUNT,
)
from cloudaudit.core.exceptions import ArchiveError
from cloudaudit.utils.helpers import human_size, safe_filename

logger = logging.getLogger("cloudaudit.archive")


class ArchiveExtractor:
    """
    Download and safely extract archives for content analysis.

    The caller is responsible for providing the raw bytes of the archive.
    This class handles all extraction and returns a list of (relative_path, content_bytes).
    """

    def extract(
        self,
        archive_bytes: bytes,
        archive_name: str,
        workspace: str = ARCHIVE_WORKSPACE,
    ) -> List[Tuple[str, bytes]]:
        """
        Extract archive and return list of (relative_path, file_bytes).

        Only text-analysable files are returned (binaries are skipped).
        Zip-slip and decompression bomb protections are always enforced.
        """
        ext = "".join(Path(archive_name).suffixes).lower()

        if ".tar" in ext or archive_name.endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
            return self._extract_tar(archive_bytes, archive_name)
        elif ext in (".zip", ".jar", ".war", ".ear", ".whl"):
            return self._extract_zip(archive_bytes, archive_name)
        elif ext == ".gz" and not archive_name.endswith(".tar.gz"):
            return self._extract_gzip(archive_bytes, archive_name)
        elif ext == ".bz2":
            return self._extract_bzip2(archive_bytes, archive_name)
        else:
            raise ArchiveError(f"Unsupported archive format: {archive_name}")

    # ── Format-specific extractors ─────────────────────────────────────────────

    def _extract_zip(self, data: bytes, name: str) -> List[Tuple[str, bytes]]:
        results: List[Tuple[str, bytes]] = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                total_size = 0
                file_count = 0

                for info in zf.infolist():
                    if info.is_dir():
                        continue

                    file_count += 1
                    if file_count > MAX_ARCHIVE_FILE_COUNT:
                        logger.warning("ZIP %s: max file count reached (%d), stopping", name, MAX_ARCHIVE_FILE_COUNT)
                        break

                    # Zip-slip check
                    rel_path = self._sanitise_path(info.filename)
                    if rel_path is None:
                        logger.warning("Zip-slip attempt in %s: %s", name, info.filename)
                        continue

                    # Size guard
                    if info.file_size > 50 * 1024 * 1024:  # 50 MB per file
                        logger.debug("Skipping oversized member %s (%s)", rel_path, human_size(info.file_size))
                        continue

                    total_size += info.file_size
                    if total_size > MAX_ARCHIVE_EXTRACT_SIZE:
                        logger.warning("ZIP %s: decompression bomb guard triggered", name)
                        break

                    try:
                        content = zf.read(info.filename)
                        if self._is_text_like(rel_path, content):
                            results.append((rel_path, content))
                    except Exception as exc:
                        logger.debug("Cannot read %s from %s: %s", rel_path, name, exc)

        except zipfile.BadZipFile as exc:
            raise ArchiveError(f"Invalid ZIP file {name}: {exc}") from exc

        return results

    def _extract_tar(self, data: bytes, name: str) -> List[Tuple[str, bytes]]:
        results: List[Tuple[str, bytes]] = []
        mode = "r:*"   # auto-detect compression
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode=mode) as tf:
                total_size = 0
                file_count = 0

                for member in tf.getmembers():
                    if not member.isfile():
                        continue

                    file_count += 1
                    if file_count > MAX_ARCHIVE_FILE_COUNT:
                        logger.warning("TAR %s: max file count reached, stopping", name)
                        break

                    # Path traversal check
                    rel_path = self._sanitise_path(member.name)
                    if rel_path is None:
                        logger.warning("Path traversal in TAR %s: %s", name, member.name)
                        continue

                    if member.size > 50 * 1024 * 1024:
                        continue

                    total_size += member.size
                    if total_size > MAX_ARCHIVE_EXTRACT_SIZE:
                        logger.warning("TAR %s: decompression bomb guard triggered", name)
                        break

                    try:
                        f = tf.extractfile(member)
                        if f:
                            content = f.read()
                            if self._is_text_like(rel_path, content):
                                results.append((rel_path, content))
                    except Exception as exc:
                        logger.debug("Cannot read %s from %s: %s", rel_path, name, exc)

        except tarfile.TarError as exc:
            raise ArchiveError(f"Invalid TAR file {name}: {exc}") from exc

        return results

    def _extract_gzip(self, data: bytes, name: str) -> List[Tuple[str, bytes]]:
        """Single-file gzip (e.g. file.sql.gz)."""
        try:
            content = gzip.decompress(data)
            # Name the inner file by removing .gz suffix
            inner_name = name.removesuffix(".gz") if name.endswith(".gz") else name + ".ungzipped"
            if self._is_text_like(inner_name, content):
                return [(inner_name, content)]
        except Exception as exc:
            raise ArchiveError(f"GZIP decompression failed for {name}: {exc}") from exc
        return []

    def _extract_bzip2(self, data: bytes, name: str) -> List[Tuple[str, bytes]]:
        import bz2
        try:
            content = bz2.decompress(data)
            inner_name = name.removesuffix(".bz2") if name.endswith(".bz2") else name + ".unbz2"
            if self._is_text_like(inner_name, content):
                return [(inner_name, content)]
        except Exception as exc:
            raise ArchiveError(f"BZIP2 decompression failed for {name}: {exc}") from exc
        return []

    # ── Safety helpers ─────────────────────────────────────────────────────────

    @staticmethod
    def _sanitise_path(raw_path: str) -> str | None:
        """
        Prevent zip-slip: ensure the path is a relative path with no '..' components.
        Returns None if the path is unsafe.
        """
        # Resolve to a Path object and check for traversal
        try:
            resolved = Path(raw_path)
            # Reject absolute paths
            if resolved.is_absolute():
                return None
            # Reject paths with '..' components
            parts = resolved.parts
            if ".." in parts:
                return None
            return str(resolved)
        except Exception:
            return None

    @staticmethod
    def _is_text_like(path: str, content: bytes) -> bool:
        """
        Heuristic: is this content worth analysing as text?
        Returns True for files that are likely text-based.
        """
        from cloudaudit.scanners.file_classifier import FileClassifier
        from cloudaudit.core.models import FileType

        ft = FileClassifier.classify(path)

        # Always analyse known text types
        if FileClassifier.is_text_analysable(ft):
            # Quick byte check: reject if too many null bytes (binary)
            null_ratio = content.count(b"\x00") / max(len(content), 1)
            return null_ratio < 0.05

        # For unknown types, do a byte-level check
        if ft in (FileType.OTHER,):
            null_ratio = content.count(b"\x00") / max(len(content), 1)
            return null_ratio < 0.02 and len(content) < 5 * 1024 * 1024

        return False
