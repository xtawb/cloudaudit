"""
cloudaudit — Image Metadata / EXIF Analyser

Extracts metadata from images found in cloud storage.
GPS coordinates, device info, software versions, and author data
can inadvertently reveal sensitive organisational information.

This module is purely read-only — it never modifies images.
"""

from __future__ import annotations

import io
import logging
from typing import Dict, List, Optional

from cloudaudit.core.models import FileType, Finding, FindingCategory, Severity
from cloudaudit.utils.helpers import url_filename

logger = logging.getLogger("cloudaudit.image_meta")

try:
    from PIL import Image
    from PIL.ExifTags import TAGS, GPSTAGS
    _PIL_AVAILABLE = True
except ImportError:
    _PIL_AVAILABLE = False
    logger.debug("Pillow not installed — EXIF analysis disabled. Run: pip install Pillow")


# Fields that may contain sensitive information
_SENSITIVE_EXIF_TAGS = {
    "GPSInfo",
    "GPSLatitude",
    "GPSLongitude",
    "GPSAltitude",
    "Make",
    "Model",
    "Software",
    "Artist",
    "Copyright",
    "ImageDescription",
    "UserComment",
    "DocumentName",
    "HostComputer",
    "ProcessingSoftware",
    "CameraOwnerName",
    "BodySerialNumber",
    "LensSerialNumber",
}


class ImageMetaAnalyser:
    """
    Analyse image files for metadata leakage.

    Returns findings if:
      - GPS coordinates are present (location privacy risk)
      - Device/software information is present (asset enumeration risk)
      - Author/copyright fields contain personnel information
    """

    def analyse(self, content: bytes, file_url: str) -> List[Finding]:
        if not _PIL_AVAILABLE:
            return []

        findings: List[Finding] = []

        try:
            img = Image.open(io.BytesIO(content))
        except Exception as exc:
            logger.debug("Cannot open image %s: %s", file_url, exc)
            return []

        # Extract raw EXIF data
        exif_data = self._extract_exif(img)
        if not exif_data:
            return []

        # Check for GPS coordinates (highest severity)
        if "GPSInfo" in exif_data or any(k.startswith("GPS") for k in exif_data):
            gps_info = self._format_gps(exif_data.get("GPSInfo", {}))
            findings.append(Finding(
                file_url=file_url,
                file_name=url_filename(file_url),
                file_type=FileType.IMAGE,
                category=FindingCategory.METADATA_LEAKAGE,
                rule_name="IMAGE_GPS_COORDINATES",
                description="Image contains embedded GPS coordinates",
                severity=Severity.MEDIUM,
                match=gps_info or "GPS data present",
                recommendation=(
                    "Strip EXIF metadata from images before storing in cloud storage. "
                    "Use tools like 'exiftool -all= image.jpg' or image processing pipelines."
                ),
                compliance_refs=["SOC2 CC6.7"],
                confidence=0.95,
                scanner="ImageMetaAnalyser",
            ))

        # Check for device / software info
        device_info = {
            k: str(v) for k, v in exif_data.items()
            if k in ("Make", "Model", "Software", "HostComputer", "ProcessingSoftware")
        }
        if device_info:
            findings.append(Finding(
                file_url=file_url,
                file_name=url_filename(file_url),
                file_type=FileType.IMAGE,
                category=FindingCategory.METADATA_LEAKAGE,
                rule_name="IMAGE_DEVICE_INFO",
                description="Image reveals device/software information",
                severity=Severity.LOW,
                match=", ".join(f"{k}={v[:40]}" for k, v in device_info.items()),
                recommendation="Strip EXIF data from images before publishing to cloud storage.",
                compliance_refs=[],
                confidence=0.9,
                scanner="ImageMetaAnalyser",
            ))

        # Check for author / copyright / description fields
        person_info = {
            k: str(v) for k, v in exif_data.items()
            if k in ("Artist", "Copyright", "ImageDescription", "UserComment",
                     "CameraOwnerName", "DocumentName")
            and v
        }
        if person_info:
            findings.append(Finding(
                file_url=file_url,
                file_name=url_filename(file_url),
                file_type=FileType.IMAGE,
                category=FindingCategory.PII_EXPOSURE,
                rule_name="IMAGE_AUTHOR_INFO",
                description="Image contains author/owner information in metadata",
                severity=Severity.LOW,
                match=", ".join(f"{k}=***" for k in person_info),  # redact values
                recommendation="Strip author fields from EXIF before cloud upload.",
                compliance_refs=["SOC2 CC6.7"],
                confidence=0.85,
                scanner="ImageMetaAnalyser",
            ))

        return findings

    # ── Helpers ────────────────────────────────────────────────────────────────

    @staticmethod
    def _extract_exif(img: "Image.Image") -> Dict[str, object]:
        """Extract and decode EXIF tags from a PIL Image."""
        result: Dict[str, object] = {}
        try:
            exif_raw = img._getexif()  # type: ignore[attr-defined]
            if not exif_raw:
                return result
            for tag_id, value in exif_raw.items():
                tag = TAGS.get(tag_id, str(tag_id))
                if tag == "GPSInfo" and isinstance(value, dict):
                    gps = {GPSTAGS.get(k, k): v for k, v in value.items()}
                    result["GPSInfo"] = gps
                else:
                    result[tag] = value
        except Exception:
            pass
        return result

    @staticmethod
    def _format_gps(gps_info: Dict) -> Optional[str]:
        """Convert GPS EXIF data to human-readable lat/lon string."""
        try:
            def _dms_to_dd(dms: tuple, ref: str) -> float:
                d, m, s = dms
                dd = float(d) + float(m) / 60 + float(s) / 3600
                if ref in ("S", "W"):
                    dd = -dd
                return dd

            lat = _dms_to_dd(gps_info.get("GPSLatitude", (0, 0, 0)),
                              gps_info.get("GPSLatitudeRef", "N"))
            lon = _dms_to_dd(gps_info.get("GPSLongitude", (0, 0, 0)),
                              gps_info.get("GPSLongitudeRef", "E"))
            return f"{lat:.5f}, {lon:.5f}"
        except Exception:
            return None
