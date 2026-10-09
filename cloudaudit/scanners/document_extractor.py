"""
cloudaudit.scanners.document_extractor — text extraction from office documents

Documents are a common place for credentials and personal data to end up in
public storage (runbooks, onboarding sheets, exported spreadsheets), and they
were previously skipped entirely. This module turns a document's bytes into
plain text so the normal analysis pipeline can read it.

Supported, with the standard library only:
  - Office Open XML  (.docx .xlsx .pptx, incl. spreadsheet data connections)
  - OpenDocument     (.odt .ods .odp)
  - PDF              (uncompressed and Flate-compressed text streams)
  - Legacy OLE       (.doc .xls .ppt) and RTF — printable-string extraction

If the optional ``pypdf`` package is installed (``pip install cloudaudit[documents]``)
it is used for PDFs, which handles font encodings the built-in extractor cannot.

Safety: documents are untrusted input. Nothing here parses XML with an entity-
expanding parser, every decompression is size-capped, and archive entry counts
are bounded — a hostile file can at worst yield no text.
"""

from __future__ import annotations

import html
import io
import logging
import re
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Dict, List

logger = logging.getLogger("cloudaudit.documents")

MAX_TEXT_CHARS       = 4 * 1024 * 1024     # text handed to the analysis pipeline
MAX_PART_BYTES       = 16 * 1024 * 1024    # one XML part / one PDF stream, uncompressed
MAX_TOTAL_BYTES      = 64 * 1024 * 1024    # all parts of one document, uncompressed
MAX_ZIP_ENTRIES      = 5000
MAX_PDF_PAGES        = 300

DOCUMENT_EXTENSIONS = (
    ".pdf", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
    ".odt", ".ods", ".odp", ".doc", ".xls", ".ppt", ".rtf",
)


@dataclass
class DocumentText:
    text:     str = ""
    method:   str = "none"                       # which extractor produced the text
    metadata: Dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return bool(self.text.strip())


# ── OOXML / ODF ────────────────────────────────────────────────────────────────

_TEXT_PARTS = re.compile(
    r"^(?:word/(?:document|header\d*|footer\d*|footnotes|endnotes|comments)\.xml"
    r"|xl/sharedStrings\.xml|xl/worksheets/sheet\d+\.xml|xl/comments\d*\.xml"
    r"|ppt/slides/slide\d+\.xml|ppt/notesSlides/notesSlide\d+\.xml|ppt/comments/comment\d+\.xml"
    r"|content\.xml)$"
)
# Parts whose payload lives in XML *attributes* (connection strings, custom properties).
_ATTRIBUTE_PARTS = re.compile(r"^(?:xl/connections\.xml|xl/externalLinks/[^/]+\.xml|docProps/custom\.xml|customXml/item\d+\.xml)$")
_META_PARTS = re.compile(r"^(?:docProps/(?:core|app)\.xml|meta\.xml)$")

_BLOCK_END = re.compile(r"</(?:w:p|a:p|text:p|text:h|row|si|c|w:tr|table:table-row|comment|text)>")
_INLINE_GAP = re.compile(r"<(?:w:tab|w:br|w:cr|text:tab|text:line-break|text:s)\b[^>]*/?>")
_TAG = re.compile(r"<[^>]+>")
_META_FIELDS = (
    ("creator", r"<dc:creator[^>]*>([^<]{1,200})</dc:creator>"),
    ("last_modified_by", r"<cp:lastModifiedBy[^>]*>([^<]{1,200})</cp:lastModifiedBy>"),
    ("company", r"<Company[^>]*>([^<]{1,200})</Company>"),
    ("manager", r"<Manager[^>]*>([^<]{1,200})</Manager>"),
    ("initial_creator", r"<meta:initial-creator[^>]*>([^<]{1,200})</meta:initial-creator>"),
    ("application", r"<Application[^>]*>([^<]{1,200})</Application>"),
)


def _xml_to_text(xml: str) -> str:
    """Tag-strip with paragraph/row boundaries kept. Runs inside a paragraph are joined."""
    xml = _BLOCK_END.sub("\n", xml)
    xml = _INLINE_GAP.sub(" ", xml)
    return html.unescape(_TAG.sub("", xml))


def _read_capped(zf: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    with zf.open(info) as fh:
        return fh.read(MAX_PART_BYTES + 1)[:MAX_PART_BYTES]


def _extract_zip_document(data: bytes) -> DocumentText:
    out = DocumentText(method="ooxml/odf")
    chunks: List[str] = []
    total = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        infos = zf.infolist()
        if len(infos) > MAX_ZIP_ENTRIES:
            raise ValueError("too many archive entries")
        for info in infos:
            name = info.filename
            is_text, is_attr, is_meta = _TEXT_PARTS.match(name), _ATTRIBUTE_PARTS.match(name), _META_PARTS.match(name)
            if not (is_text or is_attr or is_meta):
                continue
            if info.file_size > MAX_PART_BYTES:
                continue
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                break
            xml = _read_capped(zf, info).decode("utf-8", errors="replace")
            if is_meta:
                for key, pattern in _META_FIELDS:
                    m = re.search(pattern, xml)
                    if m and key not in out.metadata:
                        out.metadata[key] = html.unescape(m.group(1)).strip()
            elif is_attr:
                values = re.findall(r'="([^"]{4,2000})"', xml)
                chunks.append("\n".join(html.unescape(v) for v in values))
                chunks.append(_xml_to_text(xml))
            else:
                chunks.append(_xml_to_text(xml))
    out.text = "\n".join(c for c in chunks if c.strip())[:MAX_TEXT_CHARS]
    return out


# ── PDF ────────────────────────────────────────────────────────────────────────

_PDF_STREAM = re.compile(rb"stream\r?\n(.*?)\r?\n?endstream", re.DOTALL)
_PDF_TOKEN = re.compile(rb"\(((?:\\.|[^\\()])*)\)|<([0-9A-Fa-f\s]{4,})>|\b(ET|T\*|Td|TD|Tm)\b|(')")
_PDF_ESCAPES = {b"n": b"\n", b"r": b"\r", b"t": b"\t", b"b": b"\b", b"f": b"\f", b"(": b"(", b")": b")", b"\\": b"\\"}
_PDF_META = re.compile(rb"/(Author|Creator|Producer|Title)\s*\(((?:\\.|[^\\()]){1,200})\)")


def _pdf_unescape(raw: bytes) -> bytes:
    def repl(m: "re.Match[bytes]") -> bytes:
        body = m.group(1)
        if body[:1].isdigit():
            return bytes([int(body, 8) & 0xFF])
        return _PDF_ESCAPES.get(body, body)
    return re.sub(rb"\\([0-7]{1,3}|.)", repl, raw, flags=re.DOTALL)


def _pdf_stream_text(stream: bytes) -> str:
    if b"BT" not in stream:
        return ""
    lines: List[str] = []
    current: List[str] = []
    for m in _PDF_TOKEN.finditer(stream):
        literal, hexstr, op, quote = m.groups()
        if literal is not None:
            current.append(_pdf_unescape(literal).decode("latin-1", errors="replace"))
        elif hexstr is not None:
            digits = re.sub(rb"\s", b"", hexstr)
            if len(digits) % 2 == 0:
                try:
                    decoded = bytes.fromhex(digits.decode("ascii"))
                except ValueError:
                    continue
                # Only keep hex strings that are plain single-byte text (not CID glyph ids).
                if decoded and all(32 <= b < 127 for b in decoded):
                    current.append(decoded.decode("ascii"))
        elif op is not None or quote is not None:
            if current:
                lines.append("".join(current))
                current = []
    if current:
        lines.append("".join(current))
    return "\n".join(lines)


def _extract_pdf_builtin(data: bytes) -> DocumentText:
    out = DocumentText(method="pdf-builtin")
    for m in _PDF_META.finditer(data[:2_000_000]):
        key = m.group(1).decode("ascii").lower()
        out.metadata.setdefault(key, _pdf_unescape(m.group(2)).decode("latin-1", errors="replace").strip())
    chunks: List[str] = []
    total = 0
    for m in _PDF_STREAM.finditer(data):
        raw = m.group(1)
        try:
            body = zlib.decompressobj().decompress(raw, MAX_PART_BYTES)
        except zlib.error:
            body = raw            # stream was not Flate-compressed
        total += len(body)
        if total > MAX_TOTAL_BYTES:
            break
        text = _pdf_stream_text(body)
        if text:
            chunks.append(text)
    out.text = "\n".join(chunks)[:MAX_TEXT_CHARS]
    return out


def _extract_pdf(data: bytes) -> DocumentText:
    try:
        from pypdf import PdfReader  # type: ignore[import]
    except ImportError:
        return _extract_pdf_builtin(data)
    try:
        reader = PdfReader(io.BytesIO(data))
        if getattr(reader, "is_encrypted", False):
            try:
                reader.decrypt("")
            except Exception:
                return DocumentText(method="pdf-encrypted")
        out = DocumentText(method="pypdf")
        meta = reader.metadata or {}
        for key in ("/Author", "/Creator", "/Producer", "/Title"):
            val = meta.get(key)
            if val:
                out.metadata[key.strip("/").lower()] = str(val)[:200]
        chunks: List[str] = []
        size = 0
        for i, page in enumerate(reader.pages):
            if i >= MAX_PDF_PAGES or size > MAX_TEXT_CHARS:
                break
            text = page.extract_text() or ""
            size += len(text)
            chunks.append(text)
        out.text = "\n".join(chunks)[:MAX_TEXT_CHARS]
        return out if out.ok else _extract_pdf_builtin(data)
    except Exception as exc:
        logger.debug("pypdf failed (%s) — using the built-in PDF extractor", exc)
        return _extract_pdf_builtin(data)


# ── Legacy binary formats / fallback ───────────────────────────────────────────

_ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def _extract_strings(data: bytes, method: str) -> DocumentText:
    """`strings`-style extraction: printable ASCII and UTF-16LE runs."""
    data = data[:MAX_TOTAL_BYTES]
    parts = [m.group(0).decode("ascii") for m in _ASCII_RUN.finditer(data)]
    parts += [m.group(0).decode("utf-16-le", errors="replace") for m in _UTF16_RUN.finditer(data)]
    return DocumentText(text="\n".join(parts)[:MAX_TEXT_CHARS], method=method)


# ── Entry point ────────────────────────────────────────────────────────────────

def is_document(name: str) -> bool:
    return name.lower().endswith(DOCUMENT_EXTENSIONS)


def extract_text(data: bytes, name: str = "") -> DocumentText:
    """
    Extract plain text (and author-type metadata) from a document.
    Never raises: an unreadable document yields an empty ``DocumentText``.
    """
    if not data:
        return DocumentText()
    try:
        if data[:4] == b"PK\x03\x04":
            return _extract_zip_document(data)
        if data[:5] == b"%PDF-" or b"%PDF-" in data[:1024]:
            return _extract_pdf(data)
        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            return _extract_strings(data, "ole-strings")
        if data[:5] == b"{\\rtf":
            return _extract_strings(data, "rtf-strings")
        return _extract_strings(data, "strings")
    except Exception as exc:
        logger.debug("Document extraction failed for %s: %s", name or "<bytes>", exc)
        return DocumentText(method="failed")
