"""Static attachment inventory. Never executes content; decode caps apply."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field
from email.message import EmailMessage
from typing import Any

MAX_ATTACHMENTS = 50
# Cap decoded bytes inspected per part (AppSec / DoS bound).
MAX_SCAN_BYTES = 512 * 1024

_DANGEROUS_EXT = frozenset(
    {
        ".exe",
        ".scr",
        ".com",
        ".dll",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".vbe",
        ".js",
        ".jse",
        ".wsf",
        ".wsh",
        ".hta",
        ".lnk",
        ".iso",
        ".img",
        ".jar",
        ".docm",
        ".xlsm",
        ".pptm",
        ".dotm",
        ".xltm",
        ".msi",
        ".msp",
    }
)

_DOUBLE_EXT = re.compile(
    r"\.(?:pdf|docx?|xlsx?|pptx?|txt|jpg|png|gif)\.(?:exe|scr|com|bat|cmd|js|vbs|ps1|lnk)$",
    re.IGNORECASE,
)

# OLE / Office macro hints (static byte presence only).
_MACRO_MARKERS = (
    b"vbaProject.bin",
    b"_VBA_PROJECT",
    b"VBA/",
    b"Attribut\x00e",  # common OLE stream fragment
)

_PDF_RISKY = (b"/JavaScript", b"/JS", b"/OpenAction", b"/AA", b"/Launch")
_LNK_MAGIC = b"L\x00\x00\x00"
_ZIP_MAGIC = b"PK\x03\x04"
_PDF_MAGIC = b"%PDF"


@dataclass
class AttachmentInfo:
    filename: str
    content_type: str
    size: int
    flags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _filename(part: EmailMessage) -> str:
    name = part.get_filename()
    if name:
        return str(name)
    return ""


def _is_attachment(part: EmailMessage) -> bool:
    if part.get_content_maintype() == "multipart":
        return False
    disp = (part.get_content_disposition() or "").lower()
    if disp == "attachment":
        return True
    if disp == "inline" and part.get_filename():
        return True
    # Named binary parts without disposition still matter.
    if part.get_filename() and part.get_content_maintype() != "text":
        return True
    return False


def _safe_payload(part: EmailMessage) -> bytes:
    try:
        data = part.get_payload(decode=True)
    except (TypeError, ValueError, KeyError, LookupError, UnicodeError):
        return b""
    if not isinstance(data, bytes | bytearray):
        return b""
    return bytes(data[:MAX_SCAN_BYTES])


def _ext(name: str) -> str:
    name = name.lower().strip()
    if "." not in name:
        return ""
    return "." + name.rsplit(".", 1)[-1]


def _scan_flags(filename: str, payload: bytes) -> list[str]:
    flags: list[str] = []
    lower = filename.lower()
    ext = _ext(filename)

    if ext in _DANGEROUS_EXT:
        flags.append("dangerous_extension")
    if _DOUBLE_EXT.search(lower):
        flags.append("double_extension")

    head = payload[:8]
    if head.startswith(_LNK_MAGIC) or ext == ".lnk":
        flags.append("lnk")
    if payload.startswith(_PDF_MAGIC) or ext == ".pdf":
        flags.append("pdf")
        if any(m in payload for m in _PDF_RISKY):
            flags.append("pdf_active_content")
    if payload.startswith(_ZIP_MAGIC):
        flags.append("zip_container")
    if any(m in payload for m in _MACRO_MARKERS):
        flags.append("macro_indicator")
    if ext in {".docm", ".xlsm", ".pptm", ".dotm", ".xltm"}:
        flags.append("macro_enabled_office")

    # De-dupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for f in flags:
        if f not in seen:
            seen.add(f)
            out.append(f)
    return out


def list_attachments(msg: EmailMessage) -> list[AttachmentInfo]:
    """Inventory attachments with static risk flags. No disk writes."""
    found: list[AttachmentInfo] = []
    for part in msg.walk():
        if len(found) >= MAX_ATTACHMENTS:
            break
        if not _is_attachment(part):
            continue
        name = _filename(part) or "(unnamed)"
        payload = _safe_payload(part)
        # Size: prefer Content-Length / decoded length when available.
        size = len(payload)
        try:
            raw_payload = part.get_payload(decode=True)
            if isinstance(raw_payload, bytes | bytearray):
                size = len(raw_payload)
        except (TypeError, ValueError, KeyError, LookupError, UnicodeError):
            size = len(payload)
        ctype = part.get_content_type() or "application/octet-stream"
        found.append(
            AttachmentInfo(
                filename=name[:200],
                content_type=ctype[:120],
                size=size,
                flags=_scan_flags(name, payload),
            )
        )
    return found
