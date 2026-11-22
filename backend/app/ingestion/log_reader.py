"""Module 1 (part 1): accept an uploaded file safely.

Everything here treats the upload as UNTRUSTED. We never save it to disk, never
use its filename as a path, and never execute it - we only validate it and
decode its bytes into text."""

from __future__ import annotations

import codecs
import re
from dataclasses import dataclass
from pathlib import PurePosixPath

from app.errors import LogAnalysisError

ALLOWED_EXTENSIONS = (".csv", ".txt", ".log", ".json", ".jsonl")
MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")


@dataclass(frozen=True)
class RawLog:
    """A validated, decoded upload."""

    filename: str      # sanitized, safe to display
    extension: str
    size_bytes: int
    encoding: str
    text: str


def sanitize_filename(filename: str | None) -> str:
    """Keep only the final path component (blocks '../' tricks) and drop control characters."""
    name = (filename or "").replace("\\", "/").split("/")[-1]
    name = _CONTROL_CHARS.sub("", name).strip()
    suffix = PurePosixPath(name).suffix
    stem = name[: len(name) - len(suffix)] if suffix else name
    name = stem[:80] + suffix
    return name or "uploaded_file"


def _decode(data: bytes) -> tuple[str, str]:
    if data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        return data.decode("utf-16", errors="replace"), "utf-16"
    try:
        return data.decode("utf-8-sig"), "utf-8"
    except UnicodeDecodeError:
        # Not valid UTF-8 (common for Windows exports): fall back to cp1252, never crash.
        return data.decode("cp1252", errors="replace"), "cp1252"


def read_upload(filename: str | None, data: bytes) -> RawLog:
    """Validate and decode an uploaded file. Raises LogAnalysisError with a clear message."""
    safe_name = sanitize_filename(filename)
    extension = PurePosixPath(safe_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise LogAnalysisError(
            "unsupported_extension",
            f"Files of type '{extension or 'no extension'}' are not supported. "
            f"Upload one of: {', '.join(ALLOWED_EXTENSIONS)}.",
        )
    if len(data) > MAX_FILE_SIZE_BYTES:
        limit_mb = MAX_FILE_SIZE_BYTES // (1024 * 1024)
        raise LogAnalysisError("file_too_large", f"The file is larger than the {limit_mb} MB limit.")
    if len(data) == 0:
        raise LogAnalysisError("empty_file", "The file is empty. Upload a log file that contains records.")
    if b"\x00" in data and not data.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
        raise LogAnalysisError(
            "binary_file",
            "This looks like a binary file, not a text log. Export or copy the logs as plain text and try again.",
        )

    text, encoding = _decode(data)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if not text.strip():
        raise LogAnalysisError("empty_file", "The file only contains blank space. Upload a log file that contains records.")

    return RawLog(filename=safe_name, extension=extension, size_bytes=len(data), encoding=encoding, text=text)
