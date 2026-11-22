"""The normalized record structure that every parser must produce, plus the
small cleaning helpers they share.

Every log line, whatever its original format, becomes ONE row with exactly
these columns. Later modules (features, detection, ...) only ever see this."""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field

import pandas as pd

COLUMNS = [
    "line_no",          # line number (text logs) or record number (CSV/JSON); used to point at evidence
    "timestamp",        # naive datetime. Apache and ISO timestamps are converted to UTC
    "host",
    "service",          # e.g. sshd, sudo, http
    "event",            # normalized event type, e.g. failed_login (see README for the list)
    "username",
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "http_method",
    "http_path",
    "status_code",      # HTTP status
    "auth_status",      # "success", "failure" or empty
    "user_agent",
    "message",
    "raw_line",         # the original line (cleaned + truncated), kept as evidence
]
INT_COLUMNS = ["line_no", "source_port", "destination_port", "status_code"]

MAX_FIELD = 200
MAX_TEXT = 1000

# Control characters (including ESC, used for terminal tricks) are replaced by a space.
_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_METHOD = re.compile(r"^[A-Z]{3,10}$")


# ---------------------------------------------------------------- cleaning helpers
def clean_text(value, limit: int = MAX_FIELD) -> str | None:
    """Turn any value into a safe, bounded string (or None if empty).
    We do NOT HTML-escape here: the frontend must escape when displaying."""
    if value is None:
        return None
    text = _CONTROL_CHARS.sub(" ", str(value)).strip()
    return text[:limit] if text else None


def clean_ip(value) -> str | None:
    """Return a canonical IP string, or None when the value is not a valid IPv4/IPv6 address."""
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip().strip("[]")))
    except ValueError:
        return None


def clean_port(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 0 <= port <= 65535 else None


def clean_status(value) -> int | None:
    try:
        status = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return status if 100 <= status <= 599 else None


def clean_method(value) -> str | None:
    text = clean_text(value, 10)
    if text is None:
        return None
    text = text.upper()
    return text if _METHOD.match(text) else None


def clean_protocol(value) -> str | None:
    text = clean_text(value, 32)
    return text.lower() if text else None


def slugify(value) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(value).lower()).strip("_")[:50]


def http_event(status: int | None) -> str:
    """Event name for an HTTP response, based on its status class."""
    if status is None:
        return "http_request"
    return {2: "http_success", 3: "http_redirect", 4: "http_client_error", 5: "http_server_error"}.get(
        status // 100, "http_request"
    )


# ---------------------------------------------------------------- records and frames
def make_record(**values) -> dict:
    """A record with every column present (None by default)."""
    unknown = set(values) - set(COLUMNS)
    if unknown:
        raise KeyError(f"Unknown column(s): {sorted(unknown)}")
    record = dict.fromkeys(COLUMNS)
    record.update(values)
    return record


class MalformedTracker:
    """Counts lines that could not be parsed and remembers the first few as examples."""

    def __init__(self, max_samples: int = 5):
        self.count = 0
        self.samples: list[dict] = []
        self._max = max_samples

    def add(self, line_no: int, content: str) -> None:
        self.count += 1
        if len(self.samples) < self._max:
            self.samples.append({"line": line_no, "content": clean_text(content, 200) or ""})


@dataclass
class ParsedRecords:
    """What each individual parser hands back to log_parser.py."""

    records: list[dict]
    malformed: MalformedTracker
    recognized: list[str] = field(default_factory=list)   # structured formats only
    ignored: list[str] = field(default_factory=list)      # structured formats only
    warnings: list[str] = field(default_factory=list)


def to_frame(records: list[dict]) -> pd.DataFrame:
    frame = pd.DataFrame(records, columns=COLUMNS)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"], errors="coerce")
    for column in INT_COLUMNS:
        frame[column] = pd.to_numeric(frame[column], errors="coerce").astype("Int64")
    return frame


def frame_to_json_records(frame: pd.DataFrame, limit: int | None = None) -> list[dict]:
    """DataFrame -> list of JSON-safe dicts (NaN/NA/NaT become null)."""
    part = frame if limit is None else frame.head(limit)
    part = part.copy()
    for column in part.select_dtypes(include=["datetime"]).columns:
        part[column] = part[column].dt.strftime("%Y-%m-%d %H:%M:%S")
    return json.loads(part.to_json(orient="records"))
