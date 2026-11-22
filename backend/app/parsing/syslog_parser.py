"""Parser for Linux auth / syslog files (RFC 3164 style and ISO-timestamp style)."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from app.parsing.auth_events import classify_message
from app.parsing.patterns import SYSLOG_3164, SYSLOG_ISO
from app.parsing.schema import (
    MalformedTracker, ParsedRecords, clean_ip, clean_port, clean_text, make_record,
)

_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}


def _parse_iso(text: str):
    """ISO timestamp -> naive UTC datetime (None if invalid)."""
    text = text.replace(",", ".").replace("Z", "+00:00")
    text = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    text = re.sub(r"\.(\d+)", lambda m: "." + m.group(1)[:6].ljust(6, "0"), text)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _parse_stamp(text: str):
    """'Sep 22 10:31:21' -> (month, day, hour, minute, second). Classic syslog has NO year."""
    month_name, day, clock = text.split()
    month = _MONTHS.get(month_name.lower())
    if month is None:
        return None
    hour, minute, second = (int(part) for part in clock.split(":"))
    return month, int(day), hour, minute, second


def _safe_datetime(year: int, stamp):
    try:
        return datetime(year, *stamp)
    except ValueError:
        return None


def assign_years(stamps: list, now: datetime) -> list:
    """Syslog lines carry no year, so we infer it.

    Walk the file from the LAST line to the first:
      * the last line is assumed to be from the most recent past occurrence of that date
        (this year, or last year if that would be in the future);
      * going backwards, if the month jumps up by more than 6 (Jan -> Dec), the log crossed
        New Year, so we step one year back.
    `stamps` holds tuples (or None for lines that already have a full timestamp)."""
    results = [None] * len(stamps)
    year = None
    later_month = None
    for index in range(len(stamps) - 1, -1, -1):
        stamp = stamps[index]
        if stamp is None:
            continue
        month = stamp[0]
        if year is None:
            year = now.year
            candidate = _safe_datetime(year, stamp)
            if candidate is not None and candidate > now + timedelta(days=1):
                year -= 1
        elif later_month is not None and month - later_month > 6:
            year -= 1
        later_month = month
        results[index] = _safe_datetime(year, stamp)
    return results


def parse_syslog(lines, reference_time: datetime | None = None) -> ParsedRecords:
    now = reference_time or datetime.now()
    tracker = MalformedTracker()
    records: list[dict] = []
    stamps: list = []

    for line_no, line in lines:
        match = SYSLOG_ISO.match(line)
        is_iso = match is not None
        if not is_iso:
            match = SYSLOG_3164.match(line)
        if match is None:
            tracker.add(line_no, line)
            continue

        timestamp, stamp = None, None
        if is_iso:
            timestamp = _parse_iso(match["ts"])
            if timestamp is None:
                tracker.add(line_no, line)
                continue
        else:
            stamp = _parse_stamp(match["ts"])
            if stamp is None:
                tracker.add(line_no, line)
                continue

        message = match["msg"]
        info = classify_message(message)
        service = clean_text(match["proc"], 64)
        records.append(make_record(
            line_no=line_no,
            timestamp=timestamp,
            host=clean_text(match["host"], 100),
            service=service,
            event=info["event"],
            username=clean_text(info["username"], 64),
            source_ip=clean_ip(info["source_ip"]),
            source_port=clean_port(info["source_port"]),
            protocol="ssh" if service == "sshd" else None,
            auth_status=info["auth_status"],
            message=clean_text(message, 1000),
            raw_line=clean_text(line, 1000),
        ))
        stamps.append(stamp)

    for record, inferred in zip(records, assign_years(stamps, now)):
        if record["timestamp"] is None:
            record["timestamp"] = inferred

    return ParsedRecords(records=records, malformed=tracker)
