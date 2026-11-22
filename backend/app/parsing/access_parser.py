"""Parser for Apache / Nginx access logs (common and combined formats)."""

from __future__ import annotations

from datetime import datetime, timezone

from app.parsing.patterns import APACHE_ACCESS
from app.parsing.schema import (
    MalformedTracker, ParsedRecords, clean_ip, clean_method, clean_protocol,
    clean_status, clean_text, http_event, make_record,
)


def _parse_timestamp(text: str):
    """'22/Sep/2026:10:31:21 +0530' -> naive UTC datetime (None if invalid)."""
    try:
        parsed = datetime.strptime(text, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc).replace(tzinfo=None)


def parse_access(lines) -> ParsedRecords:
    tracker = MalformedTracker()
    records: list[dict] = []

    for line_no, line in lines:
        match = APACHE_ACCESS.match(line)
        timestamp = _parse_timestamp(match["ts"]) if match else None
        if match is None or timestamp is None:
            tracker.add(line_no, line)
            continue

        request = match["req"]
        parts = request.split(" ")
        method = path = protocol = None
        if len(parts) == 3:
            method, path, protocol = parts
        elif len(parts) == 2:
            method, path = parts
        else:
            path = request  # scanners often send garbage instead of a proper request line
        if protocol is not None and not protocol.upper().startswith("HTTP"):
            protocol = None

        status = clean_status(match["status"])
        user = match["user"]
        agent = match["ua"]
        records.append(make_record(
            line_no=line_no,
            timestamp=timestamp,
            service="http",
            event=http_event(status),
            username=clean_text(user, 64) if user != "-" else None,
            source_ip=clean_ip(match["ip"]),
            protocol=clean_protocol(protocol),
            http_method=clean_method(method),
            http_path=clean_text(path, 500),
            status_code=status,
            auth_status="failure" if status == 401 else None,
            user_agent=clean_text(agent, 300) if agent not in (None, "-") else None,
            message=clean_text(request, 1000),
            raw_line=clean_text(line, 1000),
        ))

    return ParsedRecords(records=records, malformed=tracker)
