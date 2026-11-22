"""Parsers for CSV, JSON and JSON Lines.

These formats have no fixed field names, so we map whatever names the file uses
(src_ip, SourceIP, source.ip, ...) onto our normalized columns using ALIASES."""

from __future__ import annotations

import csv
import io
import json
import re

import pandas as pd

from app.errors import LogAnalysisError
from app.parsing.auth_events import classify_message
from app.parsing.schema import (
    COLUMNS, MalformedTracker, ParsedRecords, clean_ip, clean_method, clean_port,
    clean_protocol, clean_status, clean_text, http_event, make_record, slugify,
)

# canonical column -> field names we accept (compared after _norm_key()).
ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "@timestamp", "ts", "event_time",
                  "eventtime", "created_at", "log_time", "date_time"],
    "source_ip": ["source_ip", "src_ip", "srcip", "src", "source", "source_address", "client_ip",
                  "remote_addr", "remote_ip", "ip", "ip_address", "source.ip", "client.ip", "id.orig_h"],
    "destination_ip": ["destination_ip", "dst_ip", "dstip", "dest_ip", "dst", "dest", "destination",
                       "destination_address", "destination.ip", "id.resp_h"],
    "source_port": ["source_port", "src_port", "sport", "srcport", "source.port", "id.orig_p"],
    "destination_port": ["destination_port", "dst_port", "dport", "dest_port", "dstport",
                         "destination.port", "id.resp_p"],
    "username": ["username", "user", "user_name", "account", "login", "uid", "user.name"],
    "event": ["event", "event_type", "action", "event_name", "eventtype", "activity", "event.action"],
    "service": ["service", "app", "application", "process", "program", "daemon"],
    "host": ["host", "hostname", "server", "computer", "machine", "host.name"],
    "protocol": ["protocol", "proto", "network.protocol"],
    "message": ["message", "msg", "log", "text", "description", "details"],
    "http_method": ["method", "http_method", "request_method", "http.request.method"],
    "http_path": ["path", "url", "uri", "request_uri", "request", "url.path"],
    "user_agent": ["user_agent", "useragent", "ua", "user_agent.original"],
    "status_code": ["status_code", "http_status", "response_code", "statuscode", "http.response.status_code"],
    "auth_status": ["auth_status", "outcome", "login_status", "result", "event.outcome"],
    # "status" is ambiguous: a number is an HTTP status, a word is a login result.
    "status_any": ["status"],
}

EVENT_SYNONYMS = {
    "failed_login": {"failed_login", "login_failed", "login_failure", "logon_failure", "failed_logon",
                     "authentication_failure", "auth_failure", "auth_failed", "failed_password",
                     "failed_authentication", "invalid_login", "failed", "failure"},
    "successful_login": {"successful_login", "login_success", "login_successful", "logon_success",
                         "successful_logon", "authentication_success", "auth_success", "accepted",
                         "accepted_password", "success"},
}
AUTH_FOR_EVENT = {"failed_login": "failure", "successful_login": "success"}
_SUCCESS_WORDS = {"success", "succeeded", "successful", "accepted", "ok", "allow", "allowed", "passed", "pass"}
_FAILURE_WORDS = {"failure", "failed", "fail", "denied", "deny", "rejected", "reject", "invalid", "unauthorized"}

CSV_DELIMITERS = [",", ";", "\t", "|"]
MAX_FLATTEN_DEPTH = 5
WRAPPER_KEYS = ("records", "logs", "events", "entries", "data", "items", "results")


def _norm_key(key) -> str:
    return re.sub(r"[^a-z0-9.@]+", "_", str(key).strip().lower()).strip("_")


_LOOKUP = {_norm_key(alias): canonical for canonical, names in ALIASES.items() for alias in names}


# ------------------------------------------------------------------ CSV
def find_csv_delimiter(lines: list[str]) -> str | None:
    """Pick the delimiter that splits (almost) every sampled line into the same number of columns."""
    sample = lines[:20]
    if len(sample) < 2:
        return None
    for delimiter in CSV_DELIMITERS:
        counts = [len(row) for row in csv.reader(sample, delimiter=delimiter)]
        if counts[0] >= 2 and sum(1 for c in counts if c == counts[0]) / len(counts) >= 0.8:
            return delimiter
    return None


def parse_csv(text: str) -> ParsedRecords:
    lines = [line for line in text.split("\n") if line.strip() and not line.lstrip().startswith("#")]
    delimiter = find_csv_delimiter(lines)
    if delimiter is None:
        raise LogAnalysisError("unknown_format", "This CSV file could not be split into consistent columns.")

    tracker = MalformedTracker()
    warnings: list[str] = []
    header: list[str] | None = None
    rows = []
    try:
        text_lines = text.split("\n")
        reader = csv.reader(io.StringIO(text), delimiter=delimiter)
        previous_end = 0
        for row in reader:
            # Physical line numbers (a quoted cell may span lines), so evidence points at the real line in the upload.
            first_line, previous_end = previous_end + 1, reader.line_num
            if not row or all(not cell.strip() for cell in row) or row[0].lstrip().startswith("#"):
                continue
            record_no = first_line
            if header is None:
                header = [cell.strip() for cell in row]
            elif len(row) != len(header):
                tracker.add(record_no, delimiter.join(row))
            else:
                # Show the original CSV line as evidence (not a re-serialized copy); fall back for multi-line rows.
                original = text_lines[first_line - 1] if first_line == reader.line_num else json.dumps(dict(zip(header, row)), ensure_ascii=False)
                rows.append((record_no, dict(zip(header, row)), original))
    except csv.Error as error:
        warnings.append(f"Stopped reading the CSV early: {clean_text(error, 150)}.")
    return _build(rows, set(header or []), tracker, warnings)


# ------------------------------------------------------------------ JSON / JSONL
def _flatten(obj: dict, prefix: str = "", depth: int = 0) -> dict:
    flat = {}
    for key, value in obj.items():
        name = f"{prefix}{key}"
        if isinstance(value, dict) and depth < MAX_FLATTEN_DEPTH:
            flat.update(_flatten(value, name + ".", depth + 1))
        elif isinstance(value, (dict, list, tuple)):
            flat[name] = json.dumps(value, ensure_ascii=False, default=str)
        else:
            flat[name] = value
    return flat


def _row(record_no: int, obj: dict):
    return record_no, _flatten(obj), json.dumps(obj, ensure_ascii=False, default=str)


def parse_json(text: str) -> ParsedRecords:
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as error:
        raise LogAnalysisError("invalid_json", f"This file is not valid JSON ({clean_text(error, 150)}).")

    if isinstance(data, dict):
        lowered = {str(k).lower(): v for k, v in data.items()}
        wrapped = next((lowered[k] for k in WRAPPER_KEYS if isinstance(lowered.get(k), list)), None)
        items = wrapped if wrapped is not None else [data]
    elif isinstance(data, list):
        items = data
    else:
        raise LogAnalysisError("invalid_json", "The JSON must be a list of log records or a single record object.")

    tracker = MalformedTracker()
    rows = []
    for index, item in enumerate(items, start=1):
        if isinstance(item, dict):
            rows.append(_row(index, item))
        else:
            tracker.add(index, json.dumps(item, ensure_ascii=False, default=str))
    return _build(rows, {key for _, flat, _ in rows for key in flat}, tracker, [])


def parse_jsonl(lines) -> ParsedRecords:
    tracker = MalformedTracker()
    rows = []
    for line_no, line in lines:
        try:
            obj = json.loads(line)
        except (ValueError, RecursionError):
            tracker.add(line_no, line)
            continue
        if isinstance(obj, dict):
            rows.append(_row(line_no, obj))
        else:
            tracker.add(line_no, line)
    return _build(rows, {key for _, flat, _ in rows for key in flat}, tracker, [])


# ------------------------------------------------------------------ shared mapping logic
def parse_timestamps(values) -> pd.Series:
    """Many representations -> naive UTC datetimes: ISO strings, common date formats,
    and numeric epochs (seconds, or milliseconds when the number is very large)."""
    series = pd.Series(list(values), dtype="object")
    result = pd.Series(pd.NaT, index=series.index, dtype="datetime64[ns, UTC]")
    if series.empty:
        return result.dt.tz_localize(None)
    numeric = pd.to_numeric(series, errors="coerce")
    is_number = numeric.notna()
    as_text = series.notna() & ~is_number
    if as_text.any():
        result[as_text] = pd.to_datetime(series[as_text].astype(str), errors="coerce", utc=True, format="mixed")
    seconds = is_number & (numeric.abs() < 1e11)
    millis = is_number & ~seconds
    if seconds.any():
        result[seconds] = pd.to_datetime(numeric[seconds], unit="s", errors="coerce", utc=True)
    if millis.any():
        result[millis] = pd.to_datetime(numeric[millis], unit="ms", errors="coerce", utc=True)
    return result.dt.tz_localize(None)


def _canonical_event(value) -> str:
    slug = slugify(value)
    for canonical, synonyms in EVENT_SYNONYMS.items():
        if slug in synonyms:
            return canonical
    return slug or "other"


def _canonical_auth_status(value) -> str | None:
    slug = slugify(value) if value is not None else ""
    if slug in _SUCCESS_WORDS:
        return "success"
    if slug in _FAILURE_WORDS:
        return "failure"
    return None


def _map_fields(flat: dict):
    """Pick out the fields we understand from one record. Returns (fields, keys_used)."""
    fields, used = {}, set()
    for key, value in flat.items():
        canonical = _LOOKUP.get(_norm_key(key))
        if canonical is None:
            continue
        if isinstance(value, str):
            value = value.strip()
        if value is None or value == "":
            continue
        if canonical == "status_any":
            canonical = "status_code" if clean_status(value) is not None else "auth_status"
        if canonical not in fields:
            fields[canonical] = value
            used.add(key)
    return fields, used


def _build_record(record_no: int, fields: dict, raw_text: str) -> dict:
    message = clean_text(fields.get("message"), 1000)
    info = classify_message(message) if message else None
    if info is not None and not info["matched"]:
        info = None  # the message was not an auth message; ignore it

    status_code = clean_status(fields.get("status_code"))
    if "event" in fields:
        event = _canonical_event(fields["event"])
    elif info is not None:
        event = info["event"]
    elif status_code is not None:
        event = http_event(status_code)
    else:
        event = "other"

    auth_status = _canonical_auth_status(fields.get("auth_status"))
    if auth_status is None:
        auth_status = AUTH_FOR_EVENT.get(event) or (info["auth_status"] if info else None)
    if auth_status is None and status_code == 401:
        auth_status = "failure"

    pick = lambda name, key: fields.get(name) if fields.get(name) is not None else (info[key] if info else None)
    return make_record(
        line_no=record_no,
        timestamp=fields.get("timestamp"),   # converted in bulk by _build()
        host=clean_text(fields.get("host"), 100),
        service=clean_text(fields.get("service"), 64),
        event=event,
        username=clean_text(pick("username", "username"), 64),
        source_ip=clean_ip(pick("source_ip", "source_ip")),
        destination_ip=clean_ip(fields.get("destination_ip")),
        source_port=clean_port(pick("source_port", "source_port")),
        destination_port=clean_port(fields.get("destination_port")),
        protocol=clean_protocol(fields.get("protocol")),
        http_method=clean_method(fields.get("http_method")),
        http_path=clean_text(fields.get("http_path"), 500),
        status_code=status_code,
        auth_status=auth_status,
        user_agent=clean_text(fields.get("user_agent"), 300),
        message=message,
        raw_line=clean_text(raw_text, 1000),
    )


def _build(rows, all_keys: set, tracker: MalformedTracker, warnings: list) -> ParsedRecords:
    records: list[dict] = []
    recognized_keys: set = set()
    recognized_columns: set = set()

    for record_no, flat, raw_text in rows:
        fields, used = _map_fields(flat)
        if not fields:
            tracker.add(record_no, raw_text)
            continue
        recognized_keys |= used
        recognized_columns |= set(fields)
        records.append(_build_record(record_no, fields, raw_text))

    if (records or tracker.count) and len(recognized_columns) < 2:
        found = ", ".join(sorted(clean_text(k, 40) or "" for k in all_keys)[:15]) or "none"
        raise LogAnalysisError(
            "no_recognized_fields",
            f"Fewer than two fields in this file match what the analyzer understands (fields found: {found}). "
            "Use names such as: timestamp, source_ip (or src_ip), destination_ip, destination_port, "
            "username (or user), event (or action), status_code, message.",
        )

    timestamps = parse_timestamps(r["timestamp"] for r in records)
    for record, value in zip(records, timestamps):
        record["timestamp"] = value

    ignored = sorted(clean_text(k, 40) or "" for k in all_keys - recognized_keys)[:20]
    return ParsedRecords(
        records=records,
        malformed=tracker,
        recognized=[c for c in COLUMNS if c in recognized_columns],
        ignored=ignored,
        warnings=warnings,
    )
