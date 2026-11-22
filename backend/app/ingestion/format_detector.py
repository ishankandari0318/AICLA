"""Module 1 (part 2): decide WHICH log format an uploaded file is, from its content.

We look at the content (not just the extension), because a '.txt' file can hold
syslog lines and a '.log' file can hold JSON. For line-based formats we sample the
first lines and require that most of them match."""

from __future__ import annotations

import json
from itertools import islice

from app.errors import LogAnalysisError
from app.ingestion.log_reader import RawLog
from app.parsing.patterns import APACHE_ACCESS, SYSLOG_3164, SYSLOG_ISO, iter_content_lines
from app.parsing.structured_parser import find_csv_delimiter

SAMPLE_LINES = 50
MIN_MATCH_RATIO = 0.6

SUPPORTED_FORMATS = ("json", "jsonl", "apache_access", "syslog", "csv")

UNSUPPORTED_MESSAGE = (
    "Could not recognize the format of this file. Supported formats: Linux auth/syslog lines, "
    "Apache/Nginx access logs (common or combined), CSV with a header row, JSON (a list of records) "
    "and JSON Lines. Example syslog line: "
    "'Sep 22 10:31:21 server sshd[1234]: Failed password for admin from 192.168.1.50 port 22 ssh2'."
)


def _is_json_object(line: str) -> bool:
    if not (line.startswith("{") and line.endswith("}")):
        return False
    try:
        return isinstance(json.loads(line), dict)
    except (ValueError, RecursionError):
        return False


def _ratio(lines: list[str], test) -> float:
    return sum(1 for line in lines if test(line)) / len(lines)


def detect_format(raw: RawLog) -> str:
    """Return one of SUPPORTED_FORMATS, or raise LogAnalysisError explaining what is wrong."""
    text = raw.text.strip()

    json_error = None
    if text[:1] in ("[", "{"):
        try:
            json.loads(text)
            return "json"
        except (ValueError, RecursionError) as error:
            json_error = error

    lines = [line for _, line in islice(iter_content_lines(raw.text), SAMPLE_LINES)]
    if not lines:
        raise LogAnalysisError("no_records", "The file has no log lines (only comments or blank lines).")

    if _ratio(lines, _is_json_object) >= MIN_MATCH_RATIO:
        return "jsonl"
    if _ratio(lines, lambda l: APACHE_ACCESS.match(l) is not None) >= MIN_MATCH_RATIO:
        return "apache_access"
    if _ratio(lines, lambda l: SYSLOG_ISO.match(l) or SYSLOG_3164.match(l)) >= MIN_MATCH_RATIO:
        return "syslog"
    if find_csv_delimiter(lines) is not None:
        return "csv"

    if json_error is not None and text.startswith("["):
        raise LogAnalysisError("invalid_json", f"This looks like JSON but it is not valid ({json_error}).")
    raise LogAnalysisError("unknown_format", UNSUPPORTED_MESSAGE)
