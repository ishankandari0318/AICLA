"""Module 2: the front door of parsing.

Detects the format (via the ingestion module), sends the text to the matching
parser, and returns ONE normalized table plus quality information
(how many lines were malformed, which fields were recognized, warnings)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

import pandas as pd

from app.errors import LogAnalysisError
from app.ingestion.format_detector import detect_format
from app.ingestion.log_reader import RawLog
from app.parsing.access_parser import parse_access
from app.parsing.patterns import iter_content_lines
from app.parsing.schema import ParsedRecords, to_frame
from app.parsing.structured_parser import parse_csv, parse_json, parse_jsonl
from app.parsing.syslog_parser import parse_syslog

FORMAT_LABELS = {
    "syslog": "Linux auth / syslog",
    "apache_access": "Apache/Nginx access log",
    "csv": "CSV",
    "json": "JSON",
    "jsonl": "JSON Lines",
}
MALFORMED_WARNING_RATIO = 0.2
MISSING_TIME_WARNING_RATIO = 0.5


@dataclass
class ParseResult:
    detected_format: str
    records: pd.DataFrame           # the normalized table (see parsing/schema.py)
    total_records: int              # parsed + malformed
    malformed_count: int
    malformed_samples: list[dict]
    recognized_fields: list[str]
    ignored_fields: list[str]
    warnings: list[str]

    @property
    def parsed_count(self) -> int:
        return len(self.records)


def parse_log(raw: RawLog, reference_time: datetime | None = None) -> ParseResult:
    """`reference_time` is only used to infer the missing year in classic syslog timestamps."""
    detected = detect_format(raw)

    if detected == "syslog":
        parsed: ParsedRecords = parse_syslog(iter_content_lines(raw.text), reference_time)
    elif detected == "apache_access":
        parsed = parse_access(iter_content_lines(raw.text))
    elif detected == "csv":
        parsed = parse_csv(raw.text)
    elif detected == "json":
        parsed = parse_json(raw.text)
    else:
        parsed = parse_jsonl(iter_content_lines(raw.text))

    label = FORMAT_LABELS[detected]
    if not parsed.records:
        first = parsed.malformed.samples[0] if parsed.malformed.samples else None
        hint = f" First problem at line {first['line']}: '{first['content']}'." if first else ""
        raise LogAnalysisError(
            "no_records",
            f"The file looks like {label}, but no valid records could be read from it.{hint}",
        )

    frame = to_frame(parsed.records)
    malformed = parsed.malformed.count
    total = len(frame) + malformed

    warnings = list(parsed.warnings)
    if malformed / total > MALFORMED_WARNING_RATIO:
        warnings.append(
            f"{malformed} of {total} lines ({malformed / total:.0%}) could not be parsed and were skipped."
        )
    if frame["timestamp"].isna().mean() > MISSING_TIME_WARNING_RATIO:
        warnings.append("Most records have no usable timestamp, so time-based analysis will be limited.")

    return ParseResult(
        detected_format=detected,
        records=frame,
        total_records=total,
        malformed_count=malformed,
        malformed_samples=parsed.malformed.samples,
        recognized_fields=parsed.recognized,
        ignored_fields=parsed.ignored,
        warnings=warnings,
    )
