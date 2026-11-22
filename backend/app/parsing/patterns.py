"""Regular expressions that describe each text log format, plus a line helper.
Kept in one place so format DETECTION and PARSING can never disagree."""

from __future__ import annotations

import re

# Linux syslog, classic style:  Sep 22 10:31:21 server sshd[1234]: message
SYSLOG_3164 = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# Syslog with ISO timestamps:  2026-09-22T10:31:21+05:30 server sshd[1234]: message
SYSLOG_ISO = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+(?P<proc>[^\s:\[]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)

# Apache / Nginx "common" and "combined" access logs. Quoted parts allow \" escapes.
_QUOTED = r'(?:[^"\\]|\\.)*'
APACHE_ACCESS = re.compile(
    r"^(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<ts>[^\]]+)\] "
    rf'"(?P<req>{_QUOTED})" (?P<status>\d{{3}}) (?P<size>\S+)'
    rf'(?: "(?P<ref>{_QUOTED})" "(?P<ua>{_QUOTED})")?.*$'
)


def iter_content_lines(text: str):
    """Yield (line_number, line) for every non-empty line that is not a '#' comment.
    Line numbers refer to the original file, so evidence can point at the right line."""
    for number, line in enumerate(text.split("\n"), start=1):
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            yield number, stripped
