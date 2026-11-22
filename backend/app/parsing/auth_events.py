"""Turns the free-text MESSAGE part of an authentication log line into structured fields.

Example:
  "Failed password for invalid user admin from 192.168.1.50 port 5555 ssh2"
  -> event=failed_login, auth_status=failure, username=admin, source_ip=192.168.1.50, source_port=5555

Event names produced here (the "vocabulary" later modules rely on):
  failed_login        a failed authentication attempt (one per attempt)
  successful_login    an accepted login
  invalid_user        sshd noticed the username does not exist
  pam_auth_failure    PAM's own record of a failed attempt (supporting evidence; do not
                      count it as an extra attempt, it duplicates the "Failed password" line)
  max_auth_attempts   sshd gave up after too many tries on one connection
  connection_closed / disconnect / session_opened / session_closed / sudo_command
  no_identification / protocol_error / negotiation_failed   (typical of scanners)
  other               anything we do not recognize
"""

from __future__ import annotations

import re

_PORT = r"(?: port (?P<port>\d+))?"
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"

# (pattern, event, auth_status) - checked in order, first match wins.
_RULES = [
    (rf"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+){_PORT}", "failed_login", "failure"),
    (rf"^Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+){_PORT}", "successful_login", "success"),
    (rf"^Invalid user (?P<user>\S*) from (?P<ip>\S+){_PORT}", "invalid_user", None),
    (rf"^(?:error: )?maximum authentication attempts exceeded for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+){_PORT}", "max_auth_attempts", "failure"),
    (r"authentication failure;.*?rhost=(?P<ip>\S*)(?:\s+user=(?P<user>\S+))?", "pam_auth_failure", "failure"),
    (r"^(?P<user>\S+) : \d+ incorrect password attempts?", "failed_login", "failure"),
    (r"^(?P<user>\S+) : .*COMMAND=", "sudo_command", None),
    (r"^FAILED su for (?P<user>\S+) by", "failed_login", "failure"),
    (r"^Successful su for (?P<user>\S+) by", "successful_login", "success"),
    (r"session opened for user (?P<user>[^\s(]+)", "session_opened", None),
    (r"session closed for user (?P<user>[^\s(]+)", "session_closed", None),
    (rf"^Connection closed by (?:(?:authenticating|invalid) user (?P<user>\S+) )?{_IP} port (?P<port>\d+)", "connection_closed", None),
    (rf"^(?:Disconnected from|Received disconnect from) (?:(?:authenticating |invalid )?user (?P<user>\S+) )?{_IP}{_PORT}", "disconnect", None),
    (rf"^Did not receive identification string from (?P<ip>\S+){_PORT}", "no_identification", None),
    (rf"^Bad protocol version identification .* from (?P<ip>\S+){_PORT}", "protocol_error", None),
    (rf"^Unable to negotiate with (?P<ip>\S+){_PORT}", "negotiation_failed", None),
]
_COMPILED = [(re.compile(pattern), event, status) for pattern, event, status in _RULES]


def classify_message(message: str) -> dict:
    """Return event/auth_status/username/source_ip/source_port found in `message`.
    `matched` is False when nothing recognized the text (event is then 'other').
    Values are raw strings; callers validate them with the clean_* helpers."""
    for regex, event, status in _COMPILED:
        found = regex.search(message)
        if found:
            groups = found.groupdict()
            return {
                "matched": True,
                "event": event,
                "auth_status": status,
                "username": groups.get("user"),
                "source_ip": groups.get("ip"),
                "source_port": groups.get("port"),
            }
    return {"matched": False, "event": "other", "auth_status": None,
            "username": None, "source_ip": None, "source_port": None}
