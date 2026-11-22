"""Data structures shared by every part of the detection engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

METHOD_RULE = "rule"
METHOD_ML = "isolation_forest"
EVIDENCE_LIMIT = 5          # evidence lines stored per detection (the first 3 and last 2 when there are more)


@dataclass(frozen=True)
class Thresholds:
    """Every tunable number in one place. Each rule explains itself with these values,
    so a result can always say *which* threshold was crossed."""

    # --- authentication rules
    failed_login_burst_per_window: int = 10     # failed logins from ONE IP inside ONE window
    repeated_failed_logins_total: int = 20      # slow-and-low: total failures from one IP over the whole log
    failed_usernames_per_ip: int = 5            # distinct usernames one IP failed against
    success_after_failures_min: int = 5         # failures that must precede a success from the same IP
    success_lookback_seconds: int = 1800        # ...within this many seconds
    ssh_probe_events: int = 5                   # protocol-probing events from one IP
    # --- network rule
    port_scan_ports_per_window: int = 10        # distinct destination ports one IP touched in ONE window
    # --- HTTP rules
    http_flood_requests_per_window: int = 200   # requests from ONE IP inside ONE window
    http_probe_min_4xx: int = 30
    http_probe_min_4xx_rate: float = 0.6
    http_probe_min_paths: int = 5               # distinct URLs (separates scanning from password guessing)
    http_401_total: int = 20                    # HTTP 401 responses to one IP
    http_5xx_min_requests: int = 20             # a window needs this many requests to judge its error rate
    http_5xx_rate: float = 0.3
    # --- machine learning
    ml_min_active_windows: int = 20             # fewer active windows = no statistical baseline
    ml_contamination: float = 0.05              # at most this share of windows is flagged by the model
    ml_min_deviation: float = 8.0               # ...and must also be this far above typical (see ml_detector)
    # --- output size
    max_detections_per_rule: int = 100


@dataclass
class Detection:
    """One suspicious finding. It states WHAT was observed and the evidence;
    classification (Stage 5) decides what category it belongs to."""

    detection_id: str
    method: str                       # "rule" or "isolation_forest" - never mixed up
    rule_id: str
    description: str                  # factual one-liner (numbers only, no verdicts)
    source_ip: str | None
    start: str | None
    end: str | None
    occurrences: int                  # how many log records support it
    services: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)          # URLs involved (HTTP logs)
    destination_ips: list[str] = field(default_factory=list)
    destination_ports: list[int] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_total: int = 0
    related_detection_ids: list[str] = field(default_factory=list)   # overlapping in time (and same IP, if known)
    # Every log line number behind this detection (capped). Used by the report to count DISTINCT
    # suspicious records. Not part of the API output.
    record_lines: list[int] = field(default_factory=list, repr=False)


@dataclass
class RuleStatus:
    """Was a rule able to run on this log, and what did it find?"""

    rule_id: str
    title: str
    ran: bool
    findings: int
    skipped_reason: str | None = None


@dataclass
class DetectionResult:
    detections: list[Detection]
    rules: list[RuleStatus]
    ml: dict[str, Any]
    notes: list[str]
