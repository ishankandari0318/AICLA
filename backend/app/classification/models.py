"""The `Finding`: what the classification and risk stages produce and later stages (response,
report, dashboard) consume. One finding = one suspicious pattern from one source, with its evidence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

BRUTE_FORCE = "Brute Force Attack"
PORT_SCANNING = "Port Scanning"
DOS_LIKE = "DoS-like Activity"
SUSPICIOUS_LOGIN = "Suspicious Login Activity"
UNUSUAL_HTTP = "Unusual HTTP Activity"
CREDENTIAL_ATTACK = "Credential Attack Indicators"
UNKNOWN_ANOMALY = "Unknown Anomaly"

CATEGORIES = [BRUTE_FORCE, PORT_SCANNING, DOS_LIKE, SUSPICIOUS_LOGIN, UNUSUAL_HTTP, CREDENTIAL_ATTACK, UNKNOWN_ANOMALY]

SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class RiskAssessment:
    score: int                                   # 0-100
    severity: str                                # LOW / MEDIUM / HIGH / CRITICAL
    factors: list[dict[str, Any]]                # [{name, points, max_points, explanation}] - sums to `raw_score`
    raw_score: int                               # sum of factor points before any cap
    caps_applied: list[str]
    explanation: str


@dataclass
class Finding:
    finding_id: str
    category: str
    source_ip: str | None
    start: str | None
    end: str | None
    occurrences: int
    summary: str                                 # factual description of what was measured
    classification_basis: str                    # why it was put in this category
    detection_methods: list[str]                 # ["rule"], or ["rule", "isolation_forest"] when corroborated
    rule_ids: list[str]
    detection_ids: list[str]                     # the rule detections that make up this finding
    supporting_ml_detection_ids: list[str]       # Isolation Forest detections that coincide with it
    strength: float                              # observed value / rule threshold (>= 1 for rules)
    confidence: str                              # "low" | "medium" | "high"
    confidence_basis: list[str]
    services: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    usernames: list[str] = field(default_factory=list)
    paths: list[str] = field(default_factory=list)
    destination_ips: list[str] = field(default_factory=list)
    destination_ports: list[int] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)
    evidence: list[dict[str, Any]] = field(default_factory=list)
    evidence_total: int = 0
    related_finding_ids: list[str] = field(default_factory=list)   # other findings from the same IP
    risk: RiskAssessment | None = None
