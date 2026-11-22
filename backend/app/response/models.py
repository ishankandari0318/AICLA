"""What the response engine produces for each finding: everything the threat-details screen shows."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel


class EvidenceItem(BaseModel):
    line_no: int
    timestamp: str | None
    raw_line: str | None          # untrusted log text: the frontend must escape it


class ReferenceCommands(BaseModel):
    """Example configuration or commands, shown for REFERENCE only. The application never runs them."""

    label: str
    lines: list[str]


class ThreatDetail(BaseModel):
    finding_id: str
    threat_name: str
    category: str
    severity: str
    risk_score: int
    priority: str
    confidence: str
    confidence_basis: list[str]

    description: str                       # what was measured
    why_suspicious: str                    # why that behaviour is a concern
    classification_basis: str
    possible_benign_explanations: list[str]

    source_ip: str | None
    destination_ips: list[str]
    destination_ports: list[int]
    affected_services: list[str]
    affected_hosts: list[str]
    accounts_involved: list[str]
    urls_involved: list[str]
    first_seen: str | None
    last_seen: str | None
    occurrences: int

    detection_method: str                  # human-readable
    detection_methods: list[str]
    rule_ids: list[str]
    evidence: list[EvidenceItem]
    evidence_total: int

    possible_impact: list[str]
    recommended_solutions: list[str]
    immediate_mitigation: list[str]
    reference_commands: list[ReferenceCommands]

    risk_explanation: str
    risk_factors: list[dict[str, Any]]
    risk_caps: list[str]
    related_finding_ids: list[str]
