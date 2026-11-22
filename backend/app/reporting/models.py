"""The complete analysis report: the single JSON document the frontend renders."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.response.models import ThreatDetail


class ReportMeta(BaseModel):
    filename: str
    detected_format: str
    encoding: str
    size_bytes: int
    analyzed_at: str                      # UTC
    total_records: int                    # records successfully parsed
    malformed_records: int
    parse_warnings: list[str]
    line_label: str                       # "Line" for text logs, "Record" for a JSON array (numbers are record positions)
    time_range: dict[str, str] | None     # {"start", "end"}; None when the log has no usable timestamps


class StatusBlock(BaseModel):
    overall_status: str                   # "clean" | "suspicious" | "critical"
    status_label: str                     # the text shown on the dashboard
    message: str
    note: str


class Overview(BaseModel):
    """Values for the overview cards. A metric the log cannot provide is None, never a made-up 0."""

    total_logs_processed: int
    malformed_records: int
    total_anomalies: int                  # number of findings
    suspicious_events: int                # DISTINCT log records behind all findings
    critical_alerts: int                  # findings with severity CRITICAL
    high_risk_events: int                 # findings with severity HIGH
    unique_source_ips: int | None


class RemediationItem(BaseModel):
    priority: int
    finding_id: str
    threat_name: str
    severity: str
    source_ip: str | None
    actions: list[str]


class Report(BaseModel):
    meta: ReportMeta
    status: StatusBlock
    overview: Overview
    severity_distribution: dict[str, int]
    category_distribution: dict[str, int]
    findings: list[ThreatDetail]
    remediation_summary: list[RemediationItem]
    log_summary: dict[str, Any]
    activity_summary: list[str]
    charts: dict[str, Any]
    analysis_details: dict[str, Any]
    disclaimer: str
