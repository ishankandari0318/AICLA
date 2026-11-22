"""Pydantic models describing what the API sends back (also validates it)."""

from __future__ import annotations

from dataclasses import asdict
from typing import Any

from pydantic import BaseModel

from app.detection.models import DetectionResult, Thresholds
from app.pipeline import Analysis
from app.features.feature_engineering import FeatureSet
from app.ingestion.log_reader import RawLog
from app.parsing.log_parser import ParseResult
from app.parsing.schema import frame_to_json_records

PREVIEW_ROWS = 20


class MalformedSample(BaseModel):
    line: int
    content: str


class TimeRange(BaseModel):
    start: str
    end: str


class ParsePreview(BaseModel):
    filename: str
    size_bytes: int
    encoding: str
    detected_format: str
    total_records: int
    parsed_records: int
    malformed_records: int
    malformed_samples: list[MalformedSample]
    recognized_fields: list[str]
    ignored_fields: list[str]
    warnings: list[str]
    time_range: TimeRange | None
    field_coverage: dict[str, int]      # column -> how many records have a value
    preview: list[dict[str, Any]]       # first rows of the normalized table

    @classmethod
    def from_parse(cls, raw: RawLog, result: ParseResult) -> "ParsePreview":
        frame = result.records
        times = frame["timestamp"].dropna()
        time_range = None
        if not times.empty:
            fmt = "%Y-%m-%d %H:%M:%S"
            time_range = TimeRange(start=times.min().strftime(fmt), end=times.max().strftime(fmt))
        return cls(
            filename=raw.filename,
            size_bytes=raw.size_bytes,
            encoding=raw.encoding,
            detected_format=result.detected_format,
            total_records=result.total_records,
            parsed_records=result.parsed_count,
            malformed_records=result.malformed_count,
            malformed_samples=result.malformed_samples,
            recognized_fields=result.recognized_fields,
            ignored_fields=result.ignored_fields,
            warnings=result.warnings,
            time_range=time_range,
            field_coverage={column: int(count) for column, count in frame.notna().sum().items()},
            preview=frame_to_json_records(frame, PREVIEW_ROWS),
        )


class FeaturesPreview(BaseModel):
    """Stage 3 validation view: what the feature engineering produced for an uploaded file."""

    filename: str
    detected_format: str
    window_seconds: int
    window_count: int
    summary: dict[str, Any]
    capabilities: dict[str, bool]
    top_ips: list[dict[str, Any]]          # ip_summary rows for the busiest source IPs
    busiest_windows: list[dict[str, Any]]  # window_features rows with the most events

    @classmethod
    def from_features(cls, raw: RawLog, result: ParseResult, features: FeatureSet) -> "FeaturesPreview":
        windows = features.window_features
        busiest = windows.sort_values("events", ascending=False, kind="stable").head(5)
        return cls(
            filename=raw.filename,
            detected_format=result.detected_format,
            window_seconds=features.window_seconds,
            window_count=len(windows),
            summary=features.summary,
            capabilities=features.capabilities,
            top_ips=frame_to_json_records(features.ip_summary, 10),
            busiest_windows=frame_to_json_records(busiest),
        )


class EvidenceLine(BaseModel):
    line_no: int
    timestamp: str | None
    raw_line: str | None


class DetectionOut(BaseModel):
    detection_id: str
    method: str                    # "rule" or "isolation_forest"
    rule_id: str
    description: str
    source_ip: str | None
    start: str | None
    end: str | None
    occurrences: int
    services: list[str]
    hosts: list[str]
    usernames: list[str]
    paths: list[str]
    destination_ips: list[str]
    destination_ports: list[int]
    metrics: dict[str, Any]
    evidence: list[EvidenceLine]
    evidence_total: int
    related_detection_ids: list[str]


class RuleStatusOut(BaseModel):
    rule_id: str
    title: str
    ran: bool
    findings: int
    skipped_reason: str | None


class DetectionPreview(BaseModel):
    """Stage 4 validation view: what the detection engine found in an uploaded file."""

    filename: str
    detected_format: str
    total_records: int
    rule_findings: int
    ml_findings: int
    rules: list[RuleStatusOut]
    ml: dict[str, Any]
    detections: list[DetectionOut]
    notes: list[str]
    thresholds: dict[str, Any]

    @classmethod
    def from_detection(cls, raw: RawLog, parsed: ParseResult, result: DetectionResult, thresholds: Thresholds) -> "DetectionPreview":
        return cls(
            filename=raw.filename,
            detected_format=parsed.detected_format,
            total_records=parsed.parsed_count,
            rule_findings=sum(d.method == "rule" for d in result.detections),
            ml_findings=sum(d.method == "isolation_forest" for d in result.detections),
            rules=[RuleStatusOut(**asdict(status)) for status in result.rules],
            ml=result.ml,
            detections=[DetectionOut(**{k: v for k, v in asdict(d).items() if k != "record_lines"}) for d in result.detections],
            notes=result.notes,
            thresholds=asdict(thresholds),
        )


class RiskOut(BaseModel):
    score: int
    severity: str
    factors: list[dict[str, Any]]
    raw_score: int
    caps_applied: list[str]
    explanation: str


class FindingOut(BaseModel):
    finding_id: str
    category: str
    source_ip: str | None
    start: str | None
    end: str | None
    occurrences: int
    summary: str
    classification_basis: str
    detection_methods: list[str]
    rule_ids: list[str]
    detection_ids: list[str]
    supporting_ml_detection_ids: list[str]
    strength: float
    confidence: str
    confidence_basis: list[str]
    services: list[str]
    hosts: list[str]
    usernames: list[str]
    paths: list[str]
    destination_ips: list[str]
    destination_ports: list[int]
    metrics: dict[str, Any]
    evidence: list[EvidenceLine]
    evidence_total: int
    related_finding_ids: list[str]
    risk: RiskOut


class FindingsPreview(BaseModel):
    """Stage 5 validation view: classified, risk-scored findings, worst first."""

    filename: str
    detected_format: str
    total_records: int
    risk_summary: dict[str, Any]
    findings: list[FindingOut]
    notes: list[str]

    @classmethod
    def from_analysis(cls, analysis: Analysis) -> "FindingsPreview":
        return cls(
            filename=analysis.raw.filename,
            detected_format=analysis.parsed.detected_format,
            total_records=analysis.parsed.parsed_count,
            risk_summary=analysis.risk_summary,
            findings=[FindingOut(**asdict(f)) for f in analysis.findings],
            notes=analysis.detection.notes,
        )


class JobStage(BaseModel):
    id: str
    label: str
    state: str          # "pending" | "running" | "done" | "failed"


class JobError(BaseModel):
    code: str
    message: str


class JobStatus(BaseModel):
    """Progress of one background analysis (Stage 7). Every stage state is reported by the code that runs it."""

    job_id: str
    filename: str
    status: str         # "queued" | "running" | "done" | "error"
    stages: list[JobStage]
    error: JobError | None = None
