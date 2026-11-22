"""The analysis pipeline in one place: parse -> features -> detect -> classify -> score.

Routes and the job manager call this instead of chaining the modules themselves.

Progress reporting (Stage 7): `analyze_log` accepts an optional `on_stage(stage_id, state)` callback.
It is called with "running" immediately before a stage's code starts and "done" immediately after
that code returns - so what the UI shows is what the server is really doing, not a timer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from app.classification.attack_classifier import classify
from app.classification.models import Finding
from app.detection.anomaly_detector import detect
from app.detection.models import DetectionResult, Thresholds
from app.features.feature_engineering import FeatureSet, extract_features
from app.ingestion.log_reader import RawLog
from app.parsing.log_parser import ParseResult, parse_log
from app.risk.risk_engine import assess, summarize

# (stage id, label shown to the user). The order is the order they run in.
# "read" happens during upload validation and "report" happens in the job manager, so this module
# runs the five stages in between; the full list of seven lives here so there is one source of truth.
STAGES: list[tuple[str, str]] = [
    ("read", "Reading uploaded logs"),
    ("parse", "Parsing and normalizing records"),
    ("features", "Extracting security features"),
    ("detect", "Running anomaly detection"),
    ("classify", "Classifying suspicious activity"),
    ("risk", "Calculating risk scores"),
    ("report", "Generating the final report"),
]

StageCallback = Callable[[str, str], None]


@dataclass
class Analysis:
    raw: RawLog
    parsed: ParseResult
    features: FeatureSet
    detection: DetectionResult
    findings: list[Finding]
    risk_summary: dict
    thresholds: Thresholds


def analyze_log(
    raw: RawLog,
    thresholds: Thresholds | None = None,
    reference_time: datetime | None = None,
    on_stage: StageCallback | None = None,
) -> Analysis:
    thresholds = thresholds or Thresholds()
    notify = on_stage or (lambda stage, state: None)

    notify("parse", "running")
    parsed = parse_log(raw, reference_time)
    notify("parse", "done")

    notify("features", "running")
    features = extract_features(parsed.records)
    notify("features", "done")

    notify("detect", "running")
    detection = detect(parsed.records, features, thresholds)
    notify("detect", "done")

    notify("classify", "running")
    classified = classify(detection.detections)
    notify("classify", "done")

    notify("risk", "running")
    findings = assess(classified)
    risk_summary = summarize(findings)
    notify("risk", "done")

    return Analysis(raw, parsed, features, detection, findings, risk_summary, thresholds)
