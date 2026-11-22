"""Module 4: the detection engine's entry point.

    detect(records, features) -> DetectionResult

Runs every rule whose required information exists in the log, then the Isolation Forest, and
returns ALL findings in one list. Rule findings (method="rule") and ML findings
(method="isolation_forest") stay clearly distinguishable. Findings that overlap in time (and
share an IP, when known) list each other in `related_detection_ids`, so a statistical anomaly
that coincides with a rule finding is easy to spot (corroboration)."""

from __future__ import annotations

import pandas as pd

from app.detection.common import Context
from app.detection.ml_detector import run_isolation_forest
from app.detection.models import METHOD_ML, Detection, DetectionResult, RuleStatus, Thresholds
from app.detection.rules import REQUIREMENT_TEXT, RULES
from app.features.feature_engineering import FeatureSet


def _overlap(a: Detection, b: Detection) -> bool:
    if not (a.start and a.end and b.start and b.end):
        return False
    if a.source_ip and b.source_ip and a.source_ip != b.source_ip:
        return False
    return a.start <= b.end and b.start <= a.end        # "YYYY-MM-DD HH:MM:SS" strings sort chronologically


def _link_related(detections: list[Detection]) -> None:
    for first in detections:
        first.related_detection_ids = [second.detection_id for second in detections
                                       if second is not first and _overlap(first, second)]


def detect(records: pd.DataFrame, features: FeatureSet, thresholds: Thresholds | None = None) -> DetectionResult:
    thresholds = thresholds or Thresholds()
    ctx = Context(records, features, thresholds)
    capabilities = features.capabilities
    detections: list[Detection] = []
    statuses: list[RuleStatus] = []
    notes: list[str] = []

    for rule in RULES:
        missing = [REQUIREMENT_TEXT[need] for need in rule.requires if not capabilities[need]]
        if missing:
            statuses.append(RuleStatus(rule.rule_id, rule.title, ran=False, findings=0,
                                       skipped_reason="Needs " + ", ".join(missing) + ", which this log does not contain."))
            continue
        found = rule.run(ctx)
        if len(found) > thresholds.max_detections_per_rule:
            found = sorted(found, key=lambda d: d.occurrences, reverse=True)[: thresholds.max_detections_per_rule]
            notes.append(f"Rule '{rule.rule_id}' matched more than {thresholds.max_detections_per_rule} sources; "
                         "only the largest are listed.")
        ctx.found[rule.rule_id] = found
        detections += found
        statuses.append(RuleStatus(rule.rule_id, rule.title, ran=True, findings=len(found)))

    ml_detections, ml_status = run_isolation_forest(ctx)
    detections += ml_detections
    if not ml_status["ran"]:
        notes.append("Machine-learning detection did not run: " + ml_status["reason"])
    if not any(status.ran for status in statuses):
        notes.append("None of the detection rules could run because this log lacks the fields they need.")

    # Chronological order; at the same start, rule findings come before ML findings.
    detections.sort(key=lambda d: (d.start or "9999", d.method == METHOD_ML, d.rule_id, d.source_ip or ""))
    for number, detection in enumerate(detections, start=1):
        detection.detection_id = f"D-{number:03d}"
    _link_related(detections)

    return DetectionResult(detections=detections, rules=statuses, ml=ml_status, notes=notes)
