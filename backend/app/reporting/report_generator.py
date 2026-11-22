"""Module 8: report generation.

Assembles one complete, JSON-ready report from the pipeline's results. EVERY number in it is
derived from the analysis of the uploaded file: nothing is hard-coded or estimated, and a metric
the log cannot provide is reported as None (so the UI can hide it) rather than as a fake zero.

The core report needs no external service. (An optional, off-by-default LLM layer could later
rephrase explanations, but it would never be allowed to add or change findings.)"""

from __future__ import annotations

import math
from datetime import datetime, timezone

import pandas as pd

from app.classification.models import SEVERITIES
from app.pipeline import Analysis
from app.reporting.models import Overview, RemediationItem, Report, ReportMeta, StatusBlock
from app.response.response_engine import build_threat_details

MAX_CHART_POINTS = 240
MAX_EVENT_TYPES = 10
TOP_N = 10
ACTIONS_PER_FINDING = 3

CLEAN_MESSAGE = "No significant anomalies or suspicious patterns were detected in the uploaded logs."
CLEAN_NOTE = ("This does not prove the system is secure. It means nothing unusual was found in the logs provided; "
              "attacks that leave no trace in these logs cannot be detected here.")
FINDINGS_NOTE = "These are indicators found by analyzing logs, not confirmed incidents. Verify each finding before acting on it."
DISCLAIMER = ("This report is generated automatically from the uploaded log file only. Findings are indicators of suspicious behaviour "
              "and may have harmless explanations. Recommended actions are suggestions: this tool never changes firewalls, blocks "
              "addresses or modifies systems.")


# ------------------------------------------------------------------ small helpers
def _pct(part: float, whole: float) -> str:
    return f"{part / whole:.1%}" if whole else "0%"


def _duration_text(start: str | None, end: str | None) -> str:
    if not (start and end):
        return ""
    fmt = "%Y-%m-%d %H:%M:%S"
    seconds = (datetime.strptime(end, fmt) - datetime.strptime(start, fmt)).total_seconds()
    if seconds < 60:
        return "under a minute"
    if seconds < 3600:
        return f"{round(seconds / 60)} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.1f} hours"
    return f"{seconds / 86400:.1f} days"


def _status(analysis: Analysis) -> StatusBlock:
    summary = analysis.risk_summary
    total, counts = summary["total_findings"], summary["severity_counts"]
    if summary["overall_status"] == "clean":
        message, note = CLEAN_MESSAGE, CLEAN_NOTE
    elif summary["overall_status"] == "critical":
        message = f"{total} suspicious pattern(s) detected, including {counts['CRITICAL']} rated CRITICAL. Investigate immediately."
        note = FINDINGS_NOTE
    else:
        message = f"{total} suspicious pattern(s) detected; the highest risk score is {summary['highest_score']}/100."
        note = FINDINGS_NOTE
    return StatusBlock(overall_status=summary["overall_status"], status_label=summary["status_label"], message=message, note=note)


def _suspicious_lines(analysis: Analysis) -> set[int]:
    """Distinct log lines behind the findings. Rule detections for rule findings, the statistical
    detection for unknown anomalies. (Corroborating ML detections are excluded: they would add
    unrelated records that happened to share the time window.)"""
    used = {detection_id for finding in analysis.findings for detection_id in finding.detection_ids}
    return {line for d in analysis.detection.detections if d.detection_id in used for line in d.record_lines}


# ------------------------------------------------------------------ charts
def _bucket_windows(windows: pd.DataFrame, window_seconds: int) -> tuple[pd.DataFrame, int]:
    """Merge consecutive windows so a chart never has more than MAX_CHART_POINTS points."""
    merge = max(1, math.ceil(len(windows) / MAX_CHART_POINTS))
    group = pd.Series(range(len(windows))) // merge
    columns = ["events", "failed_logins", "http_4xx", "http_5xx"]
    summed = windows[columns].groupby(group.to_numpy()).sum()
    summed["window"] = windows["window"].groupby(group.to_numpy()).first()
    return summed.reset_index(drop=True), window_seconds * merge


def _label(timestamp: pd.Timestamp, bucket_seconds: int) -> str:
    return timestamp.strftime("%Y-%m-%d" if bucket_seconds >= 86400 else "%Y-%m-%d %H:%M")


def _activity_charts(analysis: Analysis, suspicious: set[int]) -> tuple[dict | None, dict | None]:
    windows = analysis.features.window_features
    if windows.empty:
        return None, None
    capabilities = analysis.features.capabilities
    buckets, bucket_seconds = _bucket_windows(windows, analysis.features.window_seconds)
    labels = [_label(w, bucket_seconds) for w in buckets["window"]]

    activity = {"bucket_seconds": bucket_seconds, "labels": labels, "events": [int(v) for v in buckets["events"]],
                "failed_logins": [int(v) for v in buckets["failed_logins"]] if capabilities["has_auth_events"] else None,
                "http_4xx": [int(v) for v in buckets["http_4xx"]] if capabilities["has_http"] else None,
                "http_5xx": [int(v) for v in buckets["http_5xx"]] if capabilities["has_http"] else None}

    records = analysis.parsed.records
    flagged = records[records["line_no"].isin(suspicious)].dropna(subset=["timestamp"])
    counts = [0] * len(buckets)
    if not flagged.empty:
        start = windows["window"].iloc[0]
        index = ((flagged["timestamp"] - start) // pd.Timedelta(bucket_seconds, unit="s")).astype(int)
        for position, count in index.value_counts().items():
            if 0 <= position < len(counts):
                counts[int(position)] = int(count)
    return activity, {"bucket_seconds": bucket_seconds, "labels": labels, "values": counts}


def _event_chart(summary: dict) -> dict:
    events = summary["event_counts"]
    labels, values = list(events), list(events.values())
    other = summary["total_records"] - sum(values)
    if other > 0:
        labels.append("other"), values.append(other)
    return {"labels": labels, "values": values}


def _top_ips(findings: list) -> list[dict]:
    by_ip: dict[str, dict] = {}
    for finding in findings:
        if not finding.source_ip:
            continue
        entry = by_ip.setdefault(finding.source_ip, {"source_ip": finding.source_ip, "findings": 0, "max_risk_score": 0,
                                                     "severity": "LOW", "occurrences": 0})
        entry["findings"] += 1
        entry["occurrences"] += finding.occurrences
        if finding.risk.score > entry["max_risk_score"]:
            entry["max_risk_score"], entry["severity"] = finding.risk.score, finding.risk.severity
    return sorted(by_ip.values(), key=lambda e: -e["max_risk_score"])[:TOP_N]


# ------------------------------------------------------------------ log summary
def _log_summary(analysis: Analysis) -> dict:
    summary, capabilities = analysis.features.summary, analysis.features.capabilities
    total = summary["total_records"]
    top_ips = analysis.features.ip_summary.head(TOP_N)
    return {
        "most_frequent_events": [{"event": e, "count": c, "share": round(c / total, 4)} for e, c in summary["event_counts"].items()],
        "most_active_source_ips": [
            {"source_ip": r.source_ip, "events": int(r.events), "failed_logins": int(r.failed_logins),
             "successful_logins": int(r.successful_logins), "http_4xx": int(r.http_4xx)}
            for r in top_ips.itertuples()] if capabilities["has_source_ips"] else None,
        "authentication": {"failed_logins": summary["failed_logins"], "successful_logins": summary["successful_logins"],
                           "failed_ratio": summary["failed_login_ratio"], "unique_usernames": summary["unique_usernames"]}
        if capabilities["has_auth_events"] else None,
        "http": {"requests": summary["http_requests"], "client_errors_4xx": summary["http_4xx"], "server_errors_5xx": summary["http_5xx"],
                 "rate_4xx": summary["http_4xx_rate"], "rate_5xx": summary["http_5xx_rate"]} if capabilities["has_http"] else None,
        "network": {"unique_destination_ips": summary["unique_destination_ips"],
                    "unique_destination_ports": summary["unique_destination_ports"]} if capabilities["has_destination_ports"] else None,
    }


def _activity_summary(analysis: Analysis, log_summary: dict) -> list[str]:
    """Short factual sentences describing the log. Used by the clean-logs screen and the dashboard."""
    summary, parsed = analysis.features.summary, analysis.parsed
    lines = []
    span = f", covering {summary['start']} to {summary['end']} ({_duration_text(summary['start'], summary['end'])})" if summary["start"] else ""
    lines.append(f"{summary['total_records']:,} log entries were analyzed{span}.")
    if parsed.malformed_count:
        lines.append(f"{parsed.malformed_count:,} line(s) could not be parsed and were skipped.")
    auth = log_summary["authentication"]
    if auth:
        ratio = f" ({auth['failed_ratio']:.0%} failed)" if auth["failed_ratio"] is not None else ""
        lines.append(f"Authentication: {auth['successful_logins']:,} successful and {auth['failed_logins']:,} failed logins{ratio}.")
    web = log_summary["http"]
    if web:
        lines.append(f"HTTP: {web['requests']:,} requests; {web['client_errors_4xx']:,} client errors (4xx, {_pct(web['client_errors_4xx'], web['requests'])}) "
                     f"and {web['server_errors_5xx']:,} server errors (5xx, {_pct(web['server_errors_5xx'], web['requests'])}).")
    if log_summary["most_active_source_ips"]:
        top = log_summary["most_active_source_ips"][0]
        lines.append(f"Most active source: {top['source_ip']} with {top['events']:,} events ({summary['unique_source_ips']:,} distinct source IPs in total).")
    if log_summary["most_frequent_events"]:
        top_event = log_summary["most_frequent_events"][0]
        lines.append(f"Most common event type: {top_event['event']} ({top_event['count']:,} entries, {top_event['share']:.0%}).")
    return lines


# ------------------------------------------------------------------ public entry point
def build_report(analysis: Analysis, analyzed_at: datetime | None = None) -> Report:
    analyzed_at = analyzed_at or datetime.now(timezone.utc)
    summary, risk = analysis.features.summary, analysis.risk_summary
    details = build_threat_details(analysis.findings)
    suspicious = _suspicious_lines(analysis)
    activity_chart, suspicious_chart = _activity_charts(analysis, suspicious)
    log_summary = _log_summary(analysis)

    time_range = {"start": summary["start"], "end": summary["end"]} if summary["start"] else None
    capabilities = analysis.features.capabilities
    detection = analysis.detection
    return Report(
        meta=ReportMeta(
            filename=analysis.raw.filename, detected_format=analysis.parsed.detected_format, encoding=analysis.raw.encoding,
            size_bytes=analysis.raw.size_bytes, analyzed_at=analyzed_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            total_records=analysis.parsed.parsed_count, malformed_records=analysis.parsed.malformed_count,
            parse_warnings=analysis.parsed.warnings, line_label="Record" if analysis.parsed.detected_format == "json" else "Line", time_range=time_range),
        status=_status(analysis),
        overview=Overview(
            total_logs_processed=analysis.parsed.parsed_count, malformed_records=analysis.parsed.malformed_count,
            total_anomalies=risk["total_findings"], suspicious_events=len(suspicious),
            critical_alerts=risk["severity_counts"]["CRITICAL"], high_risk_events=risk["severity_counts"]["HIGH"],
            unique_source_ips=summary["unique_source_ips"] if capabilities["has_source_ips"] else None),
        severity_distribution=risk["severity_counts"],
        category_distribution=risk["category_counts"],
        findings=details,
        remediation_summary=[
            RemediationItem(priority=i, finding_id=d.finding_id, threat_name=d.threat_name, severity=d.severity, source_ip=d.source_ip,
                            actions=d.immediate_mitigation[:ACTIONS_PER_FINDING])
            for i, d in enumerate(details, start=1)],
        log_summary=log_summary,
        activity_summary=_activity_summary(analysis, log_summary),
        charts={
            "severity_distribution": {"labels": SEVERITIES, "values": [risk["severity_counts"][s] for s in SEVERITIES]},
            "event_type_distribution": _event_chart(summary),
            "activity_over_time": activity_chart,
            "suspicious_timeline": suspicious_chart,
            "top_suspicious_ips": _top_ips(analysis.findings),
        },
        analysis_details={
            "capabilities": capabilities,
            "rules": [{"rule_id": r.rule_id, "title": r.title, "ran": r.ran, "findings": r.findings, "skipped_reason": r.skipped_reason}
                      for r in detection.rules],
            "machine_learning": detection.ml,
            "window_seconds": analysis.features.window_seconds,
            "notes": detection.notes,
        },
        disclaimer=DISCLAIMER,
    )
