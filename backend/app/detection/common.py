"""Helpers used by the rules and by the ML detector."""

from __future__ import annotations

from typing import Callable

import pandas as pd

from app.detection.models import EVIDENCE_LIMIT, Detection, Thresholds
from app.features.feature_engineering import FeatureSet

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"
MAX_NAMES = 10
MAX_TRACKED_LINES = 20_000


def fmt_time(value) -> str | None:
    return None if pd.isna(value) else value.strftime(TIME_FORMAT)


def merge_windows(windows, window_seconds: int, max_idle_windows: int = 1) -> list[tuple[pd.Timestamp, pd.Timestamp]]:
    """Group window start-times into runs. Windows at most `max_idle_windows` apart are one run.
    Returns (start, end_exclusive) pairs."""
    size = pd.Timedelta(window_seconds, unit="s")
    limit = pd.Timedelta(window_seconds * (max_idle_windows + 1), unit="s")
    runs, start, previous = [], None, None
    for window in sorted(set(windows)):
        if start is None:
            start = previous = window
        elif window - previous <= limit:
            previous = window
        else:
            runs.append((start, previous + size))
            start = previous = window
    if start is not None:
        runs.append((start, previous + size))
    return runs


def span(rows: pd.DataFrame) -> tuple[str | None, str | None]:
    times = rows["timestamp"].dropna()
    return (fmt_time(times.min()), fmt_time(times.max())) if not times.empty else (None, None)


def build_evidence(rows: pd.DataFrame) -> tuple[list[dict], int]:
    """Pick the log lines to show as proof: all of them if few, else the first 3 and last 2.
    Every entry is a real record from the uploaded file (line number + original text)."""
    rows = rows.sort_values("timestamp", kind="stable")
    total = len(rows)
    chosen = rows if total <= EVIDENCE_LIMIT else pd.concat([rows.head(3), rows.tail(EVIDENCE_LIMIT - 3)])
    evidence = [
        {"line_no": int(row.line_no), "timestamp": fmt_time(row.timestamp), "raw_line": row.raw_line}
        for row in chosen.itertuples()
    ]
    return evidence, total


def _names(series: pd.Series, limit: int) -> list[str]:
    return [str(value) for value in series.dropna().unique()[:limit]]


class Context:
    """Everything a rule needs: the records, the features, thresholds, and fast per-IP lookups."""

    def __init__(self, records: pd.DataFrame, features: FeatureSet, thresholds: Thresholds):
        self.records = records
        self.features = features
        self.t = thresholds
        self.found: dict[str, list[Detection]] = {}   # rule_id -> detections (lets one rule see another's results)
        self._rows_by_ip: dict | None = None
        self._windows_by_ip: dict | None = None

    @property
    def window_seconds(self) -> int:
        return self.features.window_seconds

    def rows_for_ip(self, ip: str) -> pd.DataFrame:
        if self._rows_by_ip is None:
            self._rows_by_ip = dict(tuple(self.records.dropna(subset=["source_ip"]).groupby("source_ip")))
        return self._rows_by_ip[ip]

    def windows_for_ip(self, ip: str) -> pd.DataFrame:
        if self._windows_by_ip is None:
            self._windows_by_ip = dict(tuple(self.features.ip_window_features.groupby("source_ip")))
        return self._windows_by_ip[ip]

    def rows_in_range(self, ip: str | None, start, end, keep: Callable[[pd.DataFrame], pd.Series] | None = None) -> pd.DataFrame:
        """Records of one IP (or of everyone when ip is None) with start <= timestamp < end."""
        rows = self.records if ip is None else self.rows_for_ip(ip)
        mask = (rows["timestamp"] >= start) & (rows["timestamp"] < end)
        if keep is not None:
            mask &= keep(rows)
        return rows[mask]

    def make_detection(self, *, rule_id: str, description: str, rows: pd.DataFrame, source_ip: str | None,
                       metrics: dict, method: str = "rule", occurrences: int | None = None,
                       usernames: list[str] | None = None, record_rows: pd.DataFrame | None = None) -> Detection:
        """`rows` are the records shown as evidence; `record_rows` (default: the same) are ALL records the
        detection is about, used to count distinct suspicious records later."""
        evidence, total = build_evidence(rows)
        tracked = rows if record_rows is None else record_rows
        start, end = span(rows)
        return Detection(
            detection_id="",                                  # assigned once all detections are sorted
            method=method,
            rule_id=rule_id,
            description=description,
            source_ip=source_ip,
            start=start,
            end=end,
            occurrences=total if occurrences is None else occurrences,
            services=_names(rows["service"], 5),
            hosts=_names(rows["host"], 5),
            usernames=usernames if usernames is not None else _names(rows["username"], MAX_NAMES),
            paths=_names(rows["http_path"], MAX_NAMES),
            destination_ips=_names(rows["destination_ip"], MAX_NAMES),
            destination_ports=sorted(int(p) for p in rows["destination_port"].dropna().unique())[:MAX_NAMES],
            metrics=metrics,
            evidence=evidence,
            evidence_total=total,
            record_lines=[int(n) for n in tracked["line_no"].head(MAX_TRACKED_LINES)],
        )
