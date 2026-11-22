"""Module 3: Feature engineering.

Turns the normalized table of events (Module 2) into NUMBERS that describe behaviour.
Detection rules and the Isolation Forest never look at raw log lines; they look at these tables.

Three levels of features are produced:

  window_features     one row per time window (default 1 minute) for the WHOLE log.
                      Answers: "how busy / how failing was the system in this minute?"
  ip_window_features  one row per (window, source IP) that was active.
                      Answers: "what did THIS address do in this minute?"
  ip_summary          one row per source IP over the whole log (totals and peaks).

Plus `summary` (headline numbers for the dashboard) and `capabilities` (which kinds of
analysis this log can honestly support, e.g. a web log has no login events).

Windows are "tumbling": fixed, non-overlapping slots (10:00:00-10:00:59, 10:01:00-...).
A burst that straddles a boundary is split across two windows, so detection thresholds
should leave some margin."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd

DEFAULT_WINDOW_SECONDS = 60
MAX_WINDOWS = 20_000                        # keeps tables small for very long logs
WINDOW_CHOICES = [60, 300, 900, 3600, 21600, 86400]
MIN_TIMESTAMP_COVERAGE = 0.5                # share of records needing a timestamp for time-based analysis
TOP_N = 10
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Column order matters: the ML stage will use WINDOW_FEATURE_COLUMNS as its input vector.
WINDOW_FEATURE_COLUMNS = [
    "events", "events_per_minute", "failed_logins", "successful_logins", "failed_login_ratio",
    "unique_source_ips", "unique_usernames", "unique_dest_ports",
    "http_requests", "http_4xx", "http_5xx", "http_4xx_rate", "http_5xx_rate",
    "max_events_per_ip", "mean_gap_seconds",
]
IP_WINDOW_FEATURE_COLUMNS = [
    "events", "failed_logins", "successful_logins", "failed_login_ratio",
    "unique_usernames", "unique_failed_usernames", "unique_dest_ports", "unique_paths",
    "http_requests", "http_4xx", "http_5xx", "http_4xx_rate", "http_401",
    "mean_gap_seconds", "min_gap_seconds",
]
IP_SUMMARY_COLUMNS = [
    "source_ip", "events", "first_seen", "last_seen",
    "failed_logins", "successful_logins", "unique_usernames", "unique_failed_usernames",
    "unique_dest_ports", "unique_paths",
    "http_requests", "http_4xx", "http_5xx", "http_401",
    "peak_events_per_window", "peak_failed_logins_per_window", "peak_window",
]


@dataclass
class FeatureSet:
    window_seconds: int
    summary: dict
    capabilities: dict
    window_features: pd.DataFrame
    ip_window_features: pd.DataFrame
    ip_summary: pd.DataFrame


# ------------------------------------------------------------------ small helpers
def pick_window_seconds(span_seconds: float, requested: int = DEFAULT_WINDOW_SECONDS) -> int:
    """Use the requested window size, but go coarser if the log spans so long that
    we would otherwise create an enormous number of windows."""
    if requested <= 0:
        raise ValueError("window size must be positive")
    candidates = [requested] + [w for w in WINDOW_CHOICES if w > requested]
    for size in candidates:
        if span_seconds / size <= MAX_WINDOWS:
            return size
    return candidates[-1]


def _flag(series: pd.Series) -> pd.Series:
    """Boolean column with missing values treated as False."""
    return series.fillna(False).astype(bool)


def _ratio(numerator: pd.Series, denominator: pd.Series) -> pd.Series:
    """numerator / denominator, with 0.0 wherever the denominator is 0."""
    return (numerator / denominator.where(denominator > 0)).fillna(0.0)


def _with_flags(records: pd.DataFrame) -> pd.DataFrame:
    """Add True/False helper columns that make the aggregations below easy to read."""
    out = records.copy()
    status = out["status_code"]
    out["is_failed"] = _flag(out["event"] == "failed_login")
    out["is_success"] = _flag(out["event"] == "successful_login")
    out["is_http"] = _flag(status.notna() | out["http_method"].notna())
    out["is_4xx"] = _flag(status.between(400, 499))
    out["is_5xx"] = _flag(status.between(500, 599))
    out["is_401"] = _flag(status == 401)
    out["failed_username"] = out["username"].where(out["is_failed"])   # the username, only on failed-login rows
    return out


def _fmt(value) -> str | None:
    return None if pd.isna(value) else value.strftime(TIME_FORMAT)


# ------------------------------------------------------------------ the three feature tables
def _window_features(timed: pd.DataFrame, window_seconds: int, ip_windows: pd.DataFrame) -> pd.DataFrame:
    if timed.empty:
        return pd.DataFrame(columns=["window"] + WINDOW_FEATURE_COLUMNS)

    table = timed.groupby("window").agg(
        events=("timestamp", "size"),
        failed_logins=("is_failed", "sum"),
        successful_logins=("is_success", "sum"),
        unique_source_ips=("source_ip", "nunique"),
        unique_usernames=("username", "nunique"),
        unique_dest_ports=("destination_port", "nunique"),
        http_requests=("is_http", "sum"),
        http_4xx=("is_4xx", "sum"),
        http_5xx=("is_5xx", "sum"),
        mean_gap_seconds=("gap", "mean"),
    )
    # Include windows in which nothing happened: quiet minutes are part of "normal" too.
    full_range = pd.date_range(table.index.min(), table.index.max(), freq=f"{window_seconds}s")
    table = table.reindex(full_range)
    table.index.name = "window"

    count_columns = [c for c in table.columns if c != "mean_gap_seconds"]
    table[count_columns] = table[count_columns].fillna(0).astype(int)

    busiest_ip = ip_windows.groupby("window")["events"].max() if not ip_windows.empty else pd.Series(dtype=int)
    table["max_events_per_ip"] = busiest_ip.reindex(full_range).fillna(0).astype(int)

    table["events_per_minute"] = table["events"] * 60 / window_seconds
    table["failed_login_ratio"] = _ratio(table["failed_logins"], table["failed_logins"] + table["successful_logins"])
    table["http_4xx_rate"] = _ratio(table["http_4xx"], table["http_requests"])
    table["http_5xx_rate"] = _ratio(table["http_5xx"], table["http_requests"])
    table["mean_gap_seconds"] = table["mean_gap_seconds"].fillna(window_seconds)
    return table[WINDOW_FEATURE_COLUMNS].reset_index()


def _ip_window_features(timed_ip: pd.DataFrame, window_seconds: int) -> pd.DataFrame:
    if timed_ip.empty:
        return pd.DataFrame(columns=["window", "source_ip"] + IP_WINDOW_FEATURE_COLUMNS)

    table = timed_ip.groupby(["window", "source_ip"]).agg(
        events=("timestamp", "size"),
        failed_logins=("is_failed", "sum"),
        successful_logins=("is_success", "sum"),
        unique_usernames=("username", "nunique"),
        unique_failed_usernames=("failed_username", "nunique"),
        unique_dest_ports=("destination_port", "nunique"),
        unique_paths=("http_path", "nunique"),
        http_requests=("is_http", "sum"),
        http_4xx=("is_4xx", "sum"),
        http_5xx=("is_5xx", "sum"),
        http_401=("is_401", "sum"),
        mean_gap_seconds=("ip_gap", "mean"),
        min_gap_seconds=("ip_gap", "min"),
    ).reset_index()

    table["failed_login_ratio"] = _ratio(table["failed_logins"], table["failed_logins"] + table["successful_logins"])
    table["http_4xx_rate"] = _ratio(table["http_4xx"], table["http_requests"])
    # No earlier event from this IP to compare with -> treat as "a full window apart".
    table[["mean_gap_seconds", "min_gap_seconds"]] = table[["mean_gap_seconds", "min_gap_seconds"]].fillna(window_seconds)
    return table[["window", "source_ip"] + IP_WINDOW_FEATURE_COLUMNS]


def _ip_summary(records_ip: pd.DataFrame, ip_windows: pd.DataFrame) -> pd.DataFrame:
    if records_ip.empty:
        return pd.DataFrame(columns=IP_SUMMARY_COLUMNS)

    # Uniques are computed from the raw records (summing per-window uniques would double count).
    table = records_ip.groupby("source_ip").agg(
        events=("event", "size"),
        first_seen=("timestamp", "min"),
        last_seen=("timestamp", "max"),
        failed_logins=("is_failed", "sum"),
        successful_logins=("is_success", "sum"),
        unique_usernames=("username", "nunique"),
        unique_failed_usernames=("failed_username", "nunique"),
        unique_dest_ports=("destination_port", "nunique"),
        unique_paths=("http_path", "nunique"),
        http_requests=("is_http", "sum"),
        http_4xx=("is_4xx", "sum"),
        http_5xx=("is_5xx", "sum"),
        http_401=("is_401", "sum"),
    )
    table["peak_events_per_window"] = 0
    table["peak_failed_logins_per_window"] = 0
    table["peak_window"] = pd.NaT
    if not ip_windows.empty:
        peaks = ip_windows.groupby("source_ip").agg(
            peak_events_per_window=("events", "max"),
            peak_failed_logins_per_window=("failed_logins", "max"),
        )
        busiest = ip_windows.loc[ip_windows.groupby("source_ip")["events"].idxmax()].set_index("source_ip")["window"]
        table["peak_events_per_window"] = peaks["peak_events_per_window"].reindex(table.index).fillna(0).astype(int)
        table["peak_failed_logins_per_window"] = peaks["peak_failed_logins_per_window"].reindex(table.index).fillna(0).astype(int)
        table["peak_window"] = busiest.reindex(table.index)
    table = table.sort_values("events", ascending=False, kind="stable").reset_index()
    return table[IP_SUMMARY_COLUMNS]


# ------------------------------------------------------------------ headline numbers
def _summary(records: pd.DataFrame, flagged: pd.DataFrame) -> dict:
    total = len(records)
    timestamps = records["timestamp"].dropna()
    failed, success = int(flagged["is_failed"].sum()), int(flagged["is_success"].sum())
    http, c4xx, c5xx = int(flagged["is_http"].sum()), int(flagged["is_4xx"].sum()), int(flagged["is_5xx"].sum())

    event_counts = records["event"].value_counts().head(TOP_N)
    top_ips = records["source_ip"].value_counts().head(TOP_N)
    start = timestamps.min() if not timestamps.empty else pd.NaT
    end = timestamps.max() if not timestamps.empty else pd.NaT
    return {
        "total_records": total,
        "records_with_timestamp": int(len(timestamps)),
        "records_without_timestamp": total - int(len(timestamps)),
        "records_without_source_ip": int(records["source_ip"].isna().sum()),
        "start": _fmt(start),
        "end": _fmt(end),
        "duration_seconds": None if timestamps.empty else float((end - start).total_seconds()),
        "unique_source_ips": int(records["source_ip"].nunique()),
        "unique_destination_ips": int(records["destination_ip"].nunique()),
        "unique_usernames": int(records["username"].nunique()),
        "unique_destination_ports": int(records["destination_port"].nunique()),
        "failed_logins": failed,
        "successful_logins": success,
        "failed_login_ratio": round(failed / (failed + success), 4) if failed + success else None,
        "http_requests": http,
        "http_4xx": c4xx,
        "http_5xx": c5xx,
        "http_4xx_rate": round(c4xx / http, 4) if http else None,
        "http_5xx_rate": round(c5xx / http, 4) if http else None,
        "event_counts": {str(k): int(v) for k, v in event_counts.items()},
        "top_source_ips": [{"source_ip": str(ip), "events": int(n)} for ip, n in top_ips.items()],
    }


def _capabilities(summary: dict) -> dict:
    """Which analyses can this log honestly support? Detection and the dashboard use this
    so they never report on information the file does not contain."""
    total = summary["total_records"]
    covered = summary["records_with_timestamp"] / total if total else 0
    return {
        "has_timestamps": covered >= MIN_TIMESTAMP_COVERAGE,
        "has_source_ips": summary["unique_source_ips"] > 0,
        "has_auth_events": summary["failed_logins"] + summary["successful_logins"] > 0,
        "has_http": summary["http_requests"] > 0,
        "has_destination_ports": summary["unique_destination_ports"] > 0,
        "has_usernames": summary["unique_usernames"] > 0,
    }


# ------------------------------------------------------------------ public entry point
def extract_features(records: pd.DataFrame, window_seconds: int = DEFAULT_WINDOW_SECONDS) -> FeatureSet:
    """Build every feature table from the normalized records of Module 2."""
    flagged = _with_flags(records)
    summary = _summary(records, flagged)
    capabilities = _capabilities(summary)

    timed = flagged.dropna(subset=["timestamp"]).sort_values("timestamp", kind="stable")
    span = summary["duration_seconds"] or 0
    window_seconds = pick_window_seconds(span, window_seconds)

    timed = timed.assign(
        window=timed["timestamp"].dt.floor(f"{window_seconds}s"),
        gap=timed["timestamp"].diff().dt.total_seconds(),           # seconds since the previous event (any IP)
    )
    timed_ip = timed.dropna(subset=["source_ip"]).sort_values(["source_ip", "timestamp"], kind="stable")
    timed_ip = timed_ip.assign(ip_gap=timed_ip.groupby("source_ip")["timestamp"].diff().dt.total_seconds())

    ip_windows = _ip_window_features(timed_ip, window_seconds)
    return FeatureSet(
        window_seconds=window_seconds,
        summary=summary,
        capabilities=capabilities,
        window_features=_window_features(timed, window_seconds, ip_windows),
        ip_window_features=ip_windows,
        ip_summary=_ip_summary(flagged.dropna(subset=["source_ip"]), ip_windows),
    )
